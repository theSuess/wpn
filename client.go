package main

import (
	"net/http"
	"net/url"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"github.com/songgao/water"
	"github.com/urfave/cli"
)

// ClientConfiguration tells the client how to configure the tun device
type ClientConfiguration struct {
	IP      string
	Network string
}

// Client encapsulates a tun interface
type Client struct {
	tun *water.Interface
}

// NewClient creates a new client
func NewClient(tun *water.Interface) *Client {
	return &Client{tun: tun}
}

// Run starts the Client
func (cl *Client) Run(c *cli.Context) error {
	log.WithField("Interface", c.GlobalString("interface")).Info("Starting Client")

	if c.String("remote") == "" {
		log.Error("Remote cannot be empty")
		return nil
	}
	proto := "ws"
	if c.Bool("secure") {
		proto = "wss"
	}
	u := url.URL{Scheme: proto, Host: c.String("remote"), Path: "/vpn"}
	log.Infof("Connecting to %s", u.String())
	headers := http.Header{}
	headers.Add("X-WPN-Secret", c.String("secret"))
	w, _, err := websocket.DefaultDialer.Dial(u.String(), headers)
	if err != nil {
		log.Fatal(err)
	}
	conf := &ClientConfiguration{}
	err = w.ReadJSON(&conf)
	if err != nil {
		log.Fatal(err)
	}

	log.WithFields(log.Fields{
		"IP":      conf.IP,
		"Network": conf.Network,
	}).Info("Received Configuration")

	// Set IP on interface
	err = addIPAddress(conf.IP, cl.tun.Name())
	if err != nil {
		log.Fatal(err)
	}

	// Inject IP route
	err = addDevRoute(conf.Network, cl.tun.Name())
	if err != nil {
		log.Fatal(err)
	}

	wsout := make(chan []byte, 1024)
	tout := make(chan []byte, 1024)
	go wsListener(w, wsout, nil)
	rm := &routeManager{isClient: true}
	go rm.tunListener(cl.tun, tout)
	for {
		select {
		case packet := <-tout:
			err = w.WriteMessage(2, packet)
			if err != nil {
				log.Error(err)
				return err
			}
		case packet := <-wsout:
			_, err := cl.tun.Write(packet)
			if err != nil {
				log.Error(err)
				return err
			}
		}

	}
}
