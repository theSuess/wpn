package main

import (
	"net"
	"net/http"

	"golang.org/x/net/ipv4"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"github.com/songgao/water"
	"github.com/urfave/cli"
)

type routeManager struct {
	isClient bool
	routes   map[string]chan []byte
}

// Server encapsulates a tun interface
type Server struct {
	tun *water.Interface
}

// NewServer creates a new server
func NewServer(tun *water.Interface) *Server {
	return &Server{tun: tun}
}

// Run starts the Server
func (s *Server) Run(c *cli.Context) error {
	log.WithField("Interface", c.GlobalString("interface")).Info("Starting Server")
	tin := make(chan []byte, 1024)
	go tunWriter(s.tun, tin)
	rm := &routeManager{isClient: false, routes: make(map[string]chan []byte)}
	go rm.tunListener(s.tun, nil)
	p := AddressPool{}
	p.Setup(c.String("range"), s.tun.Name())
	conf := ClientConfiguration{Network: c.String("client-network")}

	http.HandleFunc("/vpn", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-WPN-Secret") != c.String("secret") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Please authenticate yourself"))
		}
		cip := p.Get()
		if cip == nil {
			log.Error("Could not open new connection: No Address available")
			_, _ = w.Write([]byte("No Address available"))
			return
		}
		log.WithFields(log.Fields{
			"remote":   r.RemoteAddr,
			"clientip": cip,
		}).Info("New Client connected")
		conf.IP = cip.String()
		upgrader := websocket.Upgrader{}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		err = c.WriteJSON(conf)
		if err != nil {
			log.Fatal(err)
		}
		fail := make(chan error, 16)
		tout := make(chan []byte, 1024)
		go wsListener(c, tin, fail)
		rm.Add(cip, tout)
		for {
			select {
			case packet := <-tout:
				err := c.WriteMessage(2, packet)
				if err != nil {
					log.Fatal(err)
				}
			case err := <-fail:
				log.Error(err)
				p.Remove(cip)
				return
			}
		}
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://github.com/theSuess/wpn", http.StatusTemporaryRedirect)
	})
	if c.String("certfile") != "" && c.String("keyfile") != "" {
		log.Fatal(http.ListenAndServeTLS(c.String("listen"), c.String("certfile"), c.String("keyfile"), nil))
	}
	log.Fatal(http.ListenAndServe(c.String("listen"), nil))
	return nil
}

func (r *routeManager) Add(ip *net.IP, rec chan []byte) {
	r.routes[ip.String()] = rec
}

func (r *routeManager) tunListener(tun *water.Interface, out chan []byte) {
	packet := make([]byte, BUFFERSIZE)
	for {
		plen, err := tun.Read(packet)
		if err != nil {
			log.Error(err)
			continue
		}
		header, err := ipv4.ParseHeader(packet[:plen])
		if err != nil {
			log.Error(err)
			continue
		}
		log.WithFields(log.Fields{
			"Source":     header.Src.String(),
			"Dest":       header.Dst.String(),
			"SourceChan": "tun",
		}).Debug("Received Packet")
		if r.isClient {
			out <- packet[:plen]
		} else {
			log.Debugf("Pushing Packet to %s", header.Dst.String())
			c := r.routes[header.Dst.String()]
			if c != nil {
				c <- packet[:plen]
			}
		}
	}
}
