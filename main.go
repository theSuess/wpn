package main

import (
	"os"

	"golang.org/x/net/ipv4"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"github.com/songgao/water"
	"github.com/urfave/cli"
)

const (
	// BUFFERSIZE is the size of received and sent packets
	BUFFERSIZE = 1500
)

func main() {
	app := cli.NewApp()
	app.Name = "wpn"
	app.Version = "0.0.1"
	app.Usage = "WebSocket based VPN"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "interface, i",
			Value: "wpn1",
			Usage: "name of the tun device",
		},
		cli.BoolFlag{
			Name:  "debug",
			Usage: "Show debug messages",
		},
	}
	var tun *water.Interface
	app.Before = func(c *cli.Context) error {
		if c.Args().Get(1) == "--help" {
			return nil
		}
		if c.Bool("debug") {
			log.SetLevel(log.DebugLevel)
			log.Debug("Debug messages activated")
		}
		// Create the TUN Device
		i := c.GlobalString("interface")
		if i == "" {
			log.Fatal("Interface can't be empty")
		}
		conf := water.Config{
			DeviceType: water.TUN,
		}
		conf.Name = i
		t, err := water.New(conf)
		if err != nil {
			log.Error(err)
		}
		tun = t

		// Set up IP Configuration

		// Bring interface up
		err = setDevUp(tun.Name())
		if err != nil {
			log.Fatal(err)
		}
		return nil
	}
	app.After = func(c *cli.Context) error {
		if c.Args().Get(1) == "--help" {
			return nil
		}
		log.WithField("interface", tun.Name()).Info("Tearing down tun device")
		return tun.Close()
	}
	app.Commands = []cli.Command{
		{
			Name:    "server",
			Aliases: []string{"s"},
			Usage:   "Start a wpn server",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "listen, l",
					Usage: "Address to listen for remote connections",
					Value: "0.0.0.0:6969",
				},
				cli.StringFlag{
					Name:  "client-network",
					Usage: "Network to place clients into",
					Value: "10.69.69.0/24",
				},
				cli.StringFlag{
					Name:  "range",
					Usage: "IP Range to distribute to clients",
					Value: "10.69.69.100-10.69.69.150",
				},
				cli.StringFlag{
					Name:  "secret",
					Usage: "shared secret between server and client. Used for authorization",
					Value: "WPN",
				},
				cli.StringFlag{
					Name:  "certfile",
					Usage: "location of the SSL Certificate",
					Value: "",
				},
				cli.StringFlag{
					Name:  "keyfile",
					Usage: "location of the SSL Key",
					Value: "",
				},
			},
			Action: func(c *cli.Context) error {
				s := NewServer(tun)
				return s.Run(c)
			},
		},
		{
			Name:    "client",
			Aliases: []string{"c"},
			Usage:   "Connect to a wpn server",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "remote, r",
					Usage: "Address of the remote server",
					Value: "127.0.0.1:6969",
				},
				cli.BoolFlag{
					Name:  "secure, s",
					Usage: "use wss instead of ws",
				},
				cli.StringFlag{
					Name:  "secret",
					Usage: "shared secret between server and client. Used for authorization",
					Value: "WPN",
				},
			},
			Action: func(c *cli.Context) error {
				cl := NewClient(tun)
				return cl.Run(c)
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Error(err)
	}
}

func tunWriter(tun *water.Interface, in <-chan []byte) {
	for packet := range in {
		_, err := tun.Write(packet)
		if err != nil {
			log.Error(err)
		}
	}
}

func wsListener(ws *websocket.Conn, out chan []byte, fail chan error) {
	for {
		mt, packet, err := ws.ReadMessage()
		if err != nil {
			log.Error(err)
			fail <- err
			return
		}
		if mt == 9 {
			continue
		}
		if mt != 2 {
			log.Error("Received invalid message type.")
			fail <- err
			return
		}
		header, err := ipv4.ParseHeader(packet)
		if err != nil {
			log.Error(err)
			fail <- err
			break
		}
		log.WithFields(log.Fields{
			"Source":     header.Src.String(),
			"Dest":       header.Dst.String(),
			"SourceChan": "ws",
		}).Debug("Received Packet")
		out <- packet
	}
}
