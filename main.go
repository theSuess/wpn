package main

import (
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"

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

// ClientConfiguration tells the client how to configure the tun device
type ClientConfiguration struct {
	IP      string
	Network string
}

type routeManager struct {
	isClient bool
	routes   map[string]chan []byte
}

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
		cmd := exec.Command("/sbin/ip", "link", "set", "dev", tun.Name(), "up")
		err = cmd.Run()
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
			},
			Action: func(c *cli.Context) error {
				log.WithField("Interface", c.GlobalString("interface")).Info("Starting Server")
				tin := make(chan []byte, 1024)
				go tunWriter(tun, tin)
				rm := &routeManager{isClient: false, routes: make(map[string]chan []byte)}
				go rm.tunListener(tun, nil)
				p := AddressPool{}
				p.Setup(c.String("range"), tun.Name())
				conf := ClientConfiguration{Network: c.String("client-network")}

				http.HandleFunc("/vpn", func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("X-WPN-Secret") != c.String("secret") {
						w.WriteHeader(http.StatusForbidden)
						_, _ = w.Write([]byte("Please authenticate yourself"))
					}
					cip := p.Get()
					if cip == nil {
						log.Error("Could not open new connection: No Address available")
						_, _ = w.Write([]byte("No Addresss available"))
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
					defer c.Close()
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
				log.Fatal(http.ListenAndServe(c.String("listen"), nil))
				return nil
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
				log.Info("Connecting to %s", u.String())
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
				cmd := exec.Command("/sbin/ip", "addr", "add", conf.IP, "dev", tun.Name())
				err = cmd.Run()
				if err != nil {
					log.Fatal(err)
				}

				// Inject IP route
				cmd = exec.Command("/sbin/ip", "route", "add", conf.Network, "dev", tun.Name())
				err = cmd.Run()
				if err != nil {
					log.Fatal(err)
				}

				wsout := make(chan []byte, 1024)
				tout := make(chan []byte, 1024)
				go wsListener(w, wsout, nil)
				rm := &routeManager{isClient: true}
				go rm.tunListener(tun, tout)
				for {
					select {
					case packet := <-tout:
						err = w.WriteMessage(2, packet)
						if err != nil {
							log.Error(err)
							return err
						}
					case packet := <-wsout:
						_, err := tun.Write(packet)
						if err != nil {
							log.Error(err)
							return err
						}
					}

				}
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Error(err)
	}
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
