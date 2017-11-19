package main

import (
	"encoding/binary"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"

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

// AddrPool stores and manages active connections
type AddrPool struct {
	tunName string
	pool    map[*net.IP]bool
}

// ClientConfiguration tells the client how to configure the tun device
type ClientConfiguration struct {
	IP      string
	Network string
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
			},
			Action: func(c *cli.Context) error {
				log.WithField("Interface", c.GlobalString("interface")).Info("Starting Server")

				p := AddrPool{}
				p.Setup(c.String("range"), tun.Name())
				conf := ClientConfiguration{Network: c.String("client-network")}

				http.HandleFunc("/vpn", func(w http.ResponseWriter, r *http.Request) {
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
					go func() {
						for {
							mt, packet, err := c.ReadMessage()
							if err != nil {
								log.Error(err)
								p.Remove(cip)
								return
							}
							if mt != 2 {
								log.Error("Received invalid message type.")
								p.Remove(cip)
								return
							}
							header, err := ipv4.ParseHeader(packet)
							if err != nil {
								log.Error(err)
								p.Remove(cip)
								break
							}
							log.WithFields(log.Fields{
								"Source": header.Src.String(),
								"Dest":   header.Dst.String(),
							}).Debug("Received Packet")
							_, err = tun.Write(packet)
							if err != nil {
								log.Error(err)
								break
							}
						}
					}()
					packet := make([]byte, BUFFERSIZE)
					for {
						plen, err := tun.Read(packet)
						if err != nil {
							log.Error(err)
							break
						}
						header, err := ipv4.ParseHeader(packet[:plen])
						if err != nil {
							log.Error(err)
							break
						}
						log.WithFields(log.Fields{
							"Source": header.Src.String(),
							"Dest":   header.Dst.String(),
						}).Debug("Received Packet")
						c.WriteMessage(2, packet[:plen])
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
			},
			Action: func(c *cli.Context) error {
				log.WithField("Interface", c.GlobalString("interface")).Info("Starting Client")

				if c.String("remote") == "" {
					log.Error("Remote cannot be empty")
					return nil
				}

				u := url.URL{Scheme: "wss", Host: c.String("remote"), Path: "/vpn"}
				log.Info("Connecting to %s", u.String())
				w, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
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

				go func() {
					for {
						mt, packet, err := w.ReadMessage()
						if err != nil {
							log.Fatal(err)
							return
						}
						if mt != 2 {
							log.Fatal("Received invalid message type.")
							return
						}
						header, err := ipv4.ParseHeader(packet)
						if err != nil {
							log.Error(err)
							break
						}
						log.WithFields(log.Fields{
							"Source": header.Src.String(),
							"Dest":   header.Dst.String(),
						}).Debug("Received Packet")
						_, err = tun.Write(packet)
						if err != nil {
							log.Error(err)
							break
						}
					}
				}()

				packet := make([]byte, BUFFERSIZE)
				for {
					plen, err := tun.Read(packet)
					if err != nil {
						log.Error(err)
						break
					}
					header, err := ipv4.ParseHeader(packet[:plen])
					if err != nil {
						log.Error(err)
						break
					}
					log.WithFields(log.Fields{
						"Source": header.Src.String(),
						"Dest":   header.Dst.String(),
					}).Debug("Received Packet")
					err = w.WriteMessage(2, packet[:plen])
					if err != nil {
						log.Error(err)
						break
					}
				}
				return nil
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Error(err)
	}
}

// Setup initializes the address pool
func (a *AddrPool) Setup(r string, i string) {
	a.tunName = i
	a.pool = make(map[*net.IP]bool)
	adrs := strings.Split(r, "-")
	beg, end := net.ParseIP(adrs[0]), net.ParseIP(adrs[1])
	bg := ip2int(beg)
	e := ip2int(end)
	for i := bg; i < e; i++ {
		ip := int2ip(i)
		a.pool[&ip] = false
	}
}

// Get retrieves a free address
func (a *AddrPool) Get() *net.IP {
	for ip, u := range a.pool {
		if !u {
			// Inject IP route
			cmd := exec.Command("/sbin/ip", "route", "add", ip.String(), "dev", a.tunName)
			err := cmd.Run()
			if err != nil {
				log.Error(err)
				return nil
			}
			return ip
		}
	}
	return nil
}

// Remove frees the address
func (a *AddrPool) Remove(ip *net.IP) {
	a.pool[ip] = false
	cmd := exec.Command("/sbin/ip", "route", "del", ip.String(), "dev", a.tunName)
	err := cmd.Run()
	if err != nil {
		log.Error(err)
	}
}

// IP to int code from here: https://gist.github.com/ammario/649d4c0da650162efd404af23e25b86b
func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}
