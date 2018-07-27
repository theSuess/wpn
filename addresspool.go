package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
)

// AddressPool stores and manages active connections
type AddressPool struct {
	tunName string
	pool    map[*net.IP]bool
}

// Setup initializes the address pool
func (a *AddressPool) Setup(r string, i string) {
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

// Remove frees the address
func (a *AddressPool) Remove(ip *net.IP) {
	a.pool[ip] = false
	err := removeDevRoute(ip.String(), a.tunName)
	if err != nil {
		log.Error(err)
	}
}

// Get retrieves a free address
func (a *AddressPool) Get() *net.IP {
	for ip, u := range a.pool {
		if !u {
			// Inject IP route
			err := addDevRoute(ip.String(), a.tunName)
			if err != nil {
				log.Error(err)
				return nil
			}
			return ip
		}
	}
	return nil
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
