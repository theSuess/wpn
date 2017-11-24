package main

import (
	"os/exec"
)

func addDevRoute(src, dev string) error {
	cmd := exec.Command("/sbin/ip", "route", "add", src, "dev", dev)
	return cmd.Run()
}

func removeDevRoute(src, dev string) error {
	cmd := exec.Command("/sbin/ip", "route", "del", src, "dev", dev)
	return cmd.Run()
}

func addIPAddress(ip, dev string) error {
	cmd := exec.Command("/sbin/ip", "addr", "add", ip, "dev", dev)
	return cmd.Run()
}

func setDevUp(dev string) error {
	cmd := exec.Command("/sbin/ip", "link", "set", "dev", dev, "up")
	return cmd.Run()
}
