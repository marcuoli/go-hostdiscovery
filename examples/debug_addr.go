package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run debug_addr.go <ip>")
		fmt.Println("Example: go run debug_addr.go 192.168.1.100")
		os.Exit(1)
	}

	targetIP := net.ParseIP(os.Args[1])
	if targetIP == nil {
		fmt.Println("Error: invalid IP address")
		os.Exit(1)
	}

	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: targetIP, Port: 137})
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	fmt.Println("Target IP:", targetIP)
	fmt.Println("Local addr:", conn.LocalAddr())
	fmt.Println("Local IP:", localAddr.IP)
	fmt.Println("Bind string:", localAddr.IP.String()+":0")
}
