package protocol

import (
	"IP-TCP-Implementation/app/ip"
	"fmt"
	"log/slog"
	"net/netip"

	ipv4header "github.com/brown-csci1680/iptcp-headers"
)

const (
	TestProtocolNum uint8 = 0
)

// The main test command provided in REPL, sends msg from one node to another
func SendTest(ipStack *ip.IPStack, destIpStr string, msg string) {
	destIp, err := netip.ParseAddr(destIpStr)
	if err != nil {
		slog.Warn("Failed to parse given addr. ", err)
		return
	}
	n, err := ipStack.SendIP(destIp, TestProtocolNum, []byte(msg))
	if err != nil {
		slog.Warn("Failed to send msg. ", err)
	}
	fmt.Printf("Sent %d bytes\n", n)
}

// Handler for test command, called when test command received. Prints the msg with some header details
func TestPacketHandler(ipStack *ip.IPStack, data []byte) {
	// Marshal the received byte array into a UDP header
	hdr, err := ipv4header.ParseHeader(data)
	if err != nil {
		slog.Warn("Dropping packet, error parsing header", err)
		return
	}
	headerSize := hdr.Len
	message := data[headerSize:]

	fmt.Printf("Received test packet: Src: %s, Dst: %s, TTL: %d, Data: %s\n", hdr.Src, hdr.Dst, hdr.TTL-1, string(message))
}
