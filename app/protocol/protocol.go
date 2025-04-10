package protocol

import (
	"IP-TCP-Implementation/app/ip"
	"fmt"
	"log/slog"
	"net/netip"
)

func SendTest(ipStack *ip.IPStack, destIpStr string, msg string) {
	destIp, err := netip.ParseAddr(destIpStr)
	if err != nil {
		slog.Warn("Failed to parse given addr. ", err)
		return
	}
	n, err := ipStack.SendIP(destIp, 0, []byte(msg))
	if err != nil {
		slog.Warn("Failed to send msg. ", err)
	}
	fmt.Printf("Sent %d bytes\n", n)
}
