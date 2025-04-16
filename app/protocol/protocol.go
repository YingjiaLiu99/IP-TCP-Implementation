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

type TestPacketArgs struct {
	Src     netip.Addr
	Dst     netip.Addr
	TTL     int
	Message string
}

// func (args *TestPacketArgs) Marshal() ([]byte, error) {
// 	buf := new(bytes.Buffer)
// 	err := binary.Write(buf, binary.BigEndian, args)
// 	if err != nil {
// 		return []byte{}, err
// 	}

// 	err = binary.Write(buf, binary.BigEndian, msg.numStations)
// 	if err != nil {
// 		return []byte{}, err
// 	}

// 	return buf.Bytes(), nil
// }

func TestPacketHandler(args *ip.HandlerArgs) {
	fmt.Printf("Received test packet: Src: %s, Dst: %s, TTL: %d, Data: %s\n", args.Src, args.Dst, args.TTL, string(args.Message))
}
