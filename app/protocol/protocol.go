package protocol

import (
	"IP-TCP-Implementation/app/ip"
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/netip"
)

// -- sending RIP updates -- //
func SendRIPUpdate(ipStack *ip.IPStack, destIpStr string) {
	destIp, err := netip.ParseAddr(destIpStr)
	if err != nil {
		slog.Warn("Failed to parse given addr. ", err)
		return
	}

	ripMsg := ip.RIPMessage{
		Command:    2,
		NumEntries: uint16(len(ipStack.RoutingTable)),
		Entries:    make([]ip.RIPEntry, len(ipStack.RoutingTable)),
	}

	for i, route := range ipStack.RoutingTable {
		ripEntry := ip.RIPEntry{
			Cost:    uint32(route.Cost),
			Address: uint32(ConvertToAddress(route.Prefix)),
			Mask:    uint32(ConvertToMask(route.Prefix)),
		}
		ripMsg.Entries[i] = ripEntry
	}

	msg := Marshal(ripMsg)

	_, err = ipStack.SendIP(destIp, 200, []byte(msg))
	if err != nil {
		slog.Warn("Failed to send RIP update. ", err)
	}
}

// -- sending RIP requests -- //
func SendRIPRequest(ipStack *ip.IPStack, destIpStr string) {
	destIp, err := netip.ParseAddr(destIpStr)
	if err != nil {
		slog.Warn("Failed to parse given addr. ", err)
		return
	}

	ripMsg := ip.RIPMessage{
		Command:    1,
		NumEntries: 0,
		Entries:    []ip.RIPEntry{},
	}
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, ripMsg.Command)
	binary.Write(&buf, binary.BigEndian, ripMsg.NumEntries)
	msg := buf.Bytes()

	_, err = ipStack.SendIP(destIp, 200, []byte(msg))
	if err != nil {
		slog.Warn("Failed to send RIP request. ", err)
	}
}

// -- RIP packets handler function -- //
func RIPPacketHandler(ipStack *ip.IPStack, data []byte) {
	// Marshal the received byte array into a UDP header
	hdr, err := ipv4header.ParseHeader(data)
	if err != nil {
		slog.Warn("Dropping packet, error parsing header", err)
		return
	}
	headerSize := hdr.Len

	ripMsg := UnMarshal(data[headerSize:])
}

// helper method to convert the route.Prefix to address and mask
func ConvertToAddress(prefix netip.Prefix) uint32 {
	return 0 // dummy for now
}

func ConvertToMask(prefix netip.Prefix) uint32 {
	return 0 // dummy for now
}

// helper method called marshal and unmarshal to parse and unparse the RIPMessage
func Marshal(ripMsg ip.RIPMessage) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, ripMsg.Command)
	binary.Write(&buf, binary.BigEndian, ripMsg.NumEntries)
	for _, entry := range ripMsg.Entries {
		binary.Write(&buf, binary.BigEndian, entry)
	}
	return buf.Bytes()
}

func UnMarshal(data []byte) ip.RIPMessage {
	var ripMsg ip.RIPMessage

	buf := bytes.NewReader(data)
	binary.Read(buf, binary.BigEndian, &ripMsg.Command)
	binary.Read(buf, binary.BigEndian, &ripMsg.NumEntries)
	ripMsg.Entries = make([]ip.RIPEntry, ripMsg.NumEntries)
	for i := range ripMsg.Entries {
		binary.Read(buf, binary.BigEndian, &ripMsg.Entries[i])
	}

	return ripMsg
}

// The main test command provided in REPL, sends msg from one node to another
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
