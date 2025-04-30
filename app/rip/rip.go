package rip

import (
	"IP-TCP-Implementation/app/ip"
	"bytes"
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"time"

	ipv4header "github.com/brown-csci1680/iptcp-headers"
)

const (
	RIPProtocolNum         uint8  = 200
	RequestCommand         uint16 = 1
	ResponseCommand        uint16 = 2
	PeriodicUpdateInterval uint16 = 5
	Infinity               uint32 = 16
	SizeOfRIPEntry         uint16 = 12
)

type RIPEntry struct {
	Cost    uint32
	Address uint32
	Mask    uint32
}

type RIPMessage struct {
	Command    uint16
	NumEntries uint16
	Entries    []RIPEntry
}

func (msg *RIPEntry) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, msg.Cost)
	if err != nil {
		slog.Warn("Failed to marshall. Err: ", err)
		return []byte{}, err
	}
	err = binary.Write(buf, binary.BigEndian, msg.Address)
	if err != nil {
		slog.Warn("Failed to marshall. Err: ", err)
		return []byte{}, err
	}
	err = binary.Write(buf, binary.BigEndian, msg.Mask)
	if err != nil {
		slog.Warn("Failed to marshall. Err: ", err)
		return []byte{}, err
	}

	return buf.Bytes(), nil
}

func (msg *RIPEntry) Unmarshal(data []byte) {
	byte_idx := 0
	msg.Cost = binary.BigEndian.Uint32(data[byte_idx : byte_idx+4])
	byte_idx += 4
	msg.Address = binary.BigEndian.Uint32(data[byte_idx : byte_idx+4])
	byte_idx += 4
	msg.Mask = binary.BigEndian.Uint32(data[byte_idx : byte_idx+4])
}

func (msg *RIPMessage) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, msg.Command)
	if err != nil {
		slog.Warn("Failed to marshall. Err: ", err)
		return []byte{}, err
	}

	err = binary.Write(buf, binary.BigEndian, msg.NumEntries)
	if err != nil {
		slog.Warn("Failed to marshall. Err: ", err)
		return []byte{}, err
	}

	for i := 0; i < int(msg.NumEntries); i++ {
		entryData, err := msg.Entries[i].Marshal()
		if err != nil {
			slog.Warn("Failed to marshall. Err: ", err)
			return []byte{}, err
		}
		err = binary.Write(buf, binary.BigEndian, entryData)
		if err != nil {
			slog.Warn("Failed to marshall. Err: ", err)
			return []byte{}, err
		}
	}

	return buf.Bytes(), nil
}

func (msg *RIPMessage) Unmarshal(data []byte) {
	byte_idx := 0
	msg.Command = binary.BigEndian.Uint16(data[byte_idx : byte_idx+2])
	byte_idx += 2
	msg.NumEntries = binary.BigEndian.Uint16(data[byte_idx : byte_idx+2])
	byte_idx += 2
	for i := 0; i < int(msg.NumEntries); i++ {
		msg.Entries = append(msg.Entries, RIPEntry{})
		msg.Entries[i].Unmarshal(data[byte_idx : byte_idx+int(SizeOfRIPEntry)])
		byte_idx += int(SizeOfRIPEntry)
	}
}

// Send initial rip request and start interval updates
func InitRIP(ipStack *ip.IPStack) {
	// Send RIP request
	err := SendRIPRequest(ipStack)
	if err != nil {
		slog.Warn("Could not send RIP request")
	}

	// Begin Periodic RIP
	go BeginPeriodicRIP(ipStack)
}

// Start interval updates
func BeginPeriodicRIP(ipStack *ip.IPStack) {
	for {
		time.Sleep(time.Duration(PeriodicUpdateInterval) * time.Second)
		for _, ripNbor := range ipStack.RipNeighbors {
			ripMsg := RIPMessage{
				Command:    ResponseCommand,
				NumEntries: 0,
				Entries:    []RIPEntry{},
			}
			ipStack.RoutingTableMutex.Lock()
			ripMsg.Entries = append(ripMsg.Entries, RoutesToRIPEntries(ipStack.RoutingTable, ripNbor)...)
			ripMsg.NumEntries = uint16(len(ripMsg.Entries))
			ipStack.RoutingTableMutex.Unlock()

			SendRIPResponse(ipStack, ripNbor, ripMsg)
		}
	}
}

// Sends a request to immediately get RIP response, runs on startup
func SendRIPRequest(ipStack *ip.IPStack) error {
	ripRequest := RIPMessage{
		Command:    RequestCommand,
		NumEntries: 0,
	}
	data, err := ripRequest.Marshal()
	if err != nil {
		slog.Warn("Failed to marshall. Err: ", err)
		return err
	}
	for _, ripNbor := range ipStack.RipNeighbors {
		_, err := ipStack.SendIP(ripNbor, RIPProtocolNum, data)
		if err != nil {
			slog.Warn("Failed to send msg. ", err)
		}
	}
	return nil
}

// Sends a RIP response with the content of the RIPMessage
func SendRIPResponse(ipStack *ip.IPStack, dst netip.Addr, ripMsg RIPMessage) error {
	data, err := ripMsg.Marshal()
	if err != nil {
		slog.Warn("Failed to marshall. Err: ", err)
		return err
	}
	_, err = ipStack.SendIP(dst, RIPProtocolNum, data)
	if err != nil {
		slog.Warn("Failed to send msg. ", err)
		return err
	}
	return nil
}

// Handler for RIP command, called when RIP request or response recd.
func RIPPacketHandler(ipStack *ip.IPStack, data []byte) {
	// Marshal the received byte array into a UDP header
	hdr, err := ipv4header.ParseHeader(data)
	if err != nil {
		slog.Warn("Dropping packet, error parsing header", err)
		return
	}
	headerSize := hdr.Len
	message := data[headerSize:]

	// Unmarshall to RIPMessage
	ripMsg := RIPMessage{}
	ripMsg.Unmarshal(message)

	if ripMsg.Command == RequestCommand { // If RIP Request, send response
		ripResp := RIPMessage{
			Command:    ResponseCommand,
			NumEntries: 0,
			Entries:    []RIPEntry{},
		}
		ipStack.RoutingTableMutex.Lock()
		ripMsg.Entries = append(ripMsg.Entries, RoutesToRIPEntries(ipStack.RoutingTable, hdr.Src)...)
		ripMsg.NumEntries = uint16(len(ripMsg.Entries))
		ipStack.RoutingTableMutex.Unlock()

		SendRIPResponse(ipStack, hdr.Src, ripResp)
	} else if ripMsg.Command == ResponseCommand { // If RIP Response, update routing table and send trigger update
		ipStack.RoutingTableMutex.Lock()
		updatedRoutes := UpdateRoutingTable(ipStack, ripMsg.Entries, hdr.Src)
		ipStack.RoutingTableMutex.Unlock()

		// Send the updated routes immediately to RIP Neighbors
		for _, ripNbor := range ipStack.RipNeighbors {
			ripMsg := RIPMessage{
				Command:    ResponseCommand,
				NumEntries: 0,
				Entries:    []RIPEntry{},
			}
			ripMsg.Entries = append(ripMsg.Entries, RoutesToRIPEntries(updatedRoutes, ripNbor)...)
			ripMsg.NumEntries = uint16(len(ripMsg.Entries))

			if ripMsg.NumEntries > 0 {
				SendRIPResponse(ipStack, ripNbor, ripMsg)
			}
		}

	} else {
		slog.Warn("Unsupported command recd: %d", ripMsg.Command)
	}
}

// Updates the routing table based on the list of rip entries and returns a list
// of routes that got updated. Routing table mutex must be locked on entry and return
func UpdateRoutingTable(ipStack *ip.IPStack, ripEntries []RIPEntry, src netip.Addr) []ip.Route {
	var updatedRoutes []ip.Route
	for _, ripEntry := range ripEntries {
		// Decode prefix
		var addrAs4 [4]byte
		binary.BigEndian.PutUint32(addrAs4[:], ripEntry.Address)
		var ipMaskAs4 [4]byte
		binary.BigEndian.PutUint32(ipMaskAs4[:], ripEntry.Mask)
		ipMask := net.IPv4Mask(ipMaskAs4[0], ipMaskAs4[1], ipMaskAs4[2], ipMaskAs4[3])
		bits, _ := ipMask.Size()

		networkAdvertised := netip.PrefixFrom(netip.AddrFrom4(addrAs4), bits)
		found := false
		for idx, route := range ipStack.RoutingTable {
			// RIP updates are not supported for static routes
			if route.RouteType == ip.RouteTypeStatic {
				continue
			}

			// Network is in routing table
			if route.Prefix == networkAdvertised {
				found = true
				// If network advertised is a local network then the advert can never be better so ignore
				// but registering here that the entry was found saves from adding a duplicate entry in table
				if route.RouteType == ip.RouteTypeLocal {
					break
				}
				if route.NextHop.Addr == src { // update is from the same node from which the entry was made
					if ripEntry.Cost+1 == route.Cost { // same cost so just refresh
						ipStack.RoutingTable[idx].UpdatedAt = time.Now()
					} else { // topology might have changed so update
						ipStack.RoutingTable[idx].Cost = ripEntry.Cost + 1
						ipStack.RoutingTable[idx].UpdatedAt = time.Now()
						updatedRoutes = append(updatedRoutes, ipStack.RoutingTable[idx])
					}
				} else { // update comes from a diff node
					if ripEntry.Cost+1 < route.Cost { // only update if it is strictly better
						ipStack.RoutingTable[idx].NextHop.Addr = src
						ipStack.RoutingTable[idx].Cost = ripEntry.Cost + 1
						ipStack.RoutingTable[idx].UpdatedAt = time.Now()
						updatedRoutes = append(updatedRoutes, ipStack.RoutingTable[idx])
					}
				}
				break
			}
		}
		if !found && ripEntry.Cost+1 < Infinity { // a fresh update for a reachable network so add it to table
			newRoute := ip.Route{
				RouteType: ip.RouteTypeRIP,
				Prefix:    networkAdvertised,
				NextHop: ip.NextHop{
					InterfaceName: "",
					Addr:          src,
				},
				Cost:      ripEntry.Cost + 1,
				UpdatedAt: time.Now(),
			}
			ipStack.RoutingTable = append(ipStack.RoutingTable, newRoute)
			updatedRoutes = append(updatedRoutes, newRoute)
		}

	}
	return updatedRoutes
}

// ---------- Helpers ----------

// Converts a routting table to to a RipEntries - []RIPEntry
func RoutesToRIPEntries(routes []ip.Route, ripDst netip.Addr) []RIPEntry {
	var ripEntries []RIPEntry
	for _, route := range routes {
		if route.RouteType == ip.RouteTypeStatic { // not supported
			continue
		}
		entry := RouteToRIPEntry(ripDst, route)
		if entry == (RIPEntry{}) {
			continue
		}
		ripEntries = append(ripEntries, entry)
	}
	return ripEntries
}

// Converts a route to a RIPEntry and also takes care of Split Horizon - Poison Reverse
func RouteToRIPEntry(dst netip.Addr, route ip.Route) RIPEntry {
	if route.RouteType == ip.RouteTypeStatic { // Not supported
		return RIPEntry{}
	}
	cost := route.Cost
	if route.RouteType == ip.RouteTypeRIP && route.NextHop.Addr == dst { // Split Horizon with Poisoned Reverse
		cost = Infinity
	}
	return RIPEntry{
		Cost:    cost,
		Address: binary.BigEndian.Uint32(route.Prefix.Addr().AsSlice()),
		Mask:    binary.BigEndian.Uint32(net.CIDRMask(route.Prefix.Bits(), 32)),
	}
}
