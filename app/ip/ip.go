package ip

import (
	"IP-TCP-Implementation/app/lnxconfig"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"text/tabwriter"

	ipv4header "github.com/brown-csci1680/iptcp-headers"
	"github.com/google/netstack/tcpip/header"
)

// General
const (
	MaxMessageSize = 1400
)

// Routing mode
type RoutingMode int

const (
	RoutingTypeNone   RoutingMode = 0
	RoutingTypeStatic RoutingMode = 1
	RoutingTypeRIP    RoutingMode = 2
)

// Route type
type RouteType int

const (
	RouteTypeLocal  RouteType = 0
	RouteTypeStatic RouteType = 1
	RouteTypeRIP    RouteType = 2
)

// IP header
const (
	Version   int = 4
	HeaderLen int = 20 // Header length is always 20 when no IP options
	TTL       int = 32
)

// Recv Handler function
type HandlerFunc = func(*IPStack, []byte)

type IPStack struct {
	Interfaces          []Interface
	Neighbors           []Neighbor
	RoutingMode         RoutingMode
	RipNeighbors        []netip.Addr
	RoutingTable        []Route
	RecvHandlerRegistry map[int]HandlerFunc
}

type Interface struct {
	Name           string
	AssignedIP     netip.Addr
	AssignedPrefix netip.Prefix
	UDPAddr        netip.AddrPort
	IsUp           bool
	Conn           *net.UDPConn
}

type Neighbor struct {
	DestAddr      netip.Addr
	UDPAddr       netip.AddrPort
	InterfaceName string
}

type Route struct {
	RouteType RouteType
	Prefix    netip.Prefix
	NextHop   NextHop
	Cost      int
}

type NextHop struct {
	InterfaceName string
	Addr          netip.Addr
}

// Initializes the IPStack using the IPConfig provided.
// Populates the routing table.
// Returns pointer to an IPStack struct
func Initialize(configInfo *lnxconfig.IPConfig) *IPStack {
	ipStack := &IPStack{}

	// Initialize interfaces
	for _, iface := range configInfo.Interfaces {
		ipStack.Interfaces = append(ipStack.Interfaces, Interface{
			Name:           iface.Name,
			AssignedIP:     iface.AssignedIP,
			AssignedPrefix: iface.AssignedPrefix,
			UDPAddr:        iface.UDPAddr,
			IsUp:           true,
		})
	}

	// Initialize neighbors
	for _, nbor := range configInfo.Neighbors {
		ipStack.Neighbors = append(ipStack.Neighbors, Neighbor{
			DestAddr:      nbor.DestAddr,
			UDPAddr:       nbor.UDPAddr,
			InterfaceName: nbor.InterfaceName,
		})
	}

	// Initialize routing mode
	ipStack.RoutingMode = RoutingMode(configInfo.RoutingMode)

	// Initialize RIP neighbors
	ipStack.RipNeighbors = append(ipStack.RipNeighbors, configInfo.RipNeighbors...)

	// Initialize Routing table

	// Adding static routes
	for prefix, addr := range configInfo.StaticRoutes {
		ipStack.RoutingTable = append(ipStack.RoutingTable, Route{
			RouteType: RouteTypeStatic,
			Prefix:    prefix,
			NextHop: NextHop{
				InterfaceName: "",
				Addr:          addr,
			},
			Cost: -1,
		})
	}

	// Adding local routes
	for _, iface := range configInfo.Interfaces {
		ipStack.RoutingTable = append(ipStack.RoutingTable, Route{
			RouteType: RouteTypeLocal,
			Prefix:    iface.AssignedPrefix,
			NextHop: NextHop{
				InterfaceName: iface.Name,
				Addr:          netip.Addr{},
			},
			Cost: 0,
		})
	}

	// Initialize registry map
	ipStack.RecvHandlerRegistry = make(map[int]HandlerFunc)

	return ipStack
}

// ---------- IPStack Methods ----------

// Print all the interfaces
func (ipStack *IPStack) ListInterfaces() {
	w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	fmt.Fprintf(w, "%s\t%s\t%s\n", "Name", "Addr/Prefix", "State")
	for _, iface := range ipStack.Interfaces {
		fmt.Fprintf(w, "%s\t%s/%s\t%s\n", iface.Name, iface.AssignedIP, strconv.Itoa(iface.AssignedPrefix.Bits()), iface.getStateAsString())
	}
	w.Flush()
}

// Print all the neighbors
func (ipStack *IPStack) ListNeighbors() {
	w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	fmt.Fprintf(w, "%s\t%s\t%s\n", "Iface", "VIP", "UDPAddr")
	for _, nbor := range ipStack.Neighbors {
		if ipStack.getInterfaceStateByName(nbor.InterfaceName) {
			fmt.Fprintf(w, "%s\t%s\t%s\n", nbor.InterfaceName, nbor.DestAddr, nbor.UDPAddr)
		}
	}
	w.Flush()
}

// Print routing table
func (ipStack *IPStack) ListRoutingTable() {
	w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", "T", "Prefix", "Next hop", "Cost")
	for _, route := range ipStack.RoutingTable {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", route.getRouteTypeEntry(), route.Prefix, route.getNextHopEntry(), route.getCostEntry())
	}
	w.Flush()
}

// Find the interface with the given name and set its status to Up
func (ipStack *IPStack) SetInterfaceState(interfaceName string, isUp bool) error {
	iface, err := ipStack.getInterfaceByName(interfaceName)
	if err != nil {
		slog.Warn("Interface %s not found", interfaceName)
		return err
	}
	iface.IsUp = isUp
	return nil
}

// Sending IP messages to the provided destination
func (ipStack *IPStack) SendIP(dst netip.Addr, protocolNum uint8, data []byte) (int, error) {
	route, nextHopUDPAddr, err := ipStack.getRouteForDest(dst)
	if err != nil {
		return 0, err
	}
	iface, err := ipStack.getInterfaceByName(route.NextHop.InterfaceName)
	if err != nil {
		return 0, err
	}

	hdr := ipv4header.IPv4Header{
		Version:  Version,
		Len:      HeaderLen, // Header length is always 20 when no IP options
		TOS:      0,
		TotalLen: ipv4header.HeaderLen + len(data),
		ID:       0,
		Flags:    0,
		FragOff:  0,
		TTL:      TTL,
		Protocol: int(protocolNum),
		Checksum: 0, // Should be 0 until checksum is computed
		Src:      iface.AssignedIP,
		Dst:      dst,
		Options:  []byte{},
	}

	// Assemble the header into a byte array
	headerBytes, err := hdr.Marshal()
	if err != nil {
		slog.Warn("Error marshalling header:  ", err)
		return 0, err
	}

	// Compute the checksum
	// Cast back to an int, which is what the Header structure expects
	hdr.Checksum = int(ipStack.computeChecksum(headerBytes))

	headerBytes, err = hdr.Marshal()
	if err != nil {
		slog.Warn("Error marshalling header:  ", err)
		return 0, err
	}

	bytesToSend := make([]byte, 0, len(headerBytes)+len(data))
	bytesToSend = append(bytesToSend, headerBytes...)
	bytesToSend = append(bytesToSend, data...)

	n, err := iface.SendLinkLayer(nextHopUDPAddr, bytesToSend)
	slog.Info("Sent %d bytes", n)
	return n, err
}

// Forward IP messages based on destination
func (ipStack *IPStack) ForwardIP(hdr *ipv4header.IPv4Header, data []byte) {
	if hdr.TTL <= 0 {
		slog.Warn("Dropping packet, TTL expired")
		return
	}
	route, nextHopUDPAddr, err := ipStack.getRouteForDest(hdr.Dst)
	if err != nil {
		slog.Warn("Failed to forward packet, no route found")
		return
	}
	iface, err := ipStack.getInterfaceByName(route.NextHop.InterfaceName)
	if err != nil {
		slog.Warn("Failed to forward packet, no interface for selected route found")
		return
	}

	hdr.Checksum = 0

	// Assemble the header into a byte array
	headerBytes, err := hdr.Marshal()
	if err != nil {
		slog.Warn("Failed to forward packet, Error marshalling header:  ", err)
		return
	}

	// Compute the checksum
	// Cast back to an int, which is what the Header structure expects
	hdr.Checksum = int(ipStack.computeChecksum(headerBytes))

	headerBytes, err = hdr.Marshal()
	if err != nil {
		slog.Warn("Failed to forward packet, Error marshalling header:  ", err)
		return
	}

	bytesToSend := make([]byte, 0, len(headerBytes)+len(data))
	bytesToSend = append(bytesToSend, headerBytes...)
	bytesToSend = append(bytesToSend, data...)

	n, err := iface.SendLinkLayer(nextHopUDPAddr, bytesToSend)
	if err != nil {
		slog.Warn("Failed to forward packet, Error sending over link layer:  ", err)
		return
	}
	slog.Info("Sent %d bytes", n)
}

// Recv IP messages, the content is passed by interface (Link Layer) process it as IP packet
func (ipStack *IPStack) RecvIP(data []byte) {
	// Marshal the received byte array into a UDP header
	hdr, err := ipv4header.ParseHeader(data)
	if err != nil {
		slog.Warn("Dropping packet, error parsing header", err)
		return
	}
	headerSize := hdr.Len
	headerBytes := data[:headerSize]

	// Validate the checksum
	checksumFromHeader := uint16(hdr.Checksum)
	computedChecksum := ipStack.validateChecksum(headerBytes, checksumFromHeader)
	if computedChecksum != checksumFromHeader {
		slog.Warn("Dropping packet, incorrect checksum")
		return
	}

	// Check the destination of the packet is one of this node's iface
	reachedDst := false
	for _, iface := range ipStack.Interfaces {
		if hdr.Dst == iface.AssignedIP {
			reachedDst = true
			break
		}
	}

	// Handle TTL: decrement ttl if it is 0 and not yet on its dst then drop
	hdr.TTL = hdr.TTL - 1
	// CHECK: this can be removed as packet drops in forwarding if ttl expired
	if hdr.TTL <= 0 && !reachedDst {
		slog.Warn("Dropping packet, TTL expired")
		return
	}

	// Get protocol number
	protocolNum := hdr.Protocol
	// Get the message, which starts after the header
	message := data[headerSize:]

	if reachedDst { // Packet reached its dst, call handler
		handlerFunc, ok := ipStack.RecvHandlerRegistry[protocolNum]
		if !ok {
			slog.Warn("Dropping packet, unsuported protocol num: ", protocolNum)
			return
		}
		handlerFunc(ipStack, data)
	} else { // Forward the packet appropriately
		ipStack.ForwardIP(hdr, message)
	}
}

// Register a recv handler which will be called based on the protocol of the msg recd
func (ipStack *IPStack) RegisterRecvHandler(protocolNum uint8, callbackFunc HandlerFunc) {
	ipStack.RecvHandlerRegistry[int(protocolNum)] = callbackFunc
}

// ---------- IPStack Helper Methods ----------

// Given an interface name return the interface
func (ipStack *IPStack) getInterfaceByName(interfaceName string) (*Interface, error) {
	for idx, iface := range ipStack.Interfaces {
		if iface.Name == interfaceName {
			return &ipStack.Interfaces[idx], nil
		}
	}
	return nil, errors.New("Interface not found")
}

// Given an interface name checks if it is up
func (ipStack *IPStack) getInterfaceStateByName(interfaceName string) bool {
	iface, err := ipStack.getInterfaceByName(interfaceName)
	if err != nil {
		slog.Warn("Interface %s not found", interfaceName)
		return false
	}
	return iface.IsUp
}

// Given a dest IP return the route it would take from the routing table
func (ipStack *IPStack) getRouteForDest(dst netip.Addr) (Route, netip.AddrPort, error) {
	slog.Debug("dst: ", dst)
	destRoute := Route{}
	for _, route := range ipStack.RoutingTable {
		if route.Prefix.Contains(dst) && (destRoute == Route{} || route.Prefix.Bits() > destRoute.Prefix.Bits()) {
			destRoute = route
		}
	}

	slog.Debug("Dest route: ", destRoute)

	var nextHopUDPAddr netip.AddrPort
	var err error = nil
	if (destRoute == Route{}) {
		slog.Warn("Failed to find a match in the routing table for %s", dst)
		err = errors.New("no matching route found")
	} else if destRoute.RouteType == RouteTypeLocal {
		// Check self
		reachedDst := false
		for _, iface := range ipStack.Interfaces {
			if iface.AssignedIP == dst {
				nextHopUDPAddr = iface.UDPAddr
				reachedDst = true
				break
			}
		}
		// Check nbors
		if !reachedDst {
			for _, nbor := range ipStack.Neighbors {
				if nbor.DestAddr == dst {
					nextHopUDPAddr = nbor.UDPAddr
					break
				}
			}
		}
		slog.Debug("Next hop UDP addr to send: ", nextHopUDPAddr)
	} else {
		destRoute, nextHopUDPAddr, err = ipStack.getRouteForDest(destRoute.NextHop.Addr)
	}
	return destRoute, nextHopUDPAddr, err
}

// Compute the checksum using the netstack package
func (ipStack *IPStack) computeChecksum(b []byte) uint16 {
	checksum := header.Checksum(b, 0)

	// Invert the checksum value. Makes it easier to use this same function
	// to validate the checksum on the receiving side.
	checksumInv := checksum ^ 0xffff

	return checksumInv
}

// Validate the checksum using the netstack package
func (ipStack *IPStack) validateChecksum(b []byte, fromHeader uint16) uint16 {
	checksum := header.Checksum(b, fromHeader)
	return checksum
}

// ---------- Interface Methods ----------

// Return string description of boolean interface state
func (iface *Interface) getStateAsString() string {
	if iface.IsUp {
		return "up"
	}
	return "down"
}

// Sends the given bytes from the interface to dst
func (iface *Interface) SendLinkLayer(dstUDPAddr netip.AddrPort, bytesToSend []byte) (int, error) {
	// NOP if interface is down
	if !iface.IsUp {
		return 0, nil
	}

	// Turn the address string into a UDPAddr for the connection
	addrString := dstUDPAddr.String()
	remoteAddr, err := net.ResolveUDPAddr("udp4", addrString)
	if err != nil {
		slog.Warn("Error resolving address:  ", err)
		return 0, err
	}

	slog.Debug("Sending to %s:%d\n",
		remoteAddr.IP.String(), remoteAddr.Port)

	// Send the message to the "link-layer" addr:port on UDP
	bytesWritten, err := iface.Conn.WriteToUDP(bytesToSend, remoteAddr)
	if err != nil {
		slog.Warn("Error writing to socket: ", err)
		return 0, err
	}
	slog.Debug("Sent %d bytes\n", bytesWritten)
	return bytesWritten, nil
}

// Listen on the interface for packets
func (iface *Interface) InitAndListenLinkLayer(ipStack *IPStack) {
	// Get the address structure for the address on which we want to listen
	listenString := iface.UDPAddr.String()
	listenAddr, err := net.ResolveUDPAddr("udp4", listenString)
	if err != nil {
		slog.Warn("Error resolving address:  ", err)
		return
	}

	// Create a socket and bind it to the port on which we want to receive data
	conn, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		slog.Warn("Could not bind to UDP port for %s: ", listenString, err)
		return
	}

	// Initialize connection and use it to listen and send UDP packets
	iface.Conn = conn

	for {
		buffer := make([]byte, MaxMessageSize)
		// Read on the UDP port
		_, _, err := iface.Conn.ReadFromUDP(buffer)
		if err != nil {
			log.Panicln("Error reading from UDP socket ", err)
		}
		if iface.IsUp {
			ipStack.RecvIP(buffer)
		}
	}
}

// ---------- Route Methods ----------

// Return string description of boolean interface state
func (route *Route) getRouteTypeEntry() string {
	switch route.RouteType {
	case RouteTypeLocal:
		return "L"
	case RouteTypeStatic:
		return "S"
	case RouteTypeRIP:
		return "R"
	}
	slog.Warn("Invalid route type: %d", route.RouteType)
	return ""
}

func (route *Route) getNextHopEntry() string {
	var nextHop string
	if route.RouteType == RouteTypeLocal {
		nextHop = fmt.Sprintf("LOCAL:%s", route.NextHop.InterfaceName)
	} else {
		nextHop = route.NextHop.Addr.String()
	}
	return nextHop
}

func (route *Route) getCostEntry() string {
	if route.Cost == -1 {
		return "-"
	}
	return strconv.Itoa(route.Cost)
}
