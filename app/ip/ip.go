package ip

import (
	"IP-TCP-Implementation/app/lnxconfig"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"text/tabwriter"
)

type RoutingMode int

const (
	RoutingTypeNone   RoutingMode = 0
	RoutingTypeStatic RoutingMode = 1
	RoutingTypeRIP    RoutingMode = 2
)

type RouteType int

const (
	RouteTypeLocal  RouteType = 0
	RouteTypeStatic RouteType = 1
	RouteTypeRIP    RouteType = 2
)

type IPStack struct {
	Interfaces   []Interface
	Neighbors    []Neighbor
	RoutingMode  RoutingMode
	RipNeighbors []netip.Addr
	RoutingTable []Route
}

type Interface struct {
	Name           string
	AssignedIP     netip.Addr
	AssignedPrefix netip.Prefix
	UDPAddr        netip.AddrPort
	IsUp           bool
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
	for _, ripNbor := range configInfo.RipNeighbors {
		ipStack.RipNeighbors = append(ipStack.RipNeighbors, ripNbor)
	}

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

// ---------- Interface Methods ----------

// Return string description of boolean interface state
func (iface *Interface) getStateAsString() string {
	if iface.IsUp {
		return "up"
	}
	return "down"
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
