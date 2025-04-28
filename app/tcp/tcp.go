package tcp

import (
	"IP-TCP-Implementation/app/ip"
	"errors"
	"net/netip"
)

type State uint16

const (
	Closed State = iota
	Listen
)

type Socket interface{}

type SocketTableEntry struct {
	SId   uint16
	LAddr netip.Addr
	LPort uint16
	RAddr netip.Addr
	RPort uint16
	Sock  *Socket
}

type VTCPListener struct {
	CurrentState State
}

type TCPStack struct {
	SocketTable []SocketTableEntry
	ipStack     *ip.IPStack
}

// Initializes the TCPStack.
// Populates the routing table.
func Initialize(ipStack *ip.IPStack) *TCPStack {
	tcpStack := &TCPStack{}
	ipStack.RegisterRecvHandler(6, tcpStack.TCPPacketHandler)
	return tcpStack
}

func (tcpStack *TCPStack) VListen(port uint16) (*VTCPListener, error) {
	// sockTableEntry := SocketTableEntry{
	// 	LAddr: netip.IPv4Unspecified(),
	// 	LPort: port,
	// 	RAddr: netip.IPv4Unspecified(),
	// 	RPort: 0,
	// }
	for _, entry := range tcpStack.SocketTable {
		if entry.LAddr == netip.IPv4Unspecified() && entry.LPort == port {
			return nil, errors.New("Port already in use")
		}
	}
	tcpStack.SocketTable = append(tcpStack.SocketTable, SocketTableEntry{
		LAddr: netip.IPv4Unspecified(),
		LPort: port,
		RAddr: netip.IPv4Unspecified(),
		RPort: 0,
		Sock:  &VTCPListener{CurrentState: Listen},
	})
}

// Handler for TCP command, called when TCP packet recd.
func (tcpStack *TCPStack) TCPPacketHandler(ipStack *ip.IPStack, data []byte) {

}
