package tcp

import (
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/netip"
	"os"
	"text/tabwriter"
)

// Creates and returns a new VTCPConn
func NewVTCPConn(tcpStack *TCPStack) VTCPConn {
	return VTCPConn{
		TcpStack:           tcpStack,
		sId:                tcpStack.SockCouter,
		HandshakeRecSynAck: make(chan bool),
		HandshakeRecAck:    make(chan bool),
		Seq:                rand.Uint32(), // ISN
		RemoteCanRecv:      make(chan bool),
		SND: SND{
			buf:            make([]byte, MaxWindowSize),
			UNA:            0,
			NXT:            0,
			WND:            MaxWindowSize,
			LBW:            MaxWindowSize - 1,
			SpaceAvailable: make(chan bool),
			DataAvailable:  make(chan bool),
		},
		RCV: RCV{
			buf:           make([]byte, MaxWindowSize),
			NXT:           0,
			WND:           MaxWindowSize,
			LBR:           MaxWindowSize - 1,
			DataAvailable: make(chan bool),
		},
	}
}

// Searches for a listener socket with the given port
func (tcpStack *TCPStack) FindListener(port uint16) (*VTCPListener, error) {
	for id, entry := range tcpStack.SocketTable {
		if entry.LAddr() == netip.IPv4Unspecified() && entry.LPort() == port {
			listener, ok := tcpStack.SocketTable[id].(*VTCPListener)
			if !ok {
				slog.Warn("Could not assert type to a VTCPListener")
				return nil, errors.New("could not assert to listener")
			}
			return listener, nil
		}
	}
	return nil, errors.New("listener not found")
}

// Searches if a listener port with the given port exists
func (tcpStack *TCPStack) FindConn(recLAddr netip.Addr, recLPort uint16, recRAddr netip.Addr, recRPort uint16) (*VTCPConn, error) {
	for id, entry := range tcpStack.SocketTable {
		if entry.LAddr() == recRAddr && entry.LPort() == recRPort && entry.RAddr() == recLAddr && entry.RPort() == recLPort {
			conn, ok := tcpStack.SocketTable[id].(*VTCPConn)
			if !ok {
				slog.Warn("Could not assert type to a VTCPConn")
				return nil, errors.New("could not assert to conn")
			}
			return conn, nil
		}
	}
	return nil, errors.New("conn not found")
}

// Find Unused Port by going through port rannge and checking if being used
func (tcpStack *TCPStack) FindUnusedPort() (uint16, error) {
	for i := EphemeralPortRangeLow; i <= EphemeralPortRangeHi; i++ {
		_, ok := tcpStack.EphemeralPortSet[i]
		if !ok {
			return i, nil
		}
	}
	return 0, errors.New("no port left")
}

// Prints the socket table
func (tcpStack *TCPStack) PrintSocketTable() {
	w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", "SID", "LAddr", "Lport", "RAddr", "RPort", "Status")
	for _, entry := range tcpStack.SocketTable {
		fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%d\t%s\n", entry.SId(), entry.LAddr(), entry.LPort(), entry.RAddr(), entry.RPort(), entry.State())
	}
	w.Flush()
}

//  VTCPListener methods

func (listener *VTCPListener) PassiveOpen() {
	for {
		listener.VAccept()
	}
}

// Getters to implement Socket

func (listener *VTCPListener) SId() uint16 {
	return listener.sId
}

func (listener *VTCPListener) LAddr() netip.Addr {
	return listener.lAddr
}

func (listener *VTCPListener) LPort() uint16 {
	return listener.lPort
}

func (listener *VTCPListener) RAddr() netip.Addr {
	return listener.rAddr
}

func (listener *VTCPListener) RPort() uint16 {
	return listener.rPort
}

func (listener *VTCPListener) State() State {
	return listener.state
}

//  VTCPConn methods to implement Socket

// Getters

func (conn *VTCPConn) SId() uint16 {
	return conn.sId
}

func (conn *VTCPConn) LAddr() netip.Addr {
	return conn.lAddr
}

func (conn *VTCPConn) LPort() uint16 {
	return conn.lPort
}

func (conn *VTCPConn) RAddr() netip.Addr {
	return conn.rAddr
}

func (conn *VTCPConn) RPort() uint16 {
	return conn.rPort
}

func (conn *VTCPConn) State() State {
	return conn.state
}

// State

func (state State) String() string {
	switch state {
	case CLOSED:
		return "CLOSED"
	case LISTEN:
		return "LISTEN"
	case SYN_SENT:
		return "SYN_SENT"
	case SYN_RECEIVED:
		return "SYN_RECEIVED"
	case ESTABLISHED:
		return "ESTABLISHED"
	default:
		return ""
	}
}

func Mod(x uint16) uint16 {
	return x % MaxWindowSize
}
