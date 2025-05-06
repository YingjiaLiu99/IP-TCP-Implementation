package tcp

import (
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/netip"
	"os"
	"sync"
	"text/tabwriter"
)

type SegPriorityQueue []*SEG

func (pq SegPriorityQueue) Len() int           { return len(pq) }
func (pq SegPriorityQueue) Less(i, j int) bool { return pq[i].SEQ < pq[j].SEQ }

func (pq *SegPriorityQueue) Push(x *SEG) {
	*pq = append(*pq, x)
}

func (pq *SegPriorityQueue) Pop() *SEG {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil // avoid memory leak
	*pq = old[0 : n-1]
	return item
}

// Creates and returns a new VTCPConn
func NewVTCPConn(tcpStack *TCPStack) *VTCPConn {
	conn := &VTCPConn{
		TcpStack:      tcpStack,
		sId:           tcpStack.SockCouter,
		HandshakeDone: make(chan bool),
		ISS:           rand.Uint32(),
		SND: SND{
			Buf: make([]byte, MaxWindowSize),
			WND: MaxWindowSize,
		},
		RCV: RCV{
			Buf: make([]byte, MaxWindowSize),
			WND: MaxWindowSize,
		},
	}
	conn.SND.SpaceAvailableCond = sync.NewCond(&conn.SND.BufLock)
	conn.SND.DataAvailableCond = sync.NewCond(&conn.SND.BufLock)
	conn.SND.NoDataToTransmitCond = sync.NewCond(&conn.SND.BufLock)
	conn.RCV.DataAvailableCond = sync.NewCond(&conn.RCV.BufLock)
	return conn
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
		_, err := listener.VAccept()
		if err != nil {
			slog.Warn("VAccept failed", "Err", err)
			return
		}
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
	case FIN_WAIT_1:
		return "FIN_WAIT_1"
	case FIN_WAIT_2:
		return "FIN_WAIT_2"
	case CLOSE_WAIT:
		return "CLOSE_WAIT"
	case LAST_ACK:
		return "LAST_ACK"
	case TIME_WAIT:
		return "TIME_WAIT"
	case CLOSING:
		return "CLOSING"
	default:
		return ""
	}
}

func (tgtState State) IfOneOfState(states []State) bool {
	for _, state := range states {
		if tgtState == state {
			return true
		}
	}
	return false
}

func AcceptableSegSeq(seg *SEG, rcv *RCV, IRS uint32) bool {
	if seg.LEN == 0 {
		if rcv.WND == 0 {
			return seg.SEQ == rcv.NXT
		} else if rcv.WND > 0 {
			return ModularLessThanEqual(rcv.NXT, seg.SEQ, IRS) && ModularLessThan(seg.SEQ, rcv.NXT+uint32(rcv.WND), IRS)
		}
	} else if seg.LEN > 0 {
		if rcv.WND == 0 {
			return false
		} else if rcv.WND > 0 {
			return ((ModularLessThanEqual(rcv.NXT, seg.SEQ, IRS) && ModularLessThan(seg.SEQ, rcv.NXT+uint32(rcv.WND), IRS)) ||
				(ModularLessThanEqual(rcv.NXT, seg.SEQ+uint32(seg.LEN)-1, IRS) && ModularLessThan(seg.SEQ+uint32(seg.LEN)-1, rcv.NXT+uint32(rcv.WND), IRS)))
		}
	}
	return false
}

func BufIdx(x uint32) uint16 {
	return uint16(x % uint32(MaxWindowSize))
}

func ModularLessThan(lhs uint32, rhs uint32, start uint32) bool {
	if lhs < rhs {
		return true
	} else if lhs >= start && rhs < start {
		return true
	}
	return false
}

func ModularLessThanEqual(lhs uint32, rhs uint32, start uint32) bool {
	if lhs == rhs {
		return true
	}
	return ModularLessThan(lhs, rhs, start)
}
