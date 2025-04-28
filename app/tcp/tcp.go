package tcp

import (
	"IP-TCP-Implementation/app/ip"
	"IP-TCP-Implementation/app/iptcp_utils"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"os"
	"text/tabwriter"

	ipv4header "github.com/brown-csci1680/iptcp-headers"
	"github.com/google/netstack/tcpip/header"
)

const (
	TcpProtocolNumber            = 6
	EphemeralPortRangeLow uint16 = 1025
	EphemeralPortRangeHi  uint16 = 65535
	MaxWindowSize         uint16 = 65535
)

type State uint16

const (
	CLOSED State = iota
	LISTEN
	SYN_SENT
	SYN_RECEIVED
	ESTABLISHED
)

type Socket interface {
	SId() uint16
	LAddr() netip.Addr
	LPort() uint16
	RAddr() netip.Addr
	RPort() uint16
	State() State
}

type VTCPListener struct {
	TcpStack *TCPStack
	sId      uint16
	lAddr    netip.Addr
	lPort    uint16
	rAddr    netip.Addr
	rPort    uint16
	state    State
	NewConns chan *VTCPConn
}

type VTCPConn struct {
	TcpStack           *TCPStack
	sId                uint16
	lAddr              netip.Addr
	lPort              uint16
	rAddr              netip.Addr
	rPort              uint16
	state              State
	HandshakeRecSynAck chan bool
	HandshakeRecAck    chan bool
	Seq                uint32
	Ack                uint32
	WindowSize         uint16
}

type TCPStack struct {
	IpStack          *ip.IPStack
	SocketTable      map[uint16]Socket
	SockCouter       uint16
	EphemeralPortSet map[uint16]bool
}

// Initializes the TCPStack.
// Populates the routing table.
func Initialize(ipStack *ip.IPStack) *TCPStack {
	tcpStack := &TCPStack{
		IpStack:          ipStack,
		SockCouter:       0,
		SocketTable:      make(map[uint16]Socket),
		EphemeralPortSet: map[uint16]bool{},
	}
	ipStack.RegisterRecvHandler(TcpProtocolNumber, tcpStack.TCPPacketHandler)
	return tcpStack
}

// VListen creates a new listening socket bound to the specified port.
// After binding, this socket moves into the LISTEN state
func (tcpStack *TCPStack) VListen(port uint16) (*VTCPListener, error) {
	_, err := tcpStack.FindListener(port) // expects to give error
	if err == nil {                       // a listener is found
		slog.Warn("Port already in use")
		return nil, errors.New("port already in use")
	}

	listener := VTCPListener{
		TcpStack: tcpStack,
		sId:      tcpStack.SockCouter,
		lAddr:    netip.IPv4Unspecified(),
		lPort:    port,
		rAddr:    netip.IPv4Unspecified(),
		rPort:    0,
		state:    LISTEN,
		NewConns: make(chan *VTCPConn),
	}
	tcpStack.SocketTable[tcpStack.SockCouter] = &listener
	fmt.Println("Created listen socket with ID", tcpStack.SockCouter)
	tcpStack.SockCouter += 1
	tcpStack.EphemeralPortSet[port] = true
	return &listener, nil
}

// This function creates a new socket that connects to the specified virtual IP address and
// port–this corresponds to an “active OPEN” in the RFC.
// VConnect MUST block until the connection is established, or an error occurs.
func (tcpStack *TCPStack) VConnect(addr netip.Addr, port uint16) (VTCPConn, error) {
	ephemeralPort, err := tcpStack.FindUnusedPort()
	if err != nil {
		slog.Warn("All ports are being used")
		return VTCPConn{}, err
	}
	conn := VTCPConn{
		TcpStack:           tcpStack,
		sId:                tcpStack.SockCouter,
		lAddr:              tcpStack.IpStack.Interfaces[0].AssignedIP, // Since each host has only one iface
		lPort:              ephemeralPort,
		rAddr:              addr,
		rPort:              port,
		HandshakeRecSynAck: make(chan bool),
		HandshakeRecAck:    make(chan bool),
		Seq:                rand.Uint32(), // ISN
		Ack:                0,
		WindowSize:         MaxWindowSize,
	}
	tcpStack.SocketTable[tcpStack.SockCouter] = &conn
	fmt.Println("Created listen socket with ID", tcpStack.SockCouter)
	tcpStack.SockCouter += 1
	tcpStack.EphemeralPortSet[ephemeralPort] = true

	// Send SYN
	_, err = tcpStack.SendTCP(&conn, header.TCPFlagSyn, []byte{})
	if err != nil {
		slog.Warn("Failed to send SYN")
		delete(tcpStack.SocketTable, conn.SId())
		tcpStack.SockCouter -= 1
		delete(tcpStack.EphemeralPortSet, ephemeralPort)
		return VTCPConn{}, errors.New("failed to send syn")
	}
	conn.state = SYN_SENT

	// Wait for SYN+ACK
	if <-conn.HandshakeRecSynAck { // TODO: timeout if SYN+ACK not rec
		// Send ACK
		conn.Seq += 1
		_, err = tcpStack.SendTCP(&conn, header.TCPFlagAck, []byte{})
		if err != nil {
			slog.Warn("Failed to send ACK")
			delete(tcpStack.SocketTable, conn.SId())
			tcpStack.SockCouter -= 1
			delete(tcpStack.EphemeralPortSet, ephemeralPort)
			return VTCPConn{}, errors.New("failed to send ack")
		}
		conn.state = ESTABLISHED
	}
	fmt.Println("Created new socket with ID", conn.SId())
	return conn, nil
}

// Handler for TCP command, called when TCP packet recd.
func (tcpStack *TCPStack) TCPPacketHandler(ipStack *ip.IPStack, data []byte) {
	hdr, err := ipv4header.ParseHeader(data)
	if err != nil {
		slog.Warn("Dropping packet, error parsing header")
		return
	}
	ipHeaderSize := hdr.Len

	tcpHeaderAndData := data[ipHeaderSize:hdr.TotalLen]

	// Parse the TCP header into a struct
	tcpHdr := iptcp_utils.ParseTCPHeader(tcpHeaderAndData)

	// Get the payload
	tcpPayload := tcpHeaderAndData[tcpHdr.DataOffset:]

	// Verify the TCP checksum
	tcpChecksumFromHeader := tcpHdr.Checksum // Save original
	tcpHdr.Checksum = 0
	tcpComputedChecksum := iptcp_utils.ComputeTCPChecksum(&tcpHdr, hdr.Src, hdr.Dst, tcpPayload)

	if tcpComputedChecksum != tcpChecksumFromHeader {
		slog.Warn("Dropping packet, incorrect tcp checksum")
		return
	}

	var conn *VTCPConn = nil
	var listener *VTCPListener = nil

	conn, err = tcpStack.FindConn(hdr.Src, tcpHdr.SrcPort, hdr.Dst, tcpHdr.DstPort)
	if err != nil {
		listener, err = tcpStack.FindListener(tcpHdr.DstPort)
		if err != nil {
			slog.Warn("No matching port found")
			return
		}
	}

	// Just an extra check
	if listener == nil && conn == nil {
		slog.Warn("No matching port found")
		return
	}

	if listener != nil {
		// SYN rec for listener -> create a new conn and send it to chan NewConns
		if tcpHdr.Flags == header.TCPFlagSyn {
			newConn := VTCPConn{
				TcpStack:           tcpStack,
				sId:                tcpStack.SockCouter,
				lAddr:              tcpStack.IpStack.Interfaces[0].AssignedIP, // Since each host has only one iface
				lPort:              listener.LPort(),
				rAddr:              hdr.Src,
				rPort:              tcpHdr.SrcPort,
				HandshakeRecSynAck: make(chan bool),
				HandshakeRecAck:    make(chan bool),
				Seq:                rand.Uint32(), // ISN
				Ack:                tcpHdr.SeqNum + 1,
				WindowSize:         MaxWindowSize,
			}
			tcpStack.SocketTable[tcpStack.SockCouter] = &newConn
			slog.Info("New conn created from listen socket", "ID", tcpStack.SockCouter)
			tcpStack.SockCouter += 1
			// CONSIDER: should this be added to set
			// tcpStack.EphemeralPortSet[tcpHdr.SrcPort] = true
			listener.NewConns <- &newConn
		}
	}

	if conn != nil {

		if conn.State() == SYN_SENT {
			// SYN+ACK rec when in SYN_SENT -> inform chan HandshakeRecSynAck
			if tcpHdr.Flags == header.TCPFlagSyn|header.TCPFlagAck {
				conn.Ack = tcpHdr.SeqNum + 1
				conn.HandshakeRecSynAck <- true
			}
		} else if conn.State() == SYN_RECEIVED {
			// ACK rec when in SYN_RECEIVED -> inform chan HandshakeRecAck
			if tcpHdr.Flags == header.TCPFlagAck {
				conn.HandshakeRecAck <- true
			}
		}

	}

}

// Sending IP messages to the provided destination
func (tcpStack *TCPStack) SendTCP(conn *VTCPConn, flags uint8, payload []byte) (int, error) {
	tcpHdr := header.TCPFields{
		SrcPort:       conn.LPort(),
		DstPort:       conn.RPort(),
		SeqNum:        conn.Seq,
		AckNum:        conn.Ack,
		DataOffset:    20,
		Flags:         flags,
		WindowSize:    conn.WindowSize,
		Checksum:      0,
		UrgentPointer: 0,
	}

	checksum := iptcp_utils.ComputeTCPChecksum(&tcpHdr, conn.LAddr(), conn.RAddr(), payload)
	tcpHdr.Checksum = checksum

	// Serialize the TCP header
	tcpHeaderBytes := make(header.TCP, iptcp_utils.TcpHeaderLen)
	tcpHeaderBytes.Encode(&tcpHdr)

	// Combine the TCP header + payload into one byte array, which
	// becomes the payload of the IP packet
	ipPacketPayload := make([]byte, 0, len(tcpHeaderBytes)+len(payload))
	ipPacketPayload = append(ipPacketPayload, tcpHeaderBytes...)
	ipPacketPayload = append(ipPacketPayload, []byte(payload)...)

	slog.Debug("Conn", "id", conn.SId())
	bytesWritten, err := tcpStack.IpStack.SendIP(conn.RAddr(), TcpProtocolNumber, ipPacketPayload)

	return bytesWritten, err
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

func (listener *VTCPListener) VAccept() (*VTCPConn, error) {
	conn := <-listener.NewConns
	conn.state = SYN_RECEIVED

	tcpStack := listener.TcpStack

	// Send SYN+ACK
	_, err := tcpStack.SendTCP(conn, header.TCPFlagSyn|header.TCPFlagAck, []byte{})
	if err != nil {
		slog.Warn("Failed to send SYN+ACK")
		delete(tcpStack.SocketTable, conn.SId())
		tcpStack.SockCouter -= 1
		// CONSIDER: removeing if was added in set
		// delete(tcpStack.EphemeralPortSet, conn.RPort())
		return nil, errors.New("failed to send syn+ack")
	}

	// Wait for ACK
	if <-conn.HandshakeRecAck { // TODO: timeout if ACK not rec
		// Send ACK
		conn.Seq += 1
		conn.state = ESTABLISHED
	}
	fmt.Printf("New connection on socket %d => created new socket %d\n", listener.SId(), conn.SId())
	fmt.Print("> ")
	return conn, nil
}

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
