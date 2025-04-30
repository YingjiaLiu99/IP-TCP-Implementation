package tcp

import (
	"IP-TCP-Implementation/app/ip"
	"IP-TCP-Implementation/app/iptcp_utils"
	"log/slog"
	"net/netip"

	ipv4header "github.com/brown-csci1680/iptcp-headers"
	"github.com/google/netstack/tcpip/header"
)

const (
	TcpProtocolNumber            = 6
	EphemeralPortRangeLow uint16 = 1025
	EphemeralPortRangeHi  uint16 = 65535
	MaxWindowSize         uint16 = 65535
	MaxTCPPayloadSize     uint16 = 512
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
	TransmittedSegs    []SEG
	SND                SND
	RCV                RCV
	RemoteWindowSize   uint16
	RemoteCanRecv      chan bool
}

type SEG struct {
	SEQ uint32
	ACK uint32
	LEN uint16
	WND uint16
}

type SND struct {
	buf            []byte
	UNA            uint16
	NXT            uint16
	WND            uint16
	LBW            uint16
	SpaceAvailable chan bool
	DataAvailable  chan bool
}

type RCV struct {
	buf           []byte
	NXT           uint16
	WND           uint16
	LBR           uint16
	DataAvailable chan bool
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

	slog.Debug("Rec", "Flags", iptcp_utils.TCPFlagsAsString(tcpHdr.Flags))

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

			newConn := NewVTCPConn(tcpStack)
			newConn.lAddr = tcpStack.IpStack.Interfaces[0].AssignedIP // Since each host has only one iface
			newConn.lPort = listener.LPort()
			newConn.rAddr = hdr.Src
			newConn.rPort = tcpHdr.SrcPort
			newConn.Ack = tcpHdr.SeqNum + 1
			newConn.RemoteWindowSize = tcpHdr.WindowSize

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
				conn.RemoteWindowSize = tcpHdr.WindowSize
				conn.HandshakeRecSynAck <- true
			}
		} else if conn.State() == SYN_RECEIVED {
			// ACK rec when in SYN_RECEIVED -> inform chan HandshakeRecAck
			if tcpHdr.Flags == header.TCPFlagAck {
				conn.HandshakeRecAck <- true
			}
		} else if conn.State() == ESTABLISHED {
			if tcpHdr.SeqNum == conn.Ack { // expected segment
				if conn.RCV.WND >= uint16(len(tcpPayload)) { // if the payload is too big it will be dropped
					signalDataAvailable := false
					if conn.RCV.LBR+1 == conn.RCV.NXT { // check if there was no data to be read
						signalDataAvailable = true // in which case now inform there is
					}
					for i := 0; i < len(tcpPayload); i++ {
						conn.RCV.buf[conn.RCV.NXT] = tcpPayload[i]
						conn.RCV.NXT = Mod(conn.RCV.NXT + 1)
					}
					if signalDataAvailable {
						conn.RCV.DataAvailable <- true
					}
					conn.Ack += uint32(len(tcpPayload))

				}
			}
			// TODO: early arrivals
			// else if tcpHdr.SeqNum == conn.Ack { // early arrival segment
			// }
			for _, seg := range conn.TransmittedSegs {
				if seg.ACK <= tcpHdr.AckNum {
					conn.SND.UNA = Mod(conn.SND.UNA + seg.WND)
					conn.SND.WND = Mod(conn.SND.WND + seg.WND)
				}
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
		WindowSize:    conn.RCV.WND,
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

	bytesWritten, err := tcpStack.IpStack.SendIP(conn.RAddr(), TcpProtocolNumber, ipPacketPayload)

	return bytesWritten, err
}
