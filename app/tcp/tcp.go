package tcp

import (
	"IP-TCP-Implementation/app/ip"
	"IP-TCP-Implementation/app/iptcp_utils"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	ipv4header "github.com/brown-csci1680/iptcp-headers"
	"github.com/google/netstack/tcpip/header"
)

const (
	TcpProtocolNumber            = 6
	EphemeralPortRangeLow uint16 = 1025
	EphemeralPortRangeHi  uint16 = 65535
	MaxWindowSize         uint16 = 65535
	MaxSegmentSize        uint16 = 512
	ConnQueueSize                = 32
)

type State uint16

const (
	CLOSED State = iota
	LISTEN
	SYN_SENT
	SYN_RECEIVED
	ESTABLISHED
	FIN_WAIT_1
	FIN_WAIT_2
	CLOSE_WAIT
	LAST_ACK
	TIME_WAIT
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
	TcpStack      *TCPStack
	sId           uint16
	lAddr         netip.Addr
	lPort         uint16
	rAddr         netip.Addr
	rPort         uint16
	state         State
	SND           SND
	RCV           RCV
	ISS           uint32
	IRS           uint32
	HandshakeDone chan bool
}

type SEG struct {
	SEQ uint32
	ACK uint32
	LEN uint16
	WND uint16
}

type SND struct {
	Buf                []byte
	UNA                uint32
	NXT                uint32
	WND                uint16
	LBW                uint32
	WL1                uint32
	WL2                uint32
	BufLock            sync.Mutex
	SpaceAvailableCond *sync.Cond
	DataAvailableCond  *sync.Cond
	RetransQ           SegPriorityQueue
}

type RCV struct {
	Buf               []byte
	NXT               uint32
	WND               uint16
	LBR               uint32
	BufLock           sync.Mutex
	DataAvailableCond *sync.Cond
	EarlyArrivalQ     SegPriorityQueue
}

type TCPStack struct {
	IpStack          *ip.IPStack
	SocketTable      map[uint16]Socket
	SockCouter       uint16
	EphemeralPortSet map[uint16]bool
	CtrlLock         sync.Mutex
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
		slog.Warn("Dropping packet, error parsing header", err)
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

	tcpStack.CtrlLock.Lock()
	conn, err = tcpStack.FindConn(hdr.Src, tcpHdr.SrcPort, hdr.Dst, tcpHdr.DstPort)
	if err != nil {
		listener, err = tcpStack.FindListener(tcpHdr.DstPort)
		if err != nil {
			slog.Warn("No matching port found")
			tcpStack.CtrlLock.Unlock()
			return
		}
	}
	tcpStack.CtrlLock.Unlock()

	// Just an extra check
	if listener == nil && conn == nil {
		slog.Warn("No matching port found")
		return
	}

	// Recvd segment
	recSeg := SEG{
		SEQ: tcpHdr.SeqNum,
		ACK: tcpHdr.AckNum,
		LEN: uint16(len(tcpPayload)),
		WND: tcpHdr.WindowSize,
	}

	if listener != nil {
		// SYN rec for listener, create a new conn, send SYN+ACK and send conn to chan NewConns
		if tcpHdr.Flags == header.TCPFlagSyn {

			newConn := NewVTCPConn(tcpStack)
			newConn.lAddr = tcpStack.IpStack.Interfaces[0].AssignedIP // Since each host has only one iface
			newConn.lPort = listener.LPort()
			newConn.rAddr = hdr.Src
			newConn.rPort = tcpHdr.SrcPort

			newConn.IRS = recSeg.SEQ
			newConn.RCV.NXT = recSeg.SEQ + 1

			// Send SYN+ACK
			sendSeg := SEG{
				SEQ: newConn.ISS,
				ACK: newConn.RCV.NXT,
				LEN: 1, // SYN is of len 1 but no data
				WND: newConn.RCV.WND,
			}
			_, err = tcpStack.SendTCP(newConn, header.TCPFlagSyn|header.TCPFlagAck, sendSeg, []byte{})
			if err != nil {
				slog.Warn("Failed to send SYN+ACK")
				return
			}
			newConn.SND.NXT = newConn.ISS + 1
			newConn.SND.UNA = newConn.ISS
			newConn.state = SYN_RECEIVED
			newConn.SND.RetransQ.Push(&sendSeg)

			tcpStack.CtrlLock.Lock()
			tcpStack.SocketTable[tcpStack.SockCouter] = newConn
			slog.Info("New conn created from listen socket", "ID", tcpStack.SockCouter)
			tcpStack.SockCouter += 1
			// CONSIDER: should this be added to set
			// tcpStack.EphemeralPortSet[tcpHdr.SrcPort] = true
			tcpStack.CtrlLock.Unlock()

			// Send the newly created normal socket conn
			listener.NewConns <- newConn
		}
	}

	if conn != nil {
		conn.RCV.BufLock.Lock()
		conn.SND.BufLock.Lock()
		defer conn.SND.BufLock.Unlock()
		defer conn.RCV.BufLock.Unlock()

		if conn.State() == SYN_SENT {
			if tcpHdr.Flags&header.TCPFlagAck > 0 { // Ack recvd
				if !(ModularLessThan(conn.SND.UNA, recSeg.ACK, conn.ISS) && ModularLessThanEqual(recSeg.ACK, conn.SND.NXT, conn.ISS)) {
					return
				}
				conn.SND.UNA = recSeg.ACK
			}

			if tcpHdr.Flags&header.TCPFlagSyn > 0 { // SYN recvd
				conn.RCV.NXT = recSeg.SEQ + 1
				conn.IRS = recSeg.SEQ

				for conn.SND.RetransQ.Len() > 0 && ModularLessThanEqual(conn.SND.RetransQ[0].SEQ+uint32(conn.SND.RetransQ[0].LEN), recSeg.ACK, conn.ISS) {
					conn.SND.RetransQ.Pop()
					// Don't update ACK here as transmitted ACK was 0, just a placeholder till you get IRS
				}

				if ModularLessThan(conn.ISS, conn.SND.UNA, conn.ISS) { // ISS has been acked
					// send ACK
					ackSendSeg := SEG{
						SEQ: conn.SND.NXT,
						ACK: conn.RCV.NXT,
						LEN: 0,
						WND: conn.RCV.WND,
					}
					_, err = tcpStack.SendTCP(conn, header.TCPFlagAck, ackSendSeg, []byte{})
					if err != nil {
						slog.Warn("Failed to send ACK")
						return
					}
					conn.SND.LBW = conn.ISS
					conn.RCV.LBR = conn.IRS
					conn.state = ESTABLISHED
					conn.HandshakeDone <- true
				} else {
					conn.state = SYN_RECEIVED
					// Send SYN+ACK
					sendSeg := SEG{
						SEQ: conn.ISS,
						ACK: conn.RCV.NXT,
						LEN: 1, // SYN is of len 1 but no data
						WND: conn.RCV.WND,
					}
					_, err = tcpStack.SendTCP(conn, header.TCPFlagSyn|header.TCPFlagAck, sendSeg, []byte{})
					if err != nil {
						slog.Warn("Failed to send SYN+ACK")
						return
					}
					conn.SND.WND = recSeg.WND
					conn.SND.WL1 = recSeg.SEQ
					conn.SND.WL2 = recSeg.ACK
					conn.SND.RetransQ.Push(&sendSeg)
				}
			}

		} else if conn.State() == SYN_RECEIVED {
			// ACK rec when in SYN_RECEIVED
			if ModularLessThan(conn.SND.UNA, recSeg.ACK, conn.ISS) && ModularLessThanEqual(recSeg.ACK, conn.SND.NXT, conn.ISS) {
				for conn.SND.RetransQ.Len() > 0 && ModularLessThanEqual(conn.SND.RetransQ[0].SEQ+uint32(conn.SND.RetransQ[0].LEN), recSeg.ACK, conn.ISS) {
					conn.SND.RetransQ.Pop()
					// Don't update ACK here as transmitted ACK was to validate the remote seq num
					// We want to update to what we have recvd as ack (our ISS ack'd)
				}
				conn.SND.UNA = recSeg.ACK
				conn.SND.WND = recSeg.WND
				conn.SND.WL1 = recSeg.SEQ
				conn.SND.WL2 = recSeg.ACK
				conn.SND.LBW = conn.ISS
				conn.RCV.LBR = conn.IRS
				conn.state = ESTABLISHED
				conn.HandshakeDone <- true
			}
		} else if AcceptableSegSeq(&recSeg, &conn.RCV, conn.IRS) {
			// trim the from the begenning of the payload
			trimBegBytes := 0
			for !ModularLessThanEqual(conn.RCV.NXT, recSeg.SEQ, conn.IRS) {
				recSeg.SEQ++
				recSeg.LEN--
				trimBegBytes++
			}
			if trimBegBytes > 0 {
				tcpPayload = tcpPayload[trimBegBytes:]
			}

			// trim the from the end of the payload
			trimEndBytes := 0
			if !ModularLessThan(recSeg.SEQ+uint32(recSeg.LEN)-1, conn.RCV.NXT+uint32(conn.RCV.WND), conn.IRS) {
				recSeg.LEN--
				trimEndBytes++
			}
			if trimEndBytes > 0 {
				tcpPayload = tcpPayload[:recSeg.LEN]
			}

			// CONSIDER: moving SYN_RECIEVED state handling here as suggested in RFC

			// ACK is not set then drop
			if tcpHdr.Flags&header.TCPFlagAck == 0 {
				slog.Debug("Incoming packet does not have ACK set")
				return
			}

			if conn.State() == ESTABLISHED {
				if tcpHdr.Flags == header.TCPFlagFin|header.TCPFlagAck {
					seqStart := conn.SND.NXT
					seg := SEG{
						SEQ: seqStart,
						ACK: tcpHdr.SeqNum + 1,
						LEN: 1,
						WND: conn.RCV.WND,
					}
					_, err := conn.TcpStack.SendTCP(conn, header.TCPFlagAck, seg, []byte{})
					if err != nil {
						slog.Warn("Failed to send ack of FIN")
					} else {
						conn.SND.RetransQ.Push(&seg)
						conn.state = CLOSE_WAIT
					}

				} else {
					wndUpdated := false
					if ModularLessThan(conn.SND.UNA, recSeg.ACK, conn.ISS) && ModularLessThanEqual(recSeg.ACK, conn.SND.NXT, conn.ISS) {
						for conn.SND.RetransQ.Len() > 0 && ModularLessThanEqual(conn.SND.RetransQ[0].SEQ+uint32(conn.SND.RetransQ[0].LEN), recSeg.ACK, conn.ISS) {
							ackedSeg := conn.SND.RetransQ.Pop()
							conn.SND.UNA = ackedSeg.ACK
							if (ModularLessThan(conn.SND.WL1, ackedSeg.SEQ, conn.ISS)) || (conn.SND.WL1 == ackedSeg.SEQ && ModularLessThanEqual(conn.SND.WL2, ackedSeg.ACK, conn.ISS)) {
								conn.SND.WND = ackedSeg.WND
								conn.SND.WL1 = ackedSeg.SEQ
								conn.SND.WL2 = ackedSeg.ACK
								wndUpdated = true
							}
						}
					} else if conn.SND.UNA == recSeg.ACK {
						// nothing to be acked but potentially update wnd
						if (ModularLessThan(conn.SND.WL1, recSeg.SEQ, conn.ISS)) || (conn.SND.WL1 == recSeg.SEQ && ModularLessThanEqual(conn.SND.WL2, recSeg.ACK, conn.ISS)) {
							conn.SND.WND = recSeg.WND
							conn.SND.WL1 = recSeg.SEQ
							conn.SND.WL2 = recSeg.ACK
							wndUpdated = true
						}
					} else if ModularLessThan(conn.SND.NXT, recSeg.ACK, conn.ISS) { // ACK for something not sent, just inform the correct ack num expected
						sendSeg := SEG{
							SEQ: conn.SND.NXT,
							ACK: conn.RCV.NXT,
							LEN: 0,
							WND: conn.RCV.WND,
						}
						_, err = tcpStack.SendTCP(conn, header.TCPFlagAck, sendSeg, []byte{})
						if err != nil {
							slog.Warn("Failed to send ACK")
							return
						}
					} else { // Duplicate ACK
						return
					}

					if wndUpdated {
						conn.SND.SpaceAvailableCond.Signal()
					}

					// Process the segment text, handles both on time and early arrivals, duplicates will be ignored after begTrim
					for i := 0; i < len(tcpPayload); i++ {
						conn.RCV.Buf[BufIdx(recSeg.SEQ+uint32(i))] = tcpPayload[i]
					}
					if recSeg.SEQ == conn.RCV.NXT { // On time arrival
						conn.RCV.NXT += uint32(recSeg.LEN)
						conn.RCV.WND -= recSeg.LEN
						for conn.RCV.EarlyArrivalQ.Len() > 0 && conn.RCV.EarlyArrivalQ[0].SEQ == conn.RCV.NXT {
							earlySeg := conn.RCV.EarlyArrivalQ.Pop()
							conn.RCV.NXT += uint32(earlySeg.LEN)
							conn.RCV.WND -= recSeg.LEN
						}
						// NXT updated thus data available
						conn.RCV.DataAvailableCond.Signal()
					} else { // Early arrival
						conn.RCV.EarlyArrivalQ.Push(&recSeg)
					}
					// If text was recvd then ack it
					if len(tcpPayload) > 0 {
						sendSeg := SEG{
							SEQ: conn.SND.NXT,
							ACK: conn.RCV.NXT,
							LEN: 0,
							WND: conn.RCV.WND,
						}
						_, err = tcpStack.SendTCP(conn, header.TCPFlagAck, sendSeg, []byte{})
						if err != nil {
							slog.Warn("Failed to send ACK")
							return
						}
					}
				}
			}
			if conn.State() == FIN_WAIT_1 {
				if tcpHdr.Flags == header.TCPFlagAck {
					conn.state = FIN_WAIT_2
				}
			}
			if conn.State() == FIN_WAIT_2 {
				if tcpHdr.Flags == header.TCPFlagFin|header.TCPFlagAck {
					seqStart := conn.SND.NXT
					seg := SEG{
						SEQ: seqStart,
						ACK: tcpHdr.SeqNum + 1,
						LEN: 1,
						WND: conn.RCV.WND,
					}
					_, err := conn.TcpStack.SendTCP(conn, header.TCPFlagAck, seg, []byte{})
					if err != nil {
						slog.Warn("Failed to send ack of FIN")
					} else {
						conn.SND.RetransQ.Push(&seg)
						conn.state = TIME_WAIT
						// need to calculate MSL and wait for 2*MSL, the following is just a dummy wait
						time.Sleep(10 * time.Second) // dummy wait
						sid := conn.sId
						tcpStack.CtrlLock.Lock()
						delete(tcpStack.SocketTable, sid)
						tcpStack.CtrlLock.Unlock()
					}
				}
			}
			if conn.State() == LAST_ACK {
				if tcpHdr.Flags == header.TCPFlagAck {
					conn.state = CLOSED
					sid := conn.sId
					tcpStack.CtrlLock.Lock()
					delete(tcpStack.SocketTable, sid)
					tcpStack.CtrlLock.Unlock()
				}
			}

		} else { // Not acceptable seg
			sendSeg := SEG{
				SEQ: conn.SND.NXT,
				ACK: conn.RCV.NXT,
				LEN: 0,
				WND: conn.RCV.WND,
			}
			_, err = tcpStack.SendTCP(conn, header.TCPFlagAck, sendSeg, []byte{})
			if err != nil {
				slog.Warn("Failed to send ACK")
				return
			}
		}
		// else if conn.State() == ESTABLISHED {
		// 	if tcpHdr.SeqNum == conn.Ack { // expected segment
		// 		if conn.RCV.WND >= uint16(len(tcpPayload)) { // if the payload is too big it will be dropped
		// 			signalDataAvailable := false
		// 			if conn.RCV.LBR+1 == conn.RCV.NXT { // check if there was no data to be read
		// 				signalDataAvailable = true // in which case now inform there is
		// 			}
		// 			for i := 0; i < len(tcpPayload); i++ {
		// 				conn.RCV.buf[conn.RCV.NXT] = tcpPayload[i]
		// 				conn.RCV.NXT = Mod(conn.RCV.NXT + 1)
		// 			}
		// 			if signalDataAvailable {
		// 				conn.RCV.DataAvailable <- true
		// 			}
		// 			conn.Ack += uint32(len(tcpPayload))

		// 		}
		// 	}
		// 	// TODO: early arrivals
		// 	// else if tcpHdr.SeqNum == conn.Ack { // early arrival segment
		// 	// }
		// 	for _, seg := range conn.TransmittedSegs {
		// 		if seg.ACK <= tcpHdr.AckNum {
		// 			conn.SND.UNA = Mod(conn.SND.UNA + seg.WND)
		// 			conn.SND.WND = Mod(conn.SND.WND + seg.WND)
		// 		}
		// 	}
		// }

	}

}

// Sending IP messages to the provided destination
func (tcpStack *TCPStack) SendTCP(conn *VTCPConn, flags uint8, seg SEG, payload []byte) (int, error) {
	tcpHdr := header.TCPFields{
		SrcPort:       conn.LPort(),
		DstPort:       conn.RPort(),
		SeqNum:        seg.SEQ,
		AckNum:        seg.ACK,
		DataOffset:    20,
		Flags:         flags,
		WindowSize:    seg.WND,
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
