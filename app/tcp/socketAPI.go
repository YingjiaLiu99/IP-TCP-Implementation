package tcp

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/google/netstack/tcpip/header"
)

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

// VAccept waits for new TCP connections on the given listening socket.
// If no new clients have connected, this function MUST block until a new connection occurs.
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
	go conn.TransmitData()
	fmt.Printf("New connection on socket %d => created new socket %d\n", listener.SId(), conn.SId())
	fmt.Print("> ")
	return conn, nil
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

	conn := NewVTCPConn(tcpStack)
	conn.lAddr = tcpStack.IpStack.Interfaces[0].AssignedIP // Since each host has only one iface
	conn.lPort = ephemeralPort
	conn.rAddr = addr
	conn.rPort = port
	conn.Ack = 0

	tcpStack.SocketTable[tcpStack.SockCouter] = &conn
	fmt.Println("Created normal socket with ID", tcpStack.SockCouter)
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
	go conn.TransmitData()
	fmt.Println("Created new socket with ID", conn.SId())
	return conn, nil
}

// This method reads data from the TCP socket (equivalent to RECEIVE in RFC).
// In this version, data is read into a slice (buf) passed as argument.
func (conn *VTCPConn) VRead(buf []byte) (int, error) {
	if Mod(conn.RCV.LBR+1) == conn.RCV.NXT { // check if data to be read
		slog.Debug("Waiting for data")
		<-conn.RCV.DataAvailable // unblock only when data to be read
		slog.Debug("Rec data")
	}
	bytesRead := 0
	for bytesRead < len(buf) {
		if Mod(conn.RCV.LBR+1) == conn.RCV.NXT { // check if data to be read
			break
		}
		conn.RCV.LBR = Mod(conn.RCV.LBR + 1)
		buf[bytesRead] = conn.RCV.buf[conn.RCV.LBR]
		bytesRead++
	}

	return bytesRead, nil
}

// Runs as a go routine.
// Packages data into segments and sends it if data available
func (conn *VTCPConn) TransmitData() {
	for {
		if conn.SND.NXT == Mod(conn.SND.LBW+1) { // check if data to be sent
			<-conn.SND.DataAvailable // unblock only when data to be sent
			// CONSIDER: using conditional variable here
		}
		if conn.RemoteWindowSize == 0 { // check if remote can recv
			// TODO: 0 window probing
			<-conn.RemoteCanRecv // unblock only when remote can recv
		}
		var payloadSize uint16 = 0
		payload := []byte{}
		for payloadSize <= conn.RemoteWindowSize && payloadSize <= MaxTCPPayloadSize {
			payload = append(payload, conn.SND.buf[conn.SND.NXT])
			payloadSize += 1
			if conn.SND.NXT == Mod(conn.SND.LBW+1) { // We have packaged all available bytes
				// special case and not increment, being blocked on conn.SND.DataAvailable will signify
				// buf is empty from the case when 1 byte LBW can be written, so no need to inc NXT
				break
			}
			conn.SND.NXT = Mod(conn.SND.NXT + 1)
		}
		conn.RemoteWindowSize -= payloadSize

		conn.TransmittedSegs = append(conn.TransmittedSegs, SEG{
			SEQ: conn.Seq,
			ACK: conn.Seq + uint32(payloadSize),
			LEN: payloadSize,
			WND: conn.RemoteWindowSize,
		})

		_, err := conn.TcpStack.SendTCP(conn, header.TCPFlagSyn|header.TCPFlagAck, payload)
		if err != nil {
			slog.Warn("Failed to transmit data")
		}
		conn.Seq += uint32(payloadSize)
	}
}

// This method writes data to the TCP socket (equivalent to SEND in the RFC).
// In this version, data to write is passed as a byte slice (data).
func (conn *VTCPConn) VWrite(data []byte) (int, error) {
	bytesWritten := 0
	for i := 0; i < len(data); i++ {
		if conn.SND.WND == 0 { // can't write, buff full
			if bytesWritten > 0 {
				conn.SND.DataAvailable <- true
			}
			<-conn.SND.SpaceAvailable // block until space is available
		}
		conn.SND.buf[Mod(conn.SND.LBW+1)] = data[i]
		conn.SND.LBW = Mod(conn.SND.LBW + 1)
		conn.SND.WND = conn.SND.WND - 1
		bytesWritten++
	}
	if bytesWritten > 0 {
		conn.SND.DataAvailable <- true
	}
	return bytesWritten, nil
}
