package tcp

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"

	"github.com/google/netstack/tcpip/header"
)

// VListen creates a new listening socket bound to the specified port.
// After binding, this socket moves into the LISTEN state
func (tcpStack *TCPStack) VListen(port uint16) (*VTCPListener, error) {
	tcpStack.CtrlLock.Lock()
	defer tcpStack.CtrlLock.Unlock()
	_, err := tcpStack.FindListener(port) // expects to give error
	if err == nil {                       // a listener is found
		slog.Warn("Port already in use")
		return nil, errors.New("port already in use")
	} else if err.Error() == "could not assert to listener" {
		return nil, err
	}

	listener := VTCPListener{
		TcpStack: tcpStack,
		sId:      tcpStack.SockCouter,
		lAddr:    netip.IPv4Unspecified(),
		lPort:    port,
		rAddr:    netip.IPv4Unspecified(),
		rPort:    0,
		state:    LISTEN,
		NewConns: make(chan *VTCPConn, ConnQueueSize),
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
	listener.SockLock.Lock()
	if listener.State() != LISTEN {
		listener.SockLock.Unlock()
		return nil, errors.New("closing")
	}
	listener.SockLock.Unlock()
	conn, ok := <-listener.NewConns // Get a newly created conn
	if conn == nil || !ok {
		return nil, errors.New("closing")
	}

	// Wait for handshake to complete
	<-conn.HandshakeDone // TODO: timeout if handshake not done

	go conn.TransmitData()
	fmt.Printf("New connection on socket %d => created new socket %d\n", listener.SId(), conn.SId())
	slog.Info("Conn.SND", "SND.NXT", conn.SND.NXT, "SND.UNA", conn.SND.UNA, "SND.LBW", conn.SND.LBW)
	slog.Info("Conn.RCV", "RCV.NXT", conn.RCV.NXT, "RCV.LBR", conn.RCV.LBR)
	fmt.Print("> ")
	return conn, nil
}

// Closes this listening socket, removing it from the socket table.
// No new connection may be made on this socket.
// Any pending requests to create new connections should be deleted.
func (listener *VTCPListener) VClose() error {
	listener.TcpStack.CtrlLock.Lock()
	listener.SockLock.Lock()
	defer listener.SockLock.Unlock()
	defer listener.TcpStack.CtrlLock.Unlock()
	listener.state = CLOSED
	delete(listener.TcpStack.SocketTable, listener.sId)
	delete(listener.TcpStack.EphemeralPortSet, listener.LPort())
	close(listener.NewConns)
	return nil
}

// This function creates a new socket that connects to the specified virtual IP address and
// port–this corresponds to an “active OPEN” in the RFC.
// VConnect MUST block until the connection is established, or an error occurs.
func (tcpStack *TCPStack) VConnect(addr netip.Addr, port uint16) (*VTCPConn, error) {
	tcpStack.CtrlLock.Lock()
	ephemeralPort, err := tcpStack.FindUnusedPort()
	if err != nil {
		slog.Warn("All ports are being used")
		tcpStack.CtrlLock.Unlock()
		return nil, err
	}
	tcpStack.EphemeralPortSet[ephemeralPort] = true // assign it for the conn
	tcpStack.CtrlLock.Unlock()

	conn := NewVTCPConn(tcpStack)
	conn.lAddr = tcpStack.IpStack.Interfaces[0].AssignedIP // Since each host has only one iface
	conn.lPort = ephemeralPort
	conn.rAddr = addr
	conn.rPort = port
	conn.SND.UNA = conn.ISS
	conn.SND.NXT = conn.ISS + 1
	// conn.Ack = 0

	// Send SYN
	synSeg := SEG{
		SEQ:   conn.ISS,
		ACK:   0,
		LEN:   1, // SYN is of len 1 but no data
		WND:   conn.RCV.WND,
		Flags: header.TCPFlagSyn,
	}
	_, err = tcpStack.SendTCP(conn, synSeg, []byte{})
	if err != nil {
		slog.Warn("Failed to send SYN")
		tcpStack.CtrlLock.Lock()
		delete(tcpStack.EphemeralPortSet, ephemeralPort)
		tcpStack.CtrlLock.Unlock()
		return nil, errors.New("failed to send syn")
	}
	conn.state = SYN_SENT
	conn.SND.RetransQ.Push(&synSeg)

	tcpStack.CtrlLock.Lock()
	tcpStack.SocketTable[tcpStack.SockCouter] = conn
	slog.Debug("Created normal socket", "ID", tcpStack.SockCouter)
	tcpStack.SockCouter += 1
	tcpStack.CtrlLock.Unlock()

	// Wait for handshake to complete
	<-conn.HandshakeDone // TODO: timeout if handshake not done

	go conn.TransmitData()
	fmt.Println("Created new socket with ID", conn.SId())
	slog.Info("Conn.SND", "SND.NXT", conn.SND.NXT, "SND.UNA", conn.SND.UNA, "SND.LBW", conn.SND.LBW)
	slog.Info("Conn.RCV", "RCV.NXT", conn.RCV.NXT, "RCV.LBR", conn.RCV.LBR)
	return conn, nil
}

// This method reads data from the TCP socket (equivalent to RECEIVE in RFC).
// In this version, data is read into a slice (buf) passed as argument.
func (conn *VTCPConn) VRead(buf []byte) (int, error) {
	conn.SockLock.Lock()
	if conn.State() != ESTABLISHED && conn.State() != CLOSE_WAIT {
		conn.SockLock.Unlock()
		return 0, io.EOF
	}
	conn.SockLock.Unlock()

	conn.RCV.BufLock.Lock()
	for !ModularLessThan(conn.RCV.LBR+1, conn.RCV.NXT, conn.IRS) { // check if no data available to be read
		// Check if nothing to be read and in CLOSE_WAIT, i.e. other side done sending
		conn.SockLock.Lock()
		if conn.State() == CLOSE_WAIT {
			conn.SockLock.Unlock()
			conn.RCV.BufLock.Unlock()
			return 0, io.EOF
		}
		conn.SockLock.Unlock()

		conn.RCV.DataAvailableCond.Wait() // unblock only when data available to be read
	}
	conn.SockLock.Lock()
	bytesRead := 0
	for ModularLessThan(conn.RCV.LBR+1, conn.RCV.NXT, conn.IRS) && bytesRead < len(buf) {
		conn.RCV.LBR++
		conn.RCV.WND++
		// not the last byte of stream which is FIN then read into user buffer
		if conn.State() != CLOSE_WAIT || conn.RCV.LBR != conn.RCV.NXT-1 {
			buf[bytesRead] = conn.RCV.Buf[BufIdx(conn.RCV.LBR)]
			bytesRead++
		}
	}
	conn.SockLock.Unlock()
	conn.RCV.BufLock.Unlock()
	return bytesRead, nil
}

// Runs as a go routine.
// Packages data into segments and sends it if data available
func (conn *VTCPConn) TransmitData() {
	for {
		conn.SND.BufLock.Lock()
		for !ModularLessThanEqual(conn.SND.NXT, conn.SND.LBW, conn.ISS) { // check if no data available to be sent
			conn.SND.NoDataToTransmitCond.Signal()
			conn.SND.DataAvailableCond.Wait() // unblock only when data available to be sent
		}

		var payloadSize uint16 = 0
		seqStart := conn.SND.NXT
		payload := []byte{}
		for ModularLessThanEqual(conn.SND.NXT, conn.SND.LBW, conn.ISS) && payloadSize < MaxSegmentSize {
			payload = append(payload, conn.SND.Buf[BufIdx(conn.SND.NXT)])
			payloadSize++
			conn.SND.NXT++
		}

		sendSeg := SEG{
			SEQ:   seqStart,
			ACK:   conn.RCV.NXT,
			LEN:   payloadSize,
			WND:   conn.RCV.WND,
			Flags: header.TCPFlagAck,
		}
		_, err := conn.TcpStack.SendTCP(conn, sendSeg, payload)
		if err != nil {
			conn.SND.NXT = seqStart
			slog.Warn("Failed to transmit data")
		} else {
			conn.SND.RetransQ.Push(&sendSeg)
		}
		conn.SND.BufLock.Unlock()
	}
}

// This method writes data to the TCP socket (equivalent to SEND in the RFC).
// In this version, data to write is passed as a byte slice (data).
func (conn *VTCPConn) VWrite(data []byte) (int, error) {
	conn.SockLock.Lock()
	if conn.State() != ESTABLISHED && conn.State() != CLOSE_WAIT {
		return 0, io.EOF
	}
	conn.SockLock.Unlock()

	bytesWritten := 0
	conn.SND.BufLock.Lock()
	for i := 0; i < len(data); i++ {
		// for BufIdx(conn.SND.LBW+1) == BufIdx(conn.SND.UNA) && conn.SND.NXT != conn.SND.UNA { // can't write, buff full
		for !ModularLessThan(conn.SND.LBW+1, conn.SND.UNA+uint32(conn.SND.WND), conn.ISS) {
			// for conn.SND.WND == 0 { // can't write, buff full
			// TODO: Zero window probbing
			if bytesWritten > 0 {
				conn.SND.DataAvailableCond.Signal()
			}
			conn.SND.SpaceAvailableCond.Wait()
		}
		conn.SND.LBW++
		conn.SND.Buf[BufIdx(conn.SND.LBW)] = data[i]
		bytesWritten++
	}
	if bytesWritten > 0 {
		conn.SND.DataAvailableCond.Signal()
	}
	conn.SND.BufLock.Unlock()
	return bytesWritten, nil
}

// Initiates the connection termination process for this socket (equivalent to CLOSE in the RFC).
// This method should be used to indicate that the user is done sending/receiving on this socket.
func (conn *VTCPConn) VClose() error {

	conn.SND.BufLock.Lock()
	for ModularLessThanEqual(conn.SND.NXT, conn.SND.LBW, conn.ISS) { // check if data available to be sent
		conn.SND.NoDataToTransmitCond.Wait() // unblock only when no data available to be sent
	}

	conn.SockLock.Lock()
	seg := SEG{
		SEQ:   conn.SND.NXT,
		ACK:   conn.RCV.NXT,
		LEN:   0,
		WND:   conn.RCV.WND,
		Flags: header.TCPFlagFin | header.TCPFlagAck,
	}
	_, err := conn.TcpStack.SendTCP(conn, seg, []byte{})
	if err != nil {
		slog.Warn("Failed to send FIN|ACK")
		conn.SockLock.Unlock()
		conn.SND.BufLock.Unlock()
		return err
	}
	conn.SND.NXT++
	conn.SND.RetransQ.Push(&seg)
	if conn.state == ESTABLISHED {
		conn.state = FIN_WAIT_1
	} else if conn.state == CLOSE_WAIT {
		conn.state = LAST_ACK
	}
	conn.SockLock.Unlock()
	conn.SND.BufLock.Unlock()
	return nil
}
