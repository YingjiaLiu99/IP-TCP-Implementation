package common

import (
	"IP-TCP-Implementation/app/tcp"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
)

func SendFile(tcpStack *tcp.TCPStack, filepath string, addr netip.Addr, port uint16) {
	conn, err := tcpStack.VConnect(addr, port)
	if err != nil {
		fmt.Println("unable to send file: ", err)
	}
	file, err := os.Open(filepath)
	if err != nil {
		fmt.Println("unable to send file: ", err)
	}
	totalBytesSent := 0
	for {
		buf := make([]byte, tcp.MaxSegmentSize)
		bytesRead, err := file.Read(buf)
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Println("unable to send file: ", err)
		}
		bytesWritten, err := conn.VWrite(buf[:bytesRead])
		if err != nil {
			fmt.Println("unable to send file: ", err)
		}
		totalBytesSent += bytesWritten
	}
	fmt.Printf("Sent %d total bytes\n", totalBytesSent)
	err = conn.VClose()
	if err != nil {
		slog.Warn("Failed to close", "Err", err)
	}
}

func RecvFile(tcpStack *tcp.TCPStack, filepath string, port uint16) {
	listener, err := tcpStack.VListen(uint16(port))
	if err != nil {
		fmt.Println("unable to rcv file: ", err)
	}
	conn, err := listener.VAccept()
	if err != nil {
		fmt.Println("unable to rcv file: ", err)
	}
	fmt.Println("recvfile: client connected!")

	file, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Println("unable to rcv file: ", err)
	}
	totalBytesRcv := 0
	for {
		buf := make([]byte, tcp.MaxSegmentSize)
		bytesRead, err := conn.VRead(buf)
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Println("unable to rcv file: ", err)
		}
		_, err = file.Write(buf[:bytesRead])
		if err != nil {
			fmt.Println("unable to rcv file: ", err)
		}
		totalBytesRcv += bytesRead
	}
	fmt.Printf("recvfile done: read %d bytes total\n", totalBytesRcv)

	err = conn.VClose()
	if err != nil {
		slog.Warn("Failed to close", "Err", err)
	}
	err = listener.VClose()
	if err != nil {
		slog.Warn("Failed to close", "Err", err)
	}
}
