package common

import (
	"IP-TCP-Implementation/app/ip"
	"IP-TCP-Implementation/app/protocol"
	"IP-TCP-Implementation/app/tcp"
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
)

// REPL that runs continuously and gives interface for users to run commands
func RunREPL(ipStack *ip.IPStack) {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("> ")
	for scanner.Scan() {
		line := scanner.Text()
		words := strings.Split(line, " ")
		cmd := words[0]
		switch cmd {
		case "echo":
			fmt.Println(strings.Join(words[1:], " "))
		case "exit":
			os.Exit(0)
		case "li":
			ipStack.ListInterfaces()
		case "lr":
			ipStack.ListRoutingTable()
		case "ln":
			ipStack.ListNeighbors()
		case "up":
			interfaceName := words[1]
			err := ipStack.SetInterfaceState(interfaceName, true)
			if err != nil {
				fmt.Println("Invalid interface name provided. ", err)
			}
		case "down":
			interfaceName := words[1]
			err := ipStack.SetInterfaceState(interfaceName, false)
			if err != nil {
				fmt.Println("Invalid interface name provided. ", err)
			}
		case "send":
			destIp := words[1]
			message := strings.Join(words[2:], " ")
			protocol.SendTest(ipStack, destIp, message)
		default:
			fmt.Println("Invalid command:")
			ListCommands(false)
		}

		fmt.Print("> ")
	}
}

// REPL that runs continuously and gives interface for users to run commands (extended with tcp)
func RunREPLExtended(ipStack *ip.IPStack, tcpStack *tcp.TCPStack) {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("> ")
	for scanner.Scan() {
		line := scanner.Text()
		words := strings.Split(line, " ")
		cmd := words[0]
		switch cmd {
		case "echo":
			fmt.Println(strings.Join(words[1:], " "))
		case "exit":
			os.Exit(0)
		case "li":
			ipStack.ListInterfaces()
		case "lr":
			ipStack.ListRoutingTable()
		case "ln":
			ipStack.ListNeighbors()
		case "up":
			interfaceName := words[1]
			err := ipStack.SetInterfaceState(interfaceName, true)
			if err != nil {
				fmt.Println("Invalid interface name provided. ", err)
			}
		case "down":
			interfaceName := words[1]
			err := ipStack.SetInterfaceState(interfaceName, false)
			if err != nil {
				fmt.Println("Invalid interface name provided. ", err)
			}
		case "send":
			destIp := words[1]
			message := strings.Join(words[2:], " ")
			protocol.SendTest(ipStack, destIp, message)
		case "ls":
			tcpStack.PrintSocketTable()
		case "a":
			if len(words) < 2 {
				fmt.Println("format should be: a <port>")
				fmt.Print("> ")
				continue
			}
			port, err := strconv.Atoi(words[1])
			if err != nil {
				fmt.Println("<port> has to be an integer")
				fmt.Print("> ")
				continue
			}
			listener, err := tcpStack.VListen(uint16(port))
			if err != nil {
				fmt.Println("VAccept error:", err)
			} else {
				go listener.PassiveOpen()
			}
		case "c":
			if len(words) < 3 {
				fmt.Println("Usage: c <ip> <port>")
				fmt.Print("> ")
				continue
			}
			vip, err := netip.ParseAddr(words[1])
			if err != nil {
				fmt.Println("<vip> must be an IPv4 address (eg. 1.2.3.4)")
				fmt.Print("> ")
				continue
			}
			port, err := strconv.Atoi(words[2])
			if err != nil {
				fmt.Println("<port> must be a 16-bit unsigned integer")
				fmt.Print("> ")
				continue
			}
			_, err = tcpStack.VConnect(vip, uint16(port))
			if err != nil {
				fmt.Println("Failed to connect")
			}
		case "s":
			if len(words) < 3 {
				fmt.Println("Usage: s <socket ID> <data>")
				fmt.Print("> ")
				continue
			}
			sid, err := strconv.Atoi(words[1])
			if err != nil {
				fmt.Println("<socket ID> must be an integer")
				fmt.Print("> ")
				continue
			}
			data := strings.Join(words[2:], " ")

			sock, ok := tcpStack.SocketTable[uint16(sid)]
			if !ok {
				fmt.Println("socket not found")
				fmt.Print("> ")
				continue
			}
			conn, ok := sock.(*tcp.VTCPConn)
			if !ok {
				fmt.Println("socket not of type conn")
				fmt.Print("> ")
				continue
			}
			n, err := conn.VWrite([]byte(data))
			if err != nil {
				fmt.Println("Failed to send")
			} else {
				fmt.Printf("Wrote %d bytes\n", n)
			}
		case "r":
			if len(words) < 3 {
				fmt.Println("Usage: r <socket ID> <numbytes>")
				fmt.Print("> ")
				continue
			}
			sid, err := strconv.Atoi(words[1])
			if err != nil {
				fmt.Println("<socket ID> must be an integer")
				fmt.Print("> ")
				continue
			}
			numBytes, err := strconv.Atoi(words[2])
			if err != nil {
				fmt.Println("<numbytes> must be an integer")
				fmt.Print("> ")
				continue
			}

			sock, ok := tcpStack.SocketTable[uint16(sid)]
			if !ok {
				fmt.Println("socket not found")
				fmt.Print("> ")
				continue
			}
			conn, ok := sock.(*tcp.VTCPConn)
			if !ok {
				fmt.Println("socket not of type conn")
				fmt.Print("> ")
				continue
			}
			buf := make([]byte, numBytes)
			n, err := conn.VRead(buf)
			if err != nil {
				fmt.Println("Failed to rcv")
			} else {
				fmt.Printf("Read %d bytes: %s\n", n, string(buf))
			}

		default:
			fmt.Println("Invalid command:")
			ListCommands(true)
		}

		fmt.Print("> ")
	}
}

func ListCommands(extended bool) {
	w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	fmt.Fprintf(w, "Commands\n")
	fmt.Fprintf(w, "\t%s\t%s\n", "echo", "Command test")
	fmt.Fprintf(w, "\t%s\t%s\n", "exit", "Terminate this program")
	fmt.Fprintf(w, "\t%s\t%s\n", "li", "List interfaces")
	fmt.Fprintf(w, "\t%s\t%s\n", "lr", "List routes")
	fmt.Fprintf(w, "\t%s\t%s\n", "ln", "List available neighbors")
	fmt.Fprintf(w, "\t%s\t%s\n", "up", "Enable an interface")
	fmt.Fprintf(w, "\t%s\t%s\n", "down", "Disable an interface")
	fmt.Fprintf(w, "\t%s\t%s\n", "send", "Send test packet")
	if extended {
		fmt.Fprintf(w, "\t%s\t%s\n", "ls", "List sockets")
		fmt.Fprintf(w, "\t%s\t%s\n", "a", "Listen on a port and accept new connections")
		fmt.Fprintf(w, "\t%s\t%s\n", "c", "Connect to a TCP socket")
	}
	w.Flush()
}
