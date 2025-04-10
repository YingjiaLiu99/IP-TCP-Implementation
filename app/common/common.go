package common

import (
	"IP-TCP-Implementation/app/ip"
	"IP-TCP-Implementation/app/protocol"
	"bufio"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

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
			ListCommands()
		}

		fmt.Print("> ")
	}
}

func ListCommands() {
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
	w.Flush()
}
