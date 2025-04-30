package main

import (
	"IP-TCP-Implementation/app/common"
	"IP-TCP-Implementation/app/ip"
	"IP-TCP-Implementation/app/lnxconfig"
	"IP-TCP-Implementation/app/protocol"
	"IP-TCP-Implementation/app/rip"
	"log/slog"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		slog.Error("usage: %s --config <lnx file>", os.Args[0])
	}

	// fmt.Println("my_imp")

	// Change logging level
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	slog.SetDefault(logger)

	lnxFile := os.Args[2]

	// Parse lnx config file
	configInfo, err := lnxconfig.ParseConfig(lnxFile)
	if err != nil {
		slog.Error("Failed to parse lnx file.")
	}

	ipStack := ip.Initialize(configInfo)

	// Set up all interfaces to listen and respond
	for idx, _ := range ipStack.Interfaces {
		err = ipStack.Interfaces[idx].InitAndListenLinkLayer(ipStack)
		if err != nil {
			slog.Error("Failed to init the interface. Err: ", err)
		}
	}

	// Register handlers for supported packets/protocols
	ipStack.RegisterRecvHandler(0, protocol.TestPacketHandler)
	// Setup and Register RIP
	if ipStack.RoutingMode == ip.RoutingTypeRIP {
		rip.InitRIP(ipStack)
		// Begin Periodic RoutingTable cleanup
		go ipStack.BeginRoutingTableCleanup()
		// Register Handler
		ipStack.RegisterRecvHandler(200, rip.RIPPacketHandler)
	}

	// REPL
	common.RunREPL(ipStack)

}
