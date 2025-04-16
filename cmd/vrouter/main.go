package main

import (
	"IP-TCP-Implementation/app/common"
	"IP-TCP-Implementation/app/ip"
	"IP-TCP-Implementation/app/lnxconfig"
	"IP-TCP-Implementation/app/protocol"
	"log/slog"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		slog.Error("usage: %s --config <lnx file>", os.Args[0])
	}

	// Change logging level
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	lnxFile := os.Args[2]

	// Parse lnx config file
	configInfo, err := lnxconfig.ParseConfig(lnxFile)
	if err != nil {
		slog.Error("Failed to parse lnx file.")
	}

	ipStack := ip.Initialize(configInfo)
	slog.Debug("IP stack initialized to: ", ipStack)

	// Register handlers for supported packets/protocols
	ipStack.RegisterRecvHandler(0, protocol.TestPacketHandler)

	// Set up all interfaces to listen and respond
	for idx, iface := range ipStack.Interfaces {
		slog.Debug("Start serving %s", iface.UDPAddr)
		go ipStack.Interfaces[idx].ListenLinkLayer(ipStack)
	}

	// REPL
	common.RunREPL(ipStack)

}
