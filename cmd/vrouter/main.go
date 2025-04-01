package main

import (
	"IP-TCP-Implementation/app/ip"
	"IP-TCP-Implementation/app/lnxconfig"
	"log/slog"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		slog.Error("usage: %s --config <lnx file>", os.Args[0])
	}

	// Change logging level
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	lnxFile := os.Args[2]

	// Parse lnx config file
	configInfo, err := lnxconfig.ParseConfig(lnxFile)
	if err != nil {
		slog.Error("Failed to parse lnx file.")
	}

	ipStack := ip.Initialize(configInfo)
	slog.Debug("IP stack initialized to: ", ipStack)

}
