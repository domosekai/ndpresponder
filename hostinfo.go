package main

import (
	"net"

	"go.uber.org/zap"
)

// HostInfo contains the link-layer address of the host machine.
type HostInfo struct {
	HostMAC net.HardwareAddr
}

func gatherHostInfo() HostInfo {
	hi := HostInfo{HostMAC: netif.HardwareAddr}
	logger.Named("HostInfo").Info("found MAC", zap.Stringer("mac", hi.HostMAC))
	return hi
}
