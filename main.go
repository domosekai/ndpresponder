package main

import (
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go4.org/netipx"
)

var logger = func() *zap.Logger {
	lvl := zapcore.InfoLevel
	if environ, ok := os.LookupEnv("NDPRESPONDER_LOG"); ok {
		lvl.Set(environ)
	}

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		os.Stderr,
		lvl,
	)
	return zap.New(core)
}()

var (
	netif         *net.Interface
	targetSubnets *netipx.IPSet
)

var app = &cli.App{
	Name:        "ndpresponder",
	Description: "IPv6 Neighbor Discovery Responder",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "ifname",
			Aliases:  []string{"i"},
			Usage:    "uplink network interface",
			Required: true,
		},
		&cli.StringSliceFlag{
			Name:    "subnet",
			Aliases: []string{"n"},
			Usage:   "static target subnet",
		},
	},
	HideHelpCommand: true,
	Before: func(c *cli.Context) (e error) {
		if netif, e = net.InterfaceByName(c.String("ifname")); e != nil {
			return cli.Exit(e, 1)
		}

		var ipset netipx.IPSetBuilder
		for _, subnet := range c.StringSlice("subnet") {
			prefix, e := netip.ParsePrefix(subnet)
			if e != nil {
				return cli.Exit(e, 1)
			}
			ipset.AddPrefix(prefix)
		}
		targetSubnets, e = ipset.IPSet()
		if e != nil {
			return cli.Exit(e, 1)
		}

		return nil
	},
	Action: func(c *cli.Context) error {
		hi := gatherHostInfo()
		h, e := afpacket.NewTPacket(
			afpacket.OptInterface(netif.Name),
			afpacket.OptBlockSize(64*1024),
			afpacket.OptNumBlocks(16),
			afpacket.OptBlockTimeout(time.Millisecond),
		)
		if e != nil {
			return cli.Exit(e, 1)
		}
		defer h.Close()
		if e = h.SetBPF(bpfFilter); e != nil {
			return cli.Exit(e, 1)
		}
		solicitations := CaptureNeighSolicitation(h)

		sbuf := gopacket.NewSerializeBuffer()
		for {
			ns := <-solicitations
			if !ns.DestIP.IsMulticast() || !targetSubnets.Contains(ns.TargetIP) {
				logger.Debug("IGNORE", zap.Stringer("ns", ns))
				continue
			}

			if e := ns.Respond(sbuf, hi); e != nil {
				logger.Warn("RESPOND error", zap.Stringer("ns", ns), zap.Error(e))
				continue
			}
			if e := h.WritePacketData(sbuf.Bytes()); e != nil {
				logger.Warn("RESPOND write error", zap.Stringer("ns", ns), zap.Error(e))
				continue
			}
			logger.Debug("RESPOND", zap.Stringer("ns", ns))
		}
	},
}

func main() {
	app.Run(os.Args)
}
