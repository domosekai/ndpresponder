package main

import (
	"net"
	"net/netip"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go4.org/netipx"
)

var logger = func() *zap.Logger {
	var lvl zapcore.Level
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
		h, e := afpacket.NewTPacket(afpacket.OptInterface(netif.Name))
		if e != nil {
			return cli.Exit(e, 1)
		}
		if e = h.SetBPF(bpfFilter); e != nil {
			return cli.Exit(e, 1)
		}
		solicitations := CaptureNeighSolicitation(h)

		sbuf := gopacket.NewSerializeBuffer()
		for {
			ns := <-solicitations
			logEntry := logger.With(zap.Stringer("ns", ns))
			if !ns.DestIP.IsMulticast() || !targetSubnets.Contains(ns.TargetIP) {
				logEntry.Debug("IGNORE")
				continue
			}
			logEntry = logEntry.With(zap.String("reason", "static"))

			if e := ns.Respond(sbuf, hi); e != nil {
				logEntry.Warn("RESPOND error", zap.Error(e))
				continue
			}
			logEntry.Info("RESPOND")
			h.WritePacketData(sbuf.Bytes())
		}
	},
}

func main() {
	app.Run(os.Args)
}
