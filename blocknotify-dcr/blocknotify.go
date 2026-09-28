// Copyright (c) 2015-2017 YiiMP

// blocknotify wrapper for Decred: dcrd has no blocknotify option, so this tool
// connects to the dcrd websocket RPC, registers for block notifications and
// calls the standard bin/blocknotify yiimp tool for every connected block.
//
// Note: this tool is connected directly to dcrd, not to the wallet!
//
// The block id sent to the stratum is the BLAKE-256 hash of the header (the
// usual Decred block hash); since DCP-0011 the proof of work hash is BLAKE3,
// the stratum stores both.
//
// usage: blocknotify-dcr -stratum 127.0.0.1:3252 -coinid 1574 \
//          -rpcuser user -rpcpass pass [-rpcserver 127.0.0.1:9109] [-rpccert rpc.cert | -notls]

package main

import (
	"bytes"
	"context"
	"flag"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/decred/dcrd/rpcclient/v8"
	"github.com/decred/dcrd/wire"
)

func main() {
	processName := flag.String("blocknotify", "blocknotify", "yiimp blocknotify tool (full path if not in PATH)")
	stratumDest := flag.String("stratum", "127.0.0.1:3252", "stratum host:port")
	coinID := flag.String("coinid", "1574", "decred coin id in the yiimp database")
	rpcServer := flag.String("rpcserver", "127.0.0.1:9109", "dcrd RPC host:port")
	rpcUser := flag.String("rpcuser", "yiimprpc", "dcrd RPC user")
	rpcPass := flag.String("rpcpass", "myDcrdPassword", "dcrd RPC password")
	rpcCert := flag.String("rpccert", "rpc.cert", "dcrd RPC TLS certificate")
	noTLS := flag.Bool("notls", false, "connect to dcrd without TLS (dcrd --notls)")
	debug := flag.Bool("debug", false, "log every block")
	flag.Parse()

	ntfnHandlers := rpcclient.NotificationHandlers{
		OnBlockConnected: func(blockHeader []byte, transactions [][]byte) {
			var bhead wire.BlockHeader
			if err := bhead.Deserialize(bytes.NewReader(blockHeader)); err != nil {
				log.Printf("invalid block header: %v", err)
				return
			}
			str := bhead.BlockHash().String()
			args := []string{*stratumDest, *coinID, str}
			out, err := exec.Command(*processName, args...).CombinedOutput()
			if err != nil {
				log.Printf("%s %v: %v %s", *processName, args, err, out)
			} else if *debug {
				log.Printf("block %d connected: %s %s", bhead.Height, str, out)
			}
		},
	}

	var certs []byte
	if !*noTLS {
		var err error
		certs, err = os.ReadFile(*rpcCert)
		if err != nil {
			log.Fatalf("%v (use -notls if dcrd runs with --notls)", err)
		}
	}

	connCfg := &rpcclient.ConnConfig{
		Host:         *rpcServer,
		Endpoint:     "ws",
		User:         *rpcUser,
		Pass:         *rpcPass,
		DisableTLS:   *noTLS,
		Certificates: certs,
	}

	client, err := rpcclient.New(connCfg, &ntfnHandlers)
	if err != nil {
		log.Fatalln(err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Register for block connect notifications (re-registered on reconnect).
	if err := client.NotifyBlocks(ctx); err != nil {
		log.Fatalln(err)
	}
	log.Println("NotifyBlocks: Registration Complete")

	<-ctx.Done()
	client.Shutdown()
	client.WaitForShutdown()
}
