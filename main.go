package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	godebug "runtime/debug"
	"strconv"
	"strings"
        _ "github.com/wlynxg/anet"
	"universal-bypass-tool/socks5"
	"universal-bypass-tool/transport"
	"universal-bypass-tool/transport/oneme"
	"universal-bypass-tool/transport/yandex"
	"universal-bypass-tool/tunnel"
	"universal-bypass-tool/utils"
)

var (
	globalDocUrl string
	maxToken     string
	maxUid       string
	localIP      string
)

func main() {
	//os.Setenv("GODEBUG", "netdns=go")
        fmt.Print("written by p1neappleXpress\n")

	exitNode := flag.Bool("exit-node", false, "Run as exit node (needs root)")
	client := flag.Bool("client", false, "Run as client")
	debug := flag.Bool("debug", false, "Enable verbose debug logging")
	socksAddr := flag.String("socks5", ":1080", "SOCKS5 address")
	transportType := flag.String("transport", "yandex", "Transport type (yandex, google, custom)")
	flag.StringVar(&globalDocUrl, "url", "http://#", "Document URL. If u use Yandex.Docs transport")
	flag.StringVar(&maxToken, "maxToken", "", "MAX Web token. If u use MAX transport")
	flag.StringVar(&maxUid, "maxUid", "", "MAX call user id. If u use MAX transport")
	flag.StringVar(&localIP, "local-ip", "", "Egress IP for exit node (scoped RST drop)")
	encryptionKeyFile := flag.String("encryption-key-file", "",
		"Optional: encrypt the transport with AES-256-GCM using a shared secret read from this file. "+
			"Both peers must use the same secret; unset means unencrypted, unchanged behavior")
	flag.Parse()

	if localIP != "" {
		tunnel.SetLocalIP(localIP)
	}

	// The exit node often runs on a tiny VPS; keep the heap tight under load
	// (GC aggressively). Set GOMEMLIMIT in the environment for a hard soft-cap.
	if *exitNode {
		godebug.SetGCPercent(20)
	}

	if !*exitNode && !*client {
		flag.Usage()
		os.Exit(1)
	}

	if *debug {
		utils.EnableDebug()
	}

	log.Printf("=== Universal Bypass Tool ===")
	log.Printf("Mode: %s", map[bool]string{true: "EXIT NODE", false: "CLIENT"}[*exitNode])
	log.Printf("Transport: %s", *transportType)

	// --url accepts either a plain document URL or a ydocs:// link that also
	// carries the shared encryption secret (ydocs://DOC_URL#SECRET). Both
	// peers must be given the same link.
	link, err := transport.ParseLink(globalDocUrl)
	if err != nil {
		log.Fatalf("Invalid --url: %v", err)
	}
	// An explicit key file wins over a secret embedded in the link, so an
	// operator can keep the secret out of shell history and process lists.
	if *encryptionKeyFile != "" {
		secretBytes, err := os.ReadFile(*encryptionKeyFile)
		if err != nil {
			log.Fatalf("Read encryption key file: %v", err)
		}
		link.Secret = strings.TrimSpace(string(secretBytes))
	}
	// Downstream transports only ever see the clean document URL.
	globalDocUrl = link.URL

	config := transport.DefaultConfig()
	var inner transport.Transport

	switch *transportType {
	case "vyandex":
		inner = yandex.NewYandexVolgaTransport(globalDocUrl, config)
	case "yandex":
		inner = yandex.NewYandexDocsTransport(globalDocUrl, config)
	case "oneme":
		uidint, _ := strconv.ParseInt(maxUid, 10, 64)
		inner = oneme.NewOneMeTransport(*exitNode, maxToken, uidint, config)
	default:
		log.Fatalf("Unknown transport type: %s", *transportType)
	}

	// Wrap encrypts (when the link carries a secret) and then compresses.
	// The KDF context is the parsed document URL, so a ydocs:// link and a
	// plain URL plus --encryption-key-file interoperate for the same doc.
	trans, err := link.Wrap(inner, config, *transportType, *exitNode)
	if err != nil {
		log.Fatalf("Configure encrypted transport: %v", err)
	}
	if link.Encrypted() {
		log.Printf("Transport encryption: AES-256-GCM enabled")
	} else {
		log.Printf("Transport encryption: DISABLED - the document provider sees your traffic in plaintext.")
		log.Printf("  Enable it by giving both peers the same link: --url \"ydocs://%s#YOUR_SHARED_SECRET\"",
			strings.TrimPrefix(strings.TrimPrefix(globalDocUrl, "https://"), "http://"))
	}

	if err := trans.Start(); err != nil {
		log.Fatalf("Failed to start transport: %v", err)
	}

	tun := tunnel.NewTCPTunnel(trans, *exitNode)

	if *exitNode {
		log.Printf("Running as EXIT NODE (needs root for raw socket)")
		if localIP != "" {
			// Scoped: only drop kernel RSTs originating from the tunnel's
			// egress IP, leaving the host's other services (and their
			// closed-port RSTs) untouched.
			log.Printf("! Run: sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s %s -j DROP", localIP)
		} else {
			log.Printf("! Kernel RSTs would tear down tunnel connections. Prefer a scoped rule:")
			log.Printf("!   assign a dedicated alias IP, run with --local-ip <ip>, then:")
			log.Printf("!   sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <ip> -j DROP")
			log.Printf("! Host-wide fallback (drops ALL outbound RST; makes closed ports look filtered):")
			log.Printf("!   sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")
		}
		select {}
	} else {
		log.Printf("Running as CLIENT (SOCKS5 on %s)", *socksAddr)
		socks5Server := socks5.NewSOCKS5Server(*socksAddr, tun)
		log.Fatal(socks5Server.Start())
	}
}
