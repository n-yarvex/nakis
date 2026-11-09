package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var version = "dev"

const usage = `nakis ` + "(version %s)" + `

usage:
  nakis client -c client.json [-v]     run the local SOCKS5 client
  nakis client -l LINK [-listen ADDR]  run the client straight from a nakis:// link
  nakis server -c server.json [-v]     run the tunnel server
  nakis cert   -name HOST [-out DIR]   make a self-signed certificate and print its pin
  nakis ech    -public-name HOST [-out DIR]  make an ECH key pair and print both config snippets (or write them to DIR)
  nakis link   -c client.json [-name N]            turn a client config into a nakis:// link
  nakis link   -s server.json -host H [-nopin] [-name N] make the share link for a server config
  nakis link   -d LINK                             decode a link into client.json
  nakis sub    FILE|URL [-n INDEX]                 list the nodes of a subscription, or print one as client.json
  nakis version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "client":
		runClient(os.Args[2:])
	case "server":
		runServer(os.Args[2:])
	case "cert":
		runCert(os.Args[2:])
	case "ech":
		runECH(os.Args[2:])
	case "link":
		runLink(os.Args[2:])
	case "sub":
		runSub(os.Args[2:])
	case "version", "-version", "--version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
}

func setup(name string, args []string, fallback string, extra func(*flag.FlagSet)) (string, *slog.Logger, *slog.LevelVar, bool, context.Context, context.CancelFunc) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	path := fs.String("c", fallback, "path to json config file")
	verbose := fs.Bool("v", false, "verbose logging")
	if extra != nil {
		extra(fs)
	}
	_ = fs.Parse(args)

	level := new(slog.LevelVar)
	if *verbose {
		level.Set(slog.LevelDebug)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	return *path, logger, level, *verbose, ctx, stop
}

func die(logger *slog.Logger, msg string, err error) {
	logger.Error(msg, "err", err)
	os.Exit(1)
}

func runClient(args []string) {
	var link, listen *string
	path, logger, level, forced, ctx, stop := setup("client", args, "/etc/nakis/client.json", func(fs *flag.FlagSet) {
		link = fs.String("l", "", "nakis:// link to use instead of a config file")
		listen = fs.String("listen", "", "listen address when using -l")
	})
	defer stop()
	var cfg ClientConfig
	var err error
	if *link != "" {
		var node Node
		if node, err = ParseLink(*link); err != nil {
			die(logger, "read link", err)
		}
		cfg = node.Config
		if *listen != "" {
			cfg.Listen = FixListen(*listen)
		}
	} else if cfg, err = LoadClient(path); err != nil {
		die(logger, "load client config", err)
	}
	applyLevel(level, forced, cfg.LogLevel)
	k, err := NewKitten(cfg, logger)
	if err != nil {
		die(logger, "init client", err)
	}
	k.Start()
	if err := k.ServeSOCKS5(ctx, cfg.Listen); err != nil {
		logger.Error("client stopped because of an error", "err", err)
	}
	k.Shutdown(5 * time.Second)
	logger.Info("client stopped, bye")
}

func runServer(args []string) {
	path, logger, level, forced, ctx, stop := setup("server", args, "/etc/nakis/server.json", nil)
	defer stop()
	cfg, err := LoadServer(path)
	if err != nil {
		die(logger, "load server config", err)
	}
	applyLevel(level, forced, cfg.LogLevel)
	l, err := NewLair(cfg, logger)
	if err != nil {
		die(logger, "init server", err)
	}
	if err := l.ListenAndServe(ctx); err != nil {
		logger.Error("server stopped because of an error", "err", err)
	}
	logger.Info("server stopped, bye")
}

func runCert(args []string) {
	fs := flag.NewFlagSet("cert", flag.ExitOnError)
	name := fs.String("name", "", "host name or IP the client will connect to (comma separated for several)")
	out := fs.String("out", ".", "directory for cert.pem and key.pem")
	_ = fs.Parse(args)
	if *name == "" {
		fmt.Fprintln(os.Stderr, "cert: -name is required")
		os.Exit(2)
	}
	certPEM, keyPEM, pin, err := NewCert(splitNames(*name)...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cert:", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "cert:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(*out, "cert.pem"), certPEM, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "cert:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(*out, "key.pem"), keyPEM, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "cert:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s and %s\n\nserver.json:\n  \"tls_cert\": %q,\n  \"tls_key\": %q\n\nclient.json:\n  \"tls_pins\": [%q]\n",
		filepath.Join(*out, "cert.pem"), filepath.Join(*out, "key.pem"),
		filepath.Join(*out, "cert.pem"), filepath.Join(*out, "key.pem"), pin)
}

func runECH(args []string) {
	fs := flag.NewFlagSet("ech", flag.ExitOnError)
	public := fs.String("public-name", "", "outer SNI that on-path observers will see")
	id := fs.Int("id", 1, "ECH config id (0-255)")
	out := fs.String("out", "", "write ech_keys.json and ech_config.txt into this directory instead of printing")
	_ = fs.Parse(args)
	if *public == "" {
		fmt.Fprintln(os.Stderr, "ech: -public-name is required")
		os.Exit(2)
	}
	kit, err := NewECH(*public, byte(*id))
	if err != nil {
		fmt.Fprintln(os.Stderr, "ech:", err)
		os.Exit(1)
	}
	if *out != "" {
		keys, _ := json.Marshal([]ECHKey{{Config: kit.Config, Key: kit.PrivateKey, Retry: true}})
		if err := os.MkdirAll(*out, 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "ech:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(filepath.Join(*out, "ech_keys.json"), keys, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "ech:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(filepath.Join(*out, "ech_config.txt"), []byte(kit.ConfigList+"\n"), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "ech:", err)
			os.Exit(1)
		}
		return
	}
	server, _ := json.MarshalIndent([]ECHKey{{Config: kit.Config, Key: kit.PrivateKey, Retry: true}}, "  ", "  ")
	fmt.Printf("server.json:\n  \"ech_keys\": %s\n\nclient.json:\n  \"ech_config\": %q\n", server, kit.ConfigList)
}

func runLink(args []string) {
	fs := flag.NewFlagSet("link", flag.ExitOnError)
	cpath := fs.String("c", "", "client.json to encode")
	spath := fs.String("s", "", "server.json to make a share link from")
	host := fs.String("host", "", "address clients should connect to (with -s)")
	sni := fs.String("sni", "", "server name for TLS (with -s; default: host when it is a name)")
	nopin := fs.Bool("nopin", false, "leave the certificate pin out (for CA-signed certificates that get renewed)")
	port := fs.Int("port", 0, "public port when it differs from the listen port (with -s)")
	name := fs.String("name", "", "node name shown in the client")
	dec := fs.String("d", "", "link to decode")
	_ = fs.Parse(args)
	fail := func(err error) {
		fmt.Fprintln(os.Stderr, "link:", err)
		os.Exit(1)
	}
	switch {
	case *dec != "":
		node, err := ParseLink(*dec)
		if err != nil {
			fail(err)
		}
		printClientJSON(node)
	case *spath != "":
		if *host == "" {
			fail(errors.New("-host is required with -s"))
		}
		sc, err := LoadServer(*spath)
		if err != nil {
			fail(err)
		}
		serverName := *sni
		if serverName == "" && net.ParseIP(*host) == nil {
			serverName = *host
		}
		cc, err := LinkFromServer(sc, *host, serverName, *port)
		if err != nil {
			fail(err)
		}
		if *nopin {
			cc.TLSPins = nil
			if err := cc.Tidy(); err != nil {
				fail(err)
			}
		}
		out, err := FormatLink(cc, *name)
		if err != nil {
			fail(err)
		}
		fmt.Println(out)
	case *cpath != "":
		cc, err := LoadClient(*cpath)
		if err != nil {
			fail(err)
		}
		out, err := FormatLink(cc, *name)
		if err != nil {
			fail(err)
		}
		fmt.Println(out)
	default:
		fail(errors.New("give one of -c, -s or -d"))
	}
}

func printClientJSON(n Node) {
	out, _ := json.MarshalIndent(n.Config, "", "  ")
	fmt.Println(string(out))
}

func runSub(args []string) {
	fs := flag.NewFlagSet("sub", flag.ExitOnError)
	index := fs.Int("n", 0, "print node number N (1-based) as client.json")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "sub: give a file path or an http(s) URL")
		os.Exit(2)
	}
	src := fs.Arg(0)
	var body []byte
	var err error
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		hc := http.Client{Timeout: 20 * time.Second}
		var resp *http.Response
		if resp, err = hc.Get(src); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				err = fmt.Errorf("server answered %s", resp.Status)
			} else {
				body, err = io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			}
		}
	} else {
		body, err = os.ReadFile(src)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sub:", err)
		os.Exit(1)
	}
	nodes, errs := ParseSubscription(body)
	for _, e := range errs {
		fmt.Fprintln(os.Stderr, "sub: skipped:", e)
	}
	if len(nodes) == 0 {
		fmt.Fprintln(os.Stderr, "sub: no usable nodes")
		os.Exit(1)
	}
	if *index > 0 {
		if *index > len(nodes) {
			fmt.Fprintf(os.Stderr, "sub: only %d nodes\n", len(nodes))
			os.Exit(1)
		}
		printClientJSON(nodes[*index-1])
		return
	}
	for i, n := range nodes {
		fmt.Printf("%d\t%s\t%s\n", i+1, n.Name, n.Config.Server)
	}
}

func splitNames(s string) []string {
	var out []string
	cur := ""
	for _, r := range s + "," {
		if r == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	return out
}

func applyLevel(lv *slog.LevelVar, forced bool, name string) {
	if forced {
		return
	}
	if l, err := ParseLevel(name); err == nil {
		lv.Set(l)
	}
}
