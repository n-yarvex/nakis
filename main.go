package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

var version = "dev"

const usage = `nakis ` + "(version %s)" + `

usage:
  nakis client -c client.json [-v]     run the local SOCKS5 client
  nakis server -c server.json [-v]     run the tunnel server
  nakis cert   -name HOST [-out DIR]   make a self-signed certificate and print its pin
  nakis ech    -public-name HOST       make an ECH key pair and print both config snippets
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
	case "version", "-version", "--version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
}

func setup(name string, args []string, fallback string) (string, *slog.Logger, *slog.LevelVar, bool, context.Context, context.CancelFunc) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	path := fs.String("c", fallback, "path to json config file")
	verbose := fs.Bool("v", false, "verbose logging")
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
	path, logger, level, forced, ctx, stop := setup("client", args, "/etc/nakis/client.json")
	defer stop()
	cfg, err := LoadClient(path)
	if err != nil {
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
	path, logger, level, forced, ctx, stop := setup("server", args, "/etc/nakis/server.json")
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
	server, _ := json.MarshalIndent([]ECHKey{{Config: kit.Config, Key: kit.PrivateKey, Retry: true}}, "  ", "  ")
	fmt.Printf("server.json:\n  \"ech_keys\": %s\n\nclient.json:\n  \"ech_config\": %q\n", server, kit.ConfigList)
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
