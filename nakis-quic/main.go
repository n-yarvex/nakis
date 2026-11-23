package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var version = "0.1.0"

const usageText = `nakis-quic %s  (=^･ω･^=)

  nakis-quic init -host example.com   write server.json, client.json and a certificate, print a share link
  nakis-quic server -c server.json    run the server
  nakis-quic client -c client.json    run the SOCKS5 client      (or: client -link nakisq://...)
  nakis-quic check  -c file.json      check a config without starting anything   (add -server for server files)
  nakis-quic link   client.json       turn a client config into a link           (or: link -decode nakisq://...)
  nakis-quic cert   -host a.com,1.2.3.4   make a self-signed certificate and print its pin
  nakis-quic ech    public.example    make an ECH key pair
  nakis-quic uuid                     make a uuid
  nakis-quic version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usageText, version)
		os.Exit(2)
	}
	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	case "server":
		err = runServer(args)
	case "client":
		err = runClient(args)
	case "init":
		err = runInit(args)
	case "check":
		err = runCheck(args)
	case "link":
		err = runLink(args)
	case "cert":
		err = runCert(args)
	case "ech":
		err = runECH(args)
	case "uuid":
		fmt.Println(newUUID())
	case "version", "-v", "--version":
		fmt.Println("nakis-quic", version)
	case "help", "-h", "--help":
		fmt.Printf(usageText, version)
	default:
		fmt.Fprintf(os.Stderr, "nyan? I don't know %q\n\n", os.Args[1])
		fmt.Fprintf(os.Stderr, usageText, version)
		os.Exit(2)
	}
	if err != nil {
		var p *Problem
		if errors.As(err, &p) {
			fmt.Fprintln(os.Stderr, "喵呜… "+p.Error())
		} else {
			fmt.Fprintln(os.Stderr, "喵呜… "+err.Error())
		}
		os.Exit(1)
	}
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return formatUUID(b[:])
}

func newLogger(level string, asJSON bool) *slog.Logger {
	lv, _ := ParseLevel(level)
	opts := &slog.HandlerOptions{Level: lv}
	if asJSON {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	opts.ReplaceAttr = func(_ []string, a slog.Attr) slog.Attr {
		switch a.Key {
		case slog.TimeKey:
			a.Value = slog.StringValue(a.Value.Time().Format("15:04:05"))
		case slog.LevelKey:
			switch a.Value.Any().(slog.Level) {
			case slog.LevelDebug:
				a.Value = slog.StringValue("dbg")
			case slog.LevelInfo:
				a.Value = slog.StringValue("meow")
			case slog.LevelWarn:
				a.Value = slog.StringValue("hiss")
			default:
				a.Value = slog.StringValue("yowl")
			}
		}
		return a
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

func banner() {
	if st, err := os.Stderr.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprintf(os.Stderr, "(=^･ω･^=) nakis-quic %s\n", version)
	}
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
		<-ch
		fmt.Fprintln(os.Stderr, "ok ok, leaving right now")
		os.Exit(130)
	}()
	return ctx, cancel
}

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	path := fs.String("c", "server.json", "config file")
	asJSON := fs.Bool("json", false, "log as json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := LoadServer(*path)
	if err != nil {
		return err
	}
	logger := newLogger(cfg.LogLevel, *asJSON)
	banner()
	lair, err := NewLair(cfg, logger)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	err = lair.ListenAndServe(ctx)
	logger.Info("bye bye~")
	return err
}

func runClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	path := fs.String("c", "", "config file")
	link := fs.String("link", "", "a nakisq:// link instead of a config file")
	listen := fs.String("listen", "", "override the SOCKS5 listen address")
	asJSON := fs.Bool("json", false, "log as json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var cfg ClientConfig
	var err error
	switch {
	case *link != "":
		var n Node
		if n, err = ParseLink(*link); err != nil {
			return err
		}
		cfg = n.Config
	case *path != "":
		cfg, err = LoadClient(*path)
	default:
		cfg, err = LoadClient("client.json")
	}
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Listen = fixListen(*listen)
	}
	logger := newLogger(cfg.LogLevel, *asJSON)
	banner()
	k, err := NewKitten(cfg, logger)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	k.Start()
	err = k.ServeSOCKS5(ctx, cfg.Listen)
	k.Shutdown(15 * time.Second)
	logger.Info("bye bye~")
	return err
}

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	path := fs.String("c", "", "config file")
	server := fs.Bool("server", false, "the file is a server config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return problem("F01", "which file? use -c file.json", "")
	}
	if *server {
		c, err := LoadServer(*path)
		if err != nil {
			return err
		}
		if _, err := NewLair(c, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
			return err
		}
		fmt.Printf("%s looks good, nya~  (listens on udp %s)\n", *path, c.Listen)
		return nil
	}
	c, err := LoadClient(*path)
	if err != nil {
		return err
	}
	k, err := NewKitten(c, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return err
	}
	k.cancel()
	fmt.Printf("%s looks good, nya~  (server %s, socks5 on %s)\n", *path, c.Server, c.Listen)
	return nil
}

func runLink(args []string) error {
	fs := flag.NewFlagSet("link", flag.ContinueOnError)
	decode := fs.String("decode", "", "decode a link into a client config")
	name := fs.String("name", "", "name to put after the #")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *decode != "" {
		n, err := ParseLink(*decode)
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(n.Config, "", "  ")
		fmt.Println(string(out))
		return nil
	}
	if fs.NArg() != 1 {
		return errors.New("usage: nakis-quic link client.json   or   nakis-quic link -decode nakisq://...")
	}
	c, err := LoadClient(fs.Arg(0))
	if err != nil {
		return err
	}
	l, err := FormatLink(c, *name)
	if err != nil {
		return err
	}
	fmt.Println(l)
	return nil
}

func runCert(args []string) error {
	fs := flag.NewFlagSet("cert", flag.ContinueOnError)
	hosts := fs.String("host", "", "comma separated names / ips")
	dir := fs.String("dir", ".", "where to write cert.pem and key.pem")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *hosts == "" {
		return errors.New("-host is needed, for example -host example.com,203.0.113.5")
	}
	pin, err := writeCert(*dir, strings.Split(*hosts, ",")...)
	if err != nil {
		return err
	}
	fmt.Println("wrote", filepath.Join(*dir, "cert.pem"), "and", filepath.Join(*dir, "key.pem"))
	fmt.Println("pin:", pin)
	return nil
}

func writeCert(dir string, names ...string) (string, error) {
	c, k, pin, err := newCert(names...)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), c, 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), k, 0o600); err != nil {
		return "", err
	}
	return pin, nil
}

func runECH(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: nakis-quic ech public.example   (the name an observer will see)")
	}
	kit, err := newECH(args[0], 1)
	if err != nil {
		return err
	}
	fmt.Printf("client json:  \"ech_config\": %q\n", kit.list)
	fmt.Printf("server json:  \"ech_keys\": [{\"config\": %q, \"key\": %q, \"retry\": true}]\n", kit.config, kit.key)
	return nil
}

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	host := fs.String("host", "", "the name or ip clients will connect to")
	port := fs.Int("port", 443, "udp port")
	dir := fs.String("dir", ".", "where to write the files")
	echName := fs.String("ech", "", "public name for ECH (leave empty to skip ECH)")
	quietOut := fs.Bool("q", false, "print only the share link")
	force := fs.Bool("force", false, "overwrite existing files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *host == "" {
		return errors.New("-host is needed, for example: nakis-quic init -host example.com")
	}
	h, err := normHost(*host)
	if err != nil {
		return err
	}
	if *port < 1 || *port > 65535 {
		return errors.New("-port must be 1-65535")
	}
	if *echName != "" && net.ParseIP(h) != nil {
		return errors.New("-ech needs a real domain name for -host (ECH can't hide an ip address)")
	}
	for _, f := range []string{"server.json", "client.json", "cert.pem", "key.pem"} {
		if _, err := os.Stat(filepath.Join(*dir, f)); err == nil && !*force {
			return fmt.Errorf("%s already exists here; pick another -dir or add -force", f)
		}
	}
	pin, err := writeCert(*dir, h)
	if err != nil {
		return err
	}
	id := newUUID()
	srv := DefaultServer()
	srv.Listen = "0.0.0.0:" + strconv.Itoa(*port)
	srv.UUID = id
	srv.TLSCert = filepath.Join(*dir, "cert.pem")
	srv.TLSKey = filepath.Join(*dir, "key.pem")
	cli := DefaultClient()
	cli.Server = fmt.Sprintf("%s:%d", h, *port)
	cli.UUID = id
	cli.TLSPins = []string{pin}
	if *echName != "" {
		kit, err := newECH(*echName, 1)
		if err != nil {
			return err
		}
		srv.ECHKeys = []ECHKey{{Config: kit.config, Key: kit.key, Retry: true}}
		cli.ECHConfig = kit.list
		cli.SNI = h
	}
	write := func(name string, v any) error {
		raw, _ := json.MarshalIndent(v, "", "  ")
		return os.WriteFile(filepath.Join(*dir, name), append(raw, '\n'), 0o600)
	}
	if err := write("server.json", srv); err != nil {
		return err
	}
	if err := write("client.json", cli); err != nil {
		return err
	}
	link, err := FormatLink(cli, h)
	if err != nil {
		return err
	}
	if *quietOut {
		fmt.Println(link)
		return nil
	}
	fmt.Println("all written to", *dir, "(server.json, client.json, cert.pem, key.pem)")
	fmt.Println("put server.json, cert.pem and key.pem on the server, then: nakis-quic server -c server.json")
	fmt.Println("on your side:  nakis-quic client -c client.json   (socks5 on 127.0.0.1:1080)")
	fmt.Println("or share this link:")
	fmt.Println(link)
	return nil
}
