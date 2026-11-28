#!/usr/bin/env python3
import argparse
import ipaddress
import json
import logging
import os
import random
import select
import socket
import ssl
import struct
import sys
import time
VERSION = "1.2.0"
try:
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted
    HAVE_AIOQUIC = True
except Exception:
    HAVE_AIOQUIC = False
class QuicStepError(RuntimeError):
    pass
class LinkError(QuicStepError):
    pass
class Socks5Relay:
    def __init__(self, host, port, username=None, password=None, timeout=10.0):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        self._tcp = None
        self._udp = None
        self._relay_addr = None
    def open(self):
        try:
            self._tcp = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except OSError as exc:
            raise QuicStepError("Cannot connect to proxy %s:%s (%s)" % (self.host, self.port, exc))
        self._tcp.settimeout(self.timeout)
        try:
            self._negotiate()
            self._associate()
        except Exception:
            self.close()
            raise
        return self
    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self._tcp.recv(n - len(buf))
            if not chunk:
                raise QuicStepError("SOCKS5 control connection closed by proxy")
            buf += chunk
        return buf
    def _negotiate(self):
        methods = b"\x00\x02" if self.username is not None else b"\x00"
        self._tcp.sendall(b"\x05" + bytes([len(methods)]) + methods)
        ver, method = self._recv_exact(2)
        if ver != 5:
            raise QuicStepError("Proxy is not SOCKS5 (version byte = %d)" % ver)
        if method == 0x02:
            if self.username is None:
                raise QuicStepError("Proxy requires username/password; use socks5://user:pass@host:port")
            user = self.username.encode()
            pwd = self.password.encode()
            self._tcp.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(pwd)]) + pwd)
            _ver, status = self._recv_exact(2)
            if status != 0:
                raise QuicStepError("SOCKS5 username/password authentication failed")
        elif method != 0x00:
            raise QuicStepError("Proxy does not accept no-auth/password auth (method = %d)" % method)
    def _associate(self):
        self._tcp.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        ver, rep, _rsv = self._recv_exact(3)
        if ver != 5:
            raise QuicStepError("SOCKS5 UDP ASSOCIATE response abnormal")
        if rep != 0:
            raise QuicStepError(
                "Proxy refused UDP ASSOCIATE (rep=%d, %s): this tunnel most likely does not have UDP enabled, "
                "so QUICstep cannot be used" % (rep, _socks5_reason(rep))
            )
        atyp = self._recv_exact(1)[0]
        if atyp == 1:
            host = socket.inet_ntoa(self._recv_exact(4))
        elif atyp == 4:
            host = str(ipaddress.IPv6Address(self._recv_exact(16)))
        elif atyp == 3:
            host = self._recv_exact(self._recv_exact(1)[0]).decode("ascii", "replace")
        else:
            raise QuicStepError("SOCKS5 UDP ASSOCIATE address type illegal: %d" % atyp)
        port = struct.unpack("!H", self._recv_exact(2))[0]
        if host in ("0.0.0.0", "::", ""):
            host = self._tcp.getpeername()[0]
        self._relay_addr = (host, port)
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        self._udp.setblocking(False)
    def fileno(self):
        return self._udp.fileno()
    def send(self, payload, dst):
        header = b"\x00\x00\x00" + _socks_addr(dst[0], dst[1])
        try:
            self._udp.sendto(header + payload, self._relay_addr)
        except OSError as exc:
            raise LinkError("Failed to send packet through tunnel (%s)" % exc)
    def recv_now(self):
        try:
            pkt, _src = self._udp.recvfrom(65535)
        except BlockingIOError:
            return None
        except OSError:
            return None
        if not pkt:
            return None
        return _parse_socks_udp(pkt)
    def close(self):
        for sock in (self._udp, self._tcp):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        self._udp = self._tcp = None
def _socks5_reason(rep):
    return {
        1: "Proxy internal failure", 2: "Rule not allowed", 3: "Network unreachable", 4: "Host unreachable",
        5: "Connection refused", 6: "TTL expired", 7: "Command not supported",
        8: "Address type not supported",
    }.get(rep, "Unknown reason")
def _socks_addr(host, port):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raw = host.encode("idna")
        return b"\x03" + bytes([len(raw)]) + raw + struct.pack("!H", port)
    if ip.version == 4:
        return b"\x01" + ip.packed + struct.pack("!H", port)
    return b"\x04" + ip.packed + struct.pack("!H", port)
def _parse_socks_udp(pkt):
    if len(pkt) < 4:
        return None
    if pkt[0] != 0 or pkt[1] != 0:
        return None
    if pkt[2] != 0:
        raise LinkError("Proxy fragmented the UDP datagram; this script does not support that")
    atyp = pkt[3]
    off = 4
    try:
        if atyp == 1:
            host = socket.inet_ntoa(pkt[off:off + 4])
            off += 4
        elif atyp == 4:
            host = str(ipaddress.IPv6Address(pkt[off:off + 16]))
            off += 16
        elif atyp == 3:
            length = pkt[off]
            off += 1
            host = pkt[off:off + length].decode("ascii", "replace")
            off += length
        else:
            return None
        port = struct.unpack("!H", pkt[off:off + 2])[0]
    except (IndexError, ValueError, struct.error):
        return None
    return (host, port), pkt[off + 2:]
def _encode_qname(name):
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna")
        if not 0 < len(raw) < 64:
            raise QuicStepError("Invalid domain name: %s" % name)
        out += bytes([len(raw)]) + raw
    return out + b"\x00"
def _skip_dns_name(data, off):
    while True:
        if off >= len(data):
            raise ValueError("DNS name out of bounds")
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            return off + 2
        off += 1 + length
def _parse_dns_a(pkt, qid):
    if len(pkt) < 12:
        return None
    rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", pkt[:12])
    if rid != qid or not flags & 0x8000 or flags & 0x000F:
        return None
    off = 12
    try:
        for _ in range(qd):
            off = _skip_dns_name(pkt, off) + 4
        for _ in range(an):
            off = _skip_dns_name(pkt, off)
            if off + 10 > len(pkt):
                return None
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", pkt[off:off + 10])
            off += 10
            if rtype == 1 and rdlen == 4 and off + 4 <= len(pkt):
                return socket.inet_ntoa(pkt[off:off + 4])
            off += rdlen
    except (ValueError, IndexError, struct.error):
        return None
    return None
def resolve_via_relay(relay, host, resolver, timeout=5.0):
    qid = random.randrange(0, 65536)
    query = (struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
             + _encode_qname(host) + struct.pack("!HH", 1, 1))
    relay.send(query, resolver)
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        wait = min(0.5, max(0.001, end - time.monotonic()))
        ready, _, _ = select.select([relay.fileno()], [], [], wait)
        if not ready:
            continue
        got = relay.recv_now()
        if got is None:
            continue
        _addr, payload = got
        answer = _parse_dns_a(payload, qid)
        if answer:
            return answer
    return None
class TunnelLink:
    is_tunnel = True
    kind = "tunnel"
    def __init__(self, relay, server_addr):
        self.relay = relay
        self.server_addr = server_addr
        self.bytes_tx = 0
        self.bytes_rx = 0
    def fileno(self):
        return self.relay.fileno()
    def send(self, data, dst=None):
        self.relay.send(data, dst or self.server_addr)
        self.bytes_tx += len(data)
    def recv_now(self):
        got = self.relay.recv_now()
        if got is None:
            return None
        _addr, payload = got
        if not payload:
            return None
        self.bytes_rx += len(payload)
        return self.server_addr, payload
    def close(self):
        pass
class DirectLink:
    is_tunnel = False
    kind = "direct"
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 0))
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        self.sock.setblocking(False)
        self.local = self.sock.getsockname()
        self.bytes_tx = 0
        self.bytes_rx = 0
    def fileno(self):
        return self.sock.fileno()
    def send(self, data, dst=None):
        if dst is None:
            raise LinkError("Direct path missing destination address")
        try:
            self.sock.sendto(data, dst)
        except BlockingIOError:
            raise LinkError("Direct socket buffer full")
        except OSError as exc:
            raise LinkError("Direct path send failed (%s)" % exc)
        self.bytes_tx += len(data)
    def recv_now(self):
        try:
            payload, src = self.sock.recvfrom(65535)
        except BlockingIOError:
            return None
        except ConnectionRefusedError:
            raise LinkError(
                "Direct UDP was reset (ICMP port unreachable): target port/path is blocked"
            )
        except OSError as exc:
            raise LinkError("Direct path receive failed (%s)" % exc)
        if not payload:
            return None
        self.bytes_rx += len(payload)
        return src, payload
    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
class Counters:
    def __init__(self):
        self.tunnel_tx = 0
        self.tunnel_rx = 0
        self.direct_tx = 0
        self.direct_rx = 0
        self.direct_pkts = 0
    def add(self, link, incoming, size):
        if link.is_tunnel:
            if incoming:
                self.tunnel_rx += size
            else:
                self.tunnel_tx += size
        else:
            if incoming:
                self.direct_rx += size
                self.direct_pkts += 1
            else:
                self.direct_tx += size
    @property
    def tunnel_total(self):
        return self.tunnel_tx + self.tunnel_rx
    @property
    def total(self):
        return self.tunnel_total + self.direct_tx + self.direct_rx
class Session:
    def __init__(self, quic, h3):
        self.quic = quic
        self.h3 = h3
        self.handshake = None
        self.terminated = None
        self.on_h3_event = None
    def drain_quic(self):
        while True:
            event = self.quic.next_event()
            if event is None:
                return
            if isinstance(event, HandshakeCompleted):
                self.handshake = event
            elif isinstance(event, ConnectionTerminated):
                self.terminated = event
            try:
                h3_events = self.h3.handle_event(event)
            except Exception as exc:
                raise QuicStepError("HTTP/3 layer processing failed: %s" % exc)
            for h3_event in h3_events:
                if self.on_h3_event is not None:
                    self.on_h3_event(h3_event)
def pump(sess, tx, rx_links, counters, timeout, stop=None):
    end = time.monotonic() + timeout
    fds = [link.fileno() for link in rx_links]
    while True:
        if stop is not None and stop():
            return True
        if sess.terminated is not None:
            return False
        now = time.monotonic()
        if now >= end:
            return False
        timer = sess.quic.get_timer()
        if timer is not None and timer <= now:
            sess.quic.handle_timer(now)
        for data, dst in sess.quic.datagrams_to_send(now):
            tx.send(data, dst)
            counters.add(tx, False, len(data))
        wait = min(0.25, end - time.monotonic())
        timer = sess.quic.get_timer()
        if timer is not None:
            wait = min(wait, max(0.001, timer - time.monotonic()))
        if wait <= 0:
            wait = 0.001
        ready, _, _ = select.select(fds, [], [], wait)
        for link in rx_links:
            if link.fileno() not in ready:
                continue
            got = link.recv_now()
            if got is None:
                continue
            src, data = got
            counters.add(link, True, len(data))
            sess.quic.receive_datagram(data, src, time.monotonic())
            sess.drain_quic()
            if sess.terminated is not None:
                return False
def split_url(url):
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise QuicStepError("Only https:// is supported (QUIC is the transport layer of HTTPS)")
    if not parts.hostname:
        raise QuicStepError("URL has no hostname")
    port = parts.port or 443
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return parts.hostname, port, path
def load_ca(conf, cafile):
    if cafile:
        conf.load_verify_locations(cafile)
        return
    try:
        import certifi
        conf.load_verify_locations(certifi.where())
        return
    except Exception:
        pass
    for candidate in (
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
        "/usr/local/etc/openssl/cert.pem",
    ):
        if os.path.exists(candidate):
            conf.load_verify_locations(candidate)
            return
    raise QuicStepError("Cannot find CA certificate: specify --cafile, or add --insecure")
def build_quic(host, insecure=False, cafile=None):
    conf = QuicConfiguration(is_client=True, server_name=host, alpn_protocols=H3_ALPN)
    if insecure:
        conf.verify_mode = ssl.CERT_NONE
    else:
        load_ca(conf, cafile)
    return QuicConnection(configuration=conf)
def http3_get(sess, tx, rx_links, counters, host, path, timeout, stall_timeout=6.0):
    stream_id = sess.quic.get_next_available_stream_id()
    state = {"status": None, "headers": [], "body": bytearray(), "ended": False,
             "first_byte_at": None, "progress_at": time.monotonic()}
    def on_h3(event):
        if isinstance(event, HeadersReceived) and event.stream_id == stream_id:
            state["headers"] = event.headers
            for key, value in event.headers:
                if key == b":status":
                    try:
                        state["status"] = int(value)
                    except ValueError:
                        state["status"] = None
            if event.stream_ended:
                state["ended"] = True
        elif isinstance(event, DataReceived) and event.stream_id == stream_id:
            if state["first_byte_at"] is None:
                state["first_byte_at"] = time.monotonic()
            state["progress_at"] = time.monotonic()
            state["body"].extend(event.data)
            if event.stream_ended:
                state["ended"] = True
    sess.on_h3_event = on_h3
    sess.h3.send_headers(
        stream_id,
        [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", host.encode("idna")),
            (b":path", path.encode("utf-8")),
            (b"user-agent", ("quicstep-py/" + VERSION).encode()),
            (b"accept", b"*/*"),
        ],
        end_stream=True,
    )
    def stop():
        if state["ended"] or sess.terminated is not None:
            return True
        return (state["status"] is not None
                and time.monotonic() - state["progress_at"] > stall_timeout)
    pump(sess, tx, rx_links, counters, timeout, stop=stop)
    sess.on_h3_event = None
    return state
def _stage(label, since, detail):
    print("[%s] %6.0f ms  %s" % (label, (time.monotonic() - since) * 1000, detail))
def run(args):
    if not HAVE_AIOQUIC:
        print("Missing dependency aioquic, please run first: pip install aioquic certifi", file=sys.stderr)
        return 2
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s %(message)s")
        logging.getLogger("aioquic").setLevel(logging.DEBUG)
    host, port, path = split_url(args.url)
    mode = args.mode
    if mode == "step" and not args.proxy:
        print("Hint: no --proxy given, automatically downgrading to --mode direct baseline", file=sys.stderr)
        mode = "direct"
    if mode == "relay" and not args.proxy:
        raise QuicStepError("relay mode requires a tunnel: --proxy socks5://host:port")
    counters = Counters()
    report = {
        "mode": mode, "host": host, "ip": None, "port": port,
        "status": None, "bytes": 0,
        "handshake_ms": None, "migrate_ms": None, "first_byte_ms": None,
        "total_ms": None, "tunnel_bytes": 0, "direct_bytes": 0,
        "alpn": None, "fallback": False, "ended": False,
    }
    t_start = time.monotonic()
    relay = None
    direct = None
    quic = None
    try:
        stage = time.monotonic()
        if args.proxy:
            relay = Socks5Relay(args.proxy_host, args.proxy_port,
                                args.proxy_user, args.proxy_pass).open()
            if args.ip:
                ip = args.ip
            else:
                ip = resolve_via_relay(relay, host, (args.dns, 53))
                if not ip:
                    raise QuicStepError(
                        "In-tunnel DNS resolution of %s failed (resolver %s). "
                        "Try --dns 8.8.8.8, or use --ip to specify the address directly" % (host, args.dns))
        else:
            try:
                ip = args.ip or socket.gethostbyname(host)
            except OSError as exc:
                raise QuicStepError("Local DNS resolution of %s failed: %s" % (host, exc))
        report["ip"] = ip
        server_addr = (ip, port)
        _stage("1/5 Resolve target", stage, "%s -> %s" % (host, ip))
        quic = build_quic(host, insecure=args.insecure, cafile=args.cafile)
        quic.connect(server_addr, time.monotonic())
        h3 = H3Connection(quic)
        sess = Session(quic, h3)
        tunnel_link = TunnelLink(relay, server_addr) if relay is not None else None
        if mode == "direct":
            link = DirectLink()
        else:
            link = tunnel_link
        stage = time.monotonic()
        try:
            ok = pump(sess, link, [link], counters, args.handshake_timeout,
                      stop=lambda: sess.handshake is not None)
        except LinkError as exc:
            raise QuicStepError("Path exception during handshake: %s" % exc)
        if not ok:
            if mode == "direct":
                hint = "Target site does not support HTTP/3, or local UDP/443 is blocked"
            else:
                hint = ("In-tunnel QUIC handshake failed: proxy does not forward UDP / target site does not support HTTP/3 / "
                        "ALPN mismatch")
            raise QuicStepError("Handshake did not complete (%.1fs): %s" % (args.handshake_timeout, hint))
        report["handshake_ms"] = (time.monotonic() - stage) * 1000
        report["alpn"] = sess.handshake.alpn_protocol
        _stage("2/5 QUIC handshake", stage,
               "alpn=%s, via %s" % (sess.handshake.alpn_protocol, link.kind))
        if mode != "direct":
            pump(sess, link, [link], counters, 0.6,
                 stop=lambda: getattr(quic, "_handshake_confirmed", False))
        rx_links = [link]
        if mode == "step":
            stage = time.monotonic()
            direct = DirectLink()
            quic.send_ping(0)
            try:
                moved = pump(sess, direct, [direct, link], counters, args.migrate_timeout,
                             stop=lambda: counters.direct_rx > 0)
            except LinkError as exc:
                moved = False
                print("   !! Direct path exception: %s" % exc, file=sys.stderr)
            if moved:
                moved_at = time.monotonic()
                pump(sess, direct, [direct, link], counters, 0.5,
                     stop=lambda: counters.direct_pkts >= 2)
                report["migrate_ms"] = (moved_at - stage) * 1000
                _stage("3/5 Migrate to direct", stage,
                       "First direct reply %.0f ms, local port %d"
                       % (report["migrate_ms"], direct.local[1]))
                link = direct
                rx_links = [direct]
                if tunnel_link is not None:
                    rx_links.append(tunnel_link)
            else:
                report["fallback"] = True
                print(
                    "   !! Migration failed: no reply on the direct path. Common causes:\n"
                    "      (a) The server set disable_active_migration and does not accept client migration;\n"
                    "      (b) This network blocks direct UDP/443, or the target IP is blocked at IP level;\n"
                    "      (c) An intermediate device dropped the 1-RTT packet without handshake.\n"
                    "      Fallen back to full tunnel mode (equivalent to a normal socks proxy).",
                    file=sys.stderr)
                link = tunnel_link
                rx_links = [tunnel_link]
        else:
            print("   (Baseline mode %s: no migration)" % mode)
        stage = time.monotonic()
        try:
            state = http3_get(sess, link, rx_links, counters, host, path,
                              args.request_timeout, args.stall_timeout)
        except LinkError as exc:
            raise QuicStepError("Path exception while fetching data: %s" % exc)
        if mode == "step" and not report["fallback"] and (
                state["status"] is None or not state["ended"]):
            why = ("No response received" if state["status"] is None
                   else "Transfer interrupted (only received %d B)" % len(state["body"]))
            print("   !! Direct path %s, falling back to full tunnel to retry" % why, file=sys.stderr)
            report["fallback"] = True
            link = tunnel_link
            stage = time.monotonic()
            state = http3_get(sess, link, [link], counters, host, path,
                              args.request_timeout, args.stall_timeout)
        if state["status"] is None:
            raise QuicStepError(
                "No HTTP/3 response received (%.1fs): %s" % (
                    args.request_timeout,
                    "connection closed by peer" if sess.terminated is not None else "timeout"))
        report["status"] = state["status"]
        report["bytes"] = len(state["body"])
        report["ended"] = state["ended"]
        if not state["ended"]:
            print("   !! Note: response incomplete (truncated after %d B)" % len(state["body"]),
                  file=sys.stderr)
        if state["first_byte_at"] is not None:
            report["first_byte_ms"] = (state["first_byte_at"] - stage) * 1000
        _stage("4/5 HTTP/3 GET", stage,
               "status=%s, body=%d B" % (state["status"], len(state["body"])))
        report["total_ms"] = (time.monotonic() - t_start) * 1000
        report["tunnel_bytes"] = counters.tunnel_total
        report["direct_bytes"] = counters.direct_tx + counters.direct_rx
        total = max(1, counters.total)
        share = 100.0 * counters.tunnel_total / total
        report["tunnel_share_pct"] = round(share, 2)
        print("[5/5 Traffic distribution] tunnel %d B (%.1f%%) / direct %d B / total %d B"
              % (counters.tunnel_total, share, report["direct_bytes"], counters.total))
        body = bytes(state["body"])
        if args.output:
            with open(args.output, "wb") as handle:
                handle.write(body)
            print("   body written to %s (%d B)" % (args.output, len(body)))
        elif body and args.preview > 0:
            text = body[:args.preview].decode("utf-8", "replace")
            print("\n--- first %d bytes of body ---\n%s\n---" % (len(text.encode()), text))
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    finally:
        if quic is not None:
            try:
                quic.close()
            except Exception:
                pass
        for obj in (direct, relay):
            if obj is not None:
                try:
                    obj.close()
                except Exception:
                    pass
def build_parser():
    parser = argparse.ArgumentParser(
        description="QUICstep client (application-layer implementation of the PETS 2026 paper principle)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("Example:\n"
                "  python3 quicstep.py https://www.bbc.com/ --proxy socks5://127.0.0.1:1080\n"
                "  python3 quicstep.py https://cloudflare-quic.com/ --mode direct\n"),
    )
    parser.add_argument("url", nargs="?", default="https://cloudflare-quic.com/",
                        help="HTTPS URL to visit (default cloudflare-quic.com)")
    parser.add_argument("--proxy", help="Tunnel: socks5://[user:pass@]host:port (must support UDP ASSOCIATE)")
    parser.add_argument("--mode", choices=["step", "direct", "relay"], default="step",
                        help="step=handshake through tunnel + direct data (default); direct=all-direct baseline; relay=all-tunnel baseline")
    parser.add_argument("--ip", help="Specify target IP directly, skip DNS (emergency when DNS is poisoned)")
    parser.add_argument("--dns", default="1.1.1.1", help="DNS resolver used inside the tunnel (default 1.1.1.1)")
    parser.add_argument("--cafile", help="CA certificate file")
    parser.add_argument("--insecure", action="store_true", help="Skip certificate verification (testing only)")
    parser.add_argument("--handshake-timeout", type=float, default=8.0)
    parser.add_argument("--migrate-timeout", type=float, default=3.0)
    parser.add_argument("--request-timeout", type=float, default=20.0)
    parser.add_argument("--stall-timeout", type=float, default=6.0,
                        help="How long after receiving response headers without new data before judging it stuck and falling back to tunnel (default 6s)")
    parser.add_argument("--output", help="Write response body to file")
    parser.add_argument("--preview", type=int, default=800, help="Number of body bytes to print (default 800)")
    parser.add_argument("--json", action="store_true", help="Output a JSON statistics block at the end")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print aioquic debug logs")
    return parser
def _parse_proxy(args):
    if not args.proxy:
        return
    from urllib.parse import unquote, urlsplit
    raw = args.proxy
    if "://" not in raw:
        raw = "socks5://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("socks5", "socks5h"):
        raise QuicStepError("--proxy currently only supports socks5:// (UDP requires UDP ASSOCIATE)")
    if not parts.hostname:
        raise QuicStepError("--proxy missing hostname")
    args.proxy_host = parts.hostname
    args.proxy_port = parts.port or 1080
    args.proxy_user = unquote(parts.username) if parts.username else None
    args.proxy_pass = unquote(parts.password) if parts.password else None
def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        _parse_proxy(args)
        return run(args)
    except QuicStepError as exc:
        print("Failure: %s" % exc, file=sys.stderr)
        return 1
    except OSError as exc:
        print("Failure (system call): %s" % exc, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
if __name__ == "__main__":
    sys.exit(main())