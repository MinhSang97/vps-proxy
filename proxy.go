// Forward proxy on ONE port, serving both HTTP/HTTPS (CONNECT) and SOCKS5,
// told apart by the first byte (0x05 = SOCKS5). Basic/userpass auth.
// Config from .env next to the binary.
//
//	go build -o proxy proxy.go && ./proxy
package main

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"vps-proxy/internal/nro"
)

func main() {
	loadConfig(".env")
	cred := os.Getenv("PROXY_AUTH")
	if cred == "" {
		log.Fatal("PROXY_AUTH=user:pass is missing from .env")
	}
	addr := envOr("HTTP_ADDR", ":8080")

	out := []io.Writer{os.Stdout}
	if path := os.Getenv("LOG_FILE"); path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
		if err != nil {
			log.Fatalf("cannot open LOG_FILE %s: %v", path, err)
		}
		// ponytail: no rotation here, point logrotate with copytruncate at the file
		out = append(out, f)
	}
	if mongoLog != nil {
		out = append(out, mongoLog)
		// Ctrl+C must drain the queue, otherwise the last seconds of a session
		// are lost exactly when they matter most.
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-stop
			log.Print("shutting down, flushing the capture to mongo")
			mongoLog.close()
			os.Exit(0)
		}()
	}
	log.SetOutput(io.MultiWriter(out...))
	if mongoNote != "" {
		log.Print(mongoNote)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	// fmt, not log: the credentials line stays on the terminal, out of the log file
	fmt.Println("proxy ", proxyLine(addr, cred, publicIP()), "(HTTP + SOCKS5 same port)")
	log.Printf("proxy listening on %s", addr)

	srv := &http.Server{Handler: newHandler(cred)}
	// No Read/WriteTimeout on purpose: CONNECT tunnels are long-lived.
	log.Fatal(srv.Serve(&sniffListener{Listener: ln, cred: cred}))
}

// ---------- one port, two protocols ----------

// sniffListener peeks the first byte of each connection. SOCKS5 (0x05) is
// handled here; everything else is handed to the HTTP server. Every accepted
// connection is logged, so an empty log proves no client reached the proxy.
type sniffListener struct {
	net.Listener
	cred string
}

func (l *sniffListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		br := bufio.NewReader(c)
		b, err := br.Peek(1)
		if err != nil {
			log.Printf("conn   %s: opened then closed, nothing sent", c.RemoteAddr())
			c.Close()
			continue
		}
		pc := &prefixConn{Conn: c, r: br}
		if b[0] == 0x05 {
			log.Printf("conn   %s -> SOCKS5", c.RemoteAddr())
			go func() {
				defer c.Close()
				if err := socksConn(pc, br, l.cred); err != nil &&
					!errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
					log.Printf("socks5 %s: %v", c.RemoteAddr(), err)
				}
			}()
			continue
		}
		log.Printf("conn   %s -> HTTP (first byte 0x%02x)", c.RemoteAddr(), b[0])
		return pc, nil
	}
}

// prefixConn lets the peeked byte be read again by whoever consumes the conn.
type prefixConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// ---------- HTTP / HTTPS ----------

// In a forward proxy r.URL is already absolute, so the director has nothing to do.
// ReverseProxy also strips hop-by-hop headers, Proxy-Authorization included.
var fwd = &httputil.ReverseProxy{Director: func(*http.Request) {}}

func newHandler(cred string) http.Handler {
	want := []byte("Basic " + base64.StdEncoding.EncodeToString([]byte(cred)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Proxy-Authorization"))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			log.Printf("http   %s: bad credentials", r.RemoteAddr)
			w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
			http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
			return
		}
		log.Printf("http   %s -> %s %s", r.RemoteAddr, r.Method, r.Host)
		if r.Method == http.MethodConnect {
			httpTunnel(w, r)
			return
		}
		fwd.ServeHTTP(w, r)
	})
}

func httpTunnel(w http.ResponseWriter, r *http.Request) {
	dst, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		// The game server refused us from this host/IP. This is the line to watch.
		log.Printf("http   %s: DIAL FAILED to %s: %v", r.RemoteAddr, r.Host, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer dst.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	src, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer src.Close()

	if _, err := src.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}
	// brw, not src: the client may already have pipelined bytes into the buffer.
	// Count bytes each way: up==0 or down==0 means the game server never really talked.
	up, down := pipe(dst, brw, src, r.Host)
	log.Printf("http   %s: %s closed up=%dB down=%dB", r.RemoteAddr, r.Host, up, down)
}

// pipe copies both directions and returns bytes client->server (up) and
// server->client (down). down==0 after a connect is the telltale of a server
// that accepts the TCP handshake but drops the session (e.g. datacenter-IP block).
// With DUMP_DIR set, every byte each way is hex-dumped to a file as well.
func pipe(dst net.Conn, clientSide io.Reader, client net.Conn, target string) (up, down int64) {
	toServer, toClient := io.Writer(dst), io.Writer(client)
	if d, closeDump := newDump("tcp", target); d != nil {
		defer closeDump()
		// Dump first, forward second: a byte is recorded before the peer sees it.
		toServer = io.MultiWriter(&dumpSide{d, "C>S"}, dst)
		toClient = io.MultiWriter(&dumpSide{d, "S>C"}, client)
	}
	done := make(chan struct{})
	go func() {
		up, _ = io.Copy(toServer, clientSide)
		dst.(interface{ CloseWrite() error }).CloseWrite()
		close(done)
	}()
	down, _ = io.Copy(toClient, dst)
	<-done
	return
}

// ---------- packet dump ----------

// dumpDir decides where captured bytes go: empty captures nothing (the
// default), "-" writes the hex into the main log beside the connection lines,
// "mongo" stores them as rows, anything else is a directory taking one file
// per tunnel.
// Set by loadConfig, never here: a package-level initialiser runs before main,
// which is before .env has been read.
var dumpDir string

// mongoLog is the open database sink, nil when MONGO_URI is unset.
var mongoLog *mongoSink

// nroLong is the client-version flag for live NRO decoding (2.4.2+). The bundled
// client is 2.4.7, so it defaults on; NRO_LONG=0 turns it off.
var nroLong = true

// mongoNote carries what went wrong reaching the database. It is held rather
// than printed because the config is read before the log knows where to write,
// and a warning about a degraded capture belongs in the log file.
var mongoNote string

// dumpFile is the capture of one tunnel. Both directions share it and its
// mutex, so the hex reads in the order the bytes actually crossed.
type dumpFile struct {
	mu    sync.Mutex
	f     *os.File   // nil writes into the main log instead
	sink  *mongoSink // when set, records become rows and f is unused
	conn  *nro.Conn  // live NRO decoder, set only for TCP tunnels going to mongo
	proto string     // tcp or udp
	peer  string     // the host this tunnel was opened for
}

// write records one chunk. Every record is one line naming protocol, peer and
// direction, then the hex block, so one parser reads the log and the files
// alike: "<time> dump <proto> <peer> <dir> <n> bytes".
func (d *dumpFile) write(peer, dir string, b []byte) {
	if d.sink != nil {
		// No lock on the raw row: put is safe from both directions at once and
		// its sequence keeps them in order.
		d.sink.put(logRecord{Kind: "packet", Proto: d.proto, Peer: peer, Dir: dir,
			N: len(b), Data: append([]byte(nil), b...)})
		d.decode(peer, dir, b)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.f == nil {
		log.Printf("dump %s %s %s %d bytes\n%s", d.proto, peer, dir, len(b), hex.Dump(b))
		return
	}
	fmt.Fprintf(d.f, "%s dump %s %s %s %d bytes\n%s\n",
		time.Now().Format("15:04:05.000"), d.proto, peer, dir, len(b), hex.Dump(b))
}

// decode feeds the bytes to the live NRO decoder and stores one row per whole
// message. It runs off the raw capture, so a decoder fault can never cost the
// tunnel its bytes; recover keeps a bad message from taking the proxy down.
// Conn.Feed mutates shared state, so it holds the per-tunnel lock, but the lock
// is dropped before the rows are queued.
func (d *dumpFile) decode(peer, dir string, b []byte) {
	if d.conn == nil {
		return
	}
	var msgs []nro.Message
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("nro    %s: decoder panic, giving up on this tunnel: %v", peer, r)
				d.conn = nil
			}
		}()
		d.mu.Lock()
		defer d.mu.Unlock()
		msgs = d.conn.Feed(dir == "C>S", b)
	}()
	for _, m := range msgs {
		cmd := m.Cmd
		// Store the decrypted payload as a readable hexdump, not raw bytes: a
		// binary field shows up as useless Base64 in a database browser, while a
		// hexdump shows the ASCII column so logins and chat are readable on sight.
		d.sink.put(logRecord{Kind: "message", Proto: d.proto, Peer: peer, Dir: m.Dir,
			Cmd: &cmd, Name: m.Name(), N: len(m.Data), Dump: hex.Dump(m.Data), Text: nro.Text(m.Data)})
	}
}

// dumpSide adapts one direction of a stream to io.Writer. UDP skips it and
// calls write directly, because every datagram names its own peer.
type dumpSide struct {
	d   *dumpFile
	dir string
}

func (s *dumpSide) Write(b []byte) (int, error) {
	s.d.write(s.d.peer, s.dir, b)
	return len(b), nil
}

// newDump opens the capture for one tunnel. Returns nil when DUMP_DIR is unset
// or unusable, which the caller reads as "do not capture".
func newDump(proto, peer string) (*dumpFile, func()) {
	switch dumpDir {
	case "":
		return nil, func() {}
	case "-":
		return &dumpFile{proto: proto, peer: peer}, func() {}
	case "mongo":
		if mongoLog == nil {
			return nil, func() {}
		}
		d := &dumpFile{sink: mongoLog, proto: proto, peer: peer}
		if proto == "tcp" {
			d.conn = nro.NewConn(nroLong) // decode game messages alongside the raw bytes
		}
		return d, func() {}
	}
	if err := os.MkdirAll(dumpDir, 0o750); err != nil {
		log.Printf("dump   %s: %v", peer, err)
		return nil, func() {}
	}
	name := fmt.Sprintf("%s/%s_%s_%s.dump", dumpDir,
		time.Now().Format("20060102-150405.000"), proto,
		strings.NewReplacer(":", "-", "/", "-").Replace(peer))
	f, err := os.Create(name)
	if err != nil {
		log.Printf("dump   %s: %v", peer, err)
		return nil, func() {}
	}
	log.Printf("dump   %s -> %s", peer, name)
	return &dumpFile{f: f, proto: proto, peer: peer}, func() { f.Close() }
}

// ---------- SOCKS5 (CONNECT only, RFC 1928 + RFC 1929) ----------

func socksConn(c net.Conn, br *bufio.Reader, cred string) error {
	c.SetDeadline(time.Now().Add(30 * time.Second)) // handshake only, cleared before the tunnel

	// Greeting: VER NMETHODS METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return err
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return err
	}
	if bytes.IndexByte(methods, 2) < 0 {
		c.Write([]byte{5, 0xff})
		return errors.New("client refuses username/password auth")
	}
	if _, err := c.Write([]byte{5, 2}); err != nil {
		return err
	}

	// Auth: VER ULEN USER PLEN PASS
	ver, err := br.ReadByte()
	if err != nil {
		return err
	}
	if ver != 1 {
		return errors.New("bad auth version")
	}
	user, err := readPrefixed(br)
	if err != nil {
		return err
	}
	pass, err := readPrefixed(br)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(user+":"+pass), []byte(cred)) != 1 {
		c.Write([]byte{1, 1})
		log.Printf("socks5 %s: bad credentials", c.RemoteAddr())
		return nil
	}
	if _, err := c.Write([]byte{1, 0}); err != nil {
		return err
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return err
	}
	var host string
	switch req[3] {
	case 1, 4:
		ip := make([]byte, map[byte]int{1: 4, 4: 16}[req[3]])
		if _, err := io.ReadFull(br, ip); err != nil {
			return err
		}
		host = net.IP(ip).String()
	case 3:
		if host, err = readPrefixed(br); err != nil {
			return err
		}
	default:
		c.Write(socksReply(8)) // address type not supported
		return errors.New("bad address type")
	}
	var port uint16
	if err := binary.Read(br, binary.BigEndian, &port); err != nil {
		return err
	}

	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	if req[1] == 3 { // UDP ASSOCIATE
		return socksUDP(c, br, target)
	}
	if req[1] != 1 { // BIND and anything else
		c.Write(socksReply(7)) // command not supported
		return errors.New("unsupported command " + strconv.Itoa(int(req[1])))
	}

	dst, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		c.Write(socksReply(5)) // connection refused
		return err
	}
	defer dst.Close()
	if _, err := c.Write(socksReply(0)); err != nil {
		return err
	}
	log.Printf("socks5 %s -> %s", c.RemoteAddr(), target)

	c.SetDeadline(time.Time{}) // tunnels are long-lived
	// br, not c: the client may have pipelined bytes already
	up, down := pipe(dst, br, c, target)
	log.Printf("socks5 %s: %s closed up=%dB down=%dB", c.RemoteAddr(), target, up, down)
	return nil
}

// socksReply answers with BND.ADDR 0.0.0.0:0, which every client ignores for CONNECT.
func socksReply(code byte) []byte { return []byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0} }

// ---------- SOCKS5 UDP ASSOCIATE (RFC 1928 section 7) ----------

// socksUDP opens a UDP relay and serves it for as long as the TCP control
// connection lives. target is the address the client claims it will send from,
// which clients usually leave as 0.0.0.0:0, so it is logged and not trusted.
func socksUDP(c net.Conn, br *bufio.Reader, target string) error {
	c.SetDeadline(time.Time{}) // an association is long-lived, like a tunnel

	// Wildcard bind: datagrams may arrive on a different interface than the
	// control connection. The address handed back is the one the client has
	// already proved it can reach.
	// ponytail: behind NAT that address is private. Clients that ignore BND.ADDR
	// and reuse the control-connection IP still work; give the public IP if not.
	pc, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		c.Write(socksReply(1)) // general failure
		return err
	}
	defer pc.Close()

	bound := &net.UDPAddr{
		IP:   c.LocalAddr().(*net.TCPAddr).IP,
		Port: pc.LocalAddr().(*net.UDPAddr).Port,
	}
	if _, err := c.Write(socksUDPReply(bound)); err != nil {
		return err
	}
	log.Printf("socks5 %s -> UDP relay on %s (client announced %s)", c.RemoteAddr(), bound, target)

	// The control connection is the association's lifetime: when it drops, stop.
	go func() {
		io.Copy(io.Discard, br)
		pc.Close()
	}()

	d, closeDump := newDump("udp", c.RemoteAddr().String())
	if d != nil {
		defer closeDump()
	}
	n := relayUDP(pc, c.RemoteAddr().(*net.TCPAddr).IP, d)
	log.Printf("socks5 %s: UDP relay closed, %d datagrams", c.RemoteAddr(), n)
	return nil
}

// relayUDP shuttles datagrams until the socket closes and returns how many it
// moved. One socket serves both directions: whatever comes from the client's
// address goes out to the host its header names, everything else is a reply
// coming back and is wrapped up for the client.
func relayUDP(pc *net.UDPConn, clientIP net.IP, d *dumpFile) (count int) {
	var client *net.UDPAddr // learned from the first datagram: clients announce 0.0.0.0:0
	buf := make([]byte, 64*1024)
	for {
		n, from, err := pc.ReadFromUDP(buf)
		if err != nil {
			return count
		}
		if client == nil {
			if !from.IP.Equal(clientIP) {
				continue // only the host holding the control connection may open it
			}
			client = from
		}
		count++
		if from.Port == client.Port && from.IP.Equal(client.IP) {
			dst, payload, err := parseUDPHeader(buf[:n])
			if err != nil {
				log.Printf("socks5 %s: dropped datagram: %v", from, err)
				continue
			}
			if d != nil {
				d.write(dst.String(), "C>S", payload)
			}
			pc.WriteToUDP(payload, dst)
			continue
		}
		if d != nil {
			d.write(from.String(), "S>C", buf[:n])
		}
		pc.WriteToUDP(append(udpHeader(from), buf[:n]...), client)
	}
}

// parseUDPHeader splits a client datagram into its destination and payload.
// Header layout: RSV RSV FRAG ATYP ADDR PORT.
func parseUDPHeader(b []byte) (*net.UDPAddr, []byte, error) {
	if len(b) < 10 {
		return nil, nil, errors.New("datagram too short")
	}
	if b[2] != 0 {
		return nil, nil, errors.New("fragmented datagram") // RFC 1928: reassembly is optional
	}
	var host string
	var rest []byte
	switch b[3] {
	case 1:
		host, rest = net.IP(b[4:8]).String(), b[8:]
	case 4:
		if len(b) < 22 {
			return nil, nil, errors.New("datagram too short")
		}
		host, rest = net.IP(b[4:20]).String(), b[20:]
	case 3:
		n := int(b[4])
		if len(b) < 5+n+2 {
			return nil, nil, errors.New("datagram too short")
		}
		host, rest = string(b[5:5+n]), b[5+n:]
	default:
		return nil, nil, errors.New("bad address type")
	}
	if len(rest) < 2 {
		return nil, nil, errors.New("datagram too short")
	}
	port := int(binary.BigEndian.Uint16(rest))
	// ponytail: a domain name resolves inline and one slow lookup stalls the
	// relay. Resolve in a goroutine if a gap ever shows up in the dump.
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	return addr, rest[2:], err
}

// udpHeader builds the header that tells the client which host a payload came from.
func udpHeader(from *net.UDPAddr) []byte {
	h := []byte{0, 0, 0, 1} // RSV RSV FRAG ATYP=IPv4
	ip := from.IP.To4()
	if ip == nil {
		h[3], ip = 4, from.IP.To16()
	}
	return binary.BigEndian.AppendUint16(append(h, ip...), uint16(from.Port))
}

// socksUDPReply answers UDP ASSOCIATE with the address the client must send to.
// Reply and UDP header share a layout: three bytes, then ATYP ADDR PORT.
func socksUDPReply(bound *net.UDPAddr) []byte {
	b := udpHeader(bound)
	b[0], b[1], b[2] = 5, 0, 0 // VER, REP=succeeded, RSV
	return b
}

func readPrefixed(br *bufio.Reader) (string, error) {
	n, err := br.ReadByte()
	if err != nil {
		return "", err
	}
	b := make([]byte, n)
	_, err = io.ReadFull(br, b)
	return string(b), err
}

// ---------- helpers ----------

// proxyLine renders a listen address as the ip:port:user:pass string that
// proxy clients and proxy lists expect.
func proxyLine(addr, cred, ip string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr + ":" + cred
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = ip
	}
	return host + ":" + port + ":" + cred
}

// publicIP asks an echo service, because a VPS behind NAT (GCP, AWS) does not
// carry its public address on any interface. Falls back to the local outbound
// address when the lookup fails, so startup never hangs on a dead network.
func publicIP() string {
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get("https://api.ipify.org")
	if err != nil {
		return outboundIP()
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64)) // untrusted, cap it
	if err != nil {
		return outboundIP()
	}
	ip := strings.TrimSpace(string(b))
	if net.ParseIP(ip) == nil {
		return outboundIP()
	}
	return ip
}

// outboundIP reports the address this host routes out on, used only when the
// public lookup fails. The UDP socket sends nothing, it just picks a route.
func outboundIP() string {
	c, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// loadConfig reads .env and then every setting that depends on it. Settings
// must be read here and not in a package-level var, because those initialise
// before main runs, which is before .env exists as far as the process knows.
func loadConfig(path string) {
	loadDotEnv(path)
	dumpDir = os.Getenv("DUMP_DIR")
	if os.Getenv("NRO_LONG") == "0" {
		nroLong = false
	}
	if uri := os.Getenv("MONGO_URI"); uri != "" {
		sink, err := openMongo(uri, envOr("MONGO_DB", "vps_proxy"), envOr("MONGO_COLL", "logs"))
		if err == nil {
			mongoLog = sink
		} else {
			mongoNote = fmt.Sprintf("mongo  unreachable (%v)", err)
		}
	}
	// Proxying is the job; recording is not. Whether the database is
	// unreachable or was never configured, the capture must not silently
	// become nothing: it falls back to the log file and says so.
	if dumpDir == "mongo" && mongoLog == nil {
		dumpDir = "-"
		if mongoNote == "" {
			mongoNote = "mongo  DUMP_DIR=mongo but MONGO_URI is empty"
		}
		mongoNote += ", capture falls back to the log file"
	}
}

// loadDotEnv reads KEY=value lines. A real environment variable always wins,
// so systemd or docker -e can override the file without editing it.
func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return // no .env is fine, the environment may already carry everything
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if _, set := os.LookupEnv(key); !set {
			os.Setenv(key, strings.Trim(strings.TrimSpace(val), `"'`))
		}
	}
}
