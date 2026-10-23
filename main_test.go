package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func client(t *testing.T, proxyURL string) *http.Client {
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(u),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
}

func TestProxy(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	plain := httptest.NewServer(h)
	defer plain.Close()
	secure := httptest.NewTLSServer(h)
	defer secure.Close()

	proxy := httptest.NewServer(newHandler("u:p"))
	defer proxy.Close()
	host := proxy.URL[len("http://"):]

	t.Run("no credentials rejected", func(t *testing.T) {
		resp, err := client(t, "http://"+host).Get(plain.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("got %d, want 407", resp.StatusCode)
		}
	})

	for name, target := range map[string]string{"http": plain.URL, "https via CONNECT": secure.URL} {
		t.Run(name, func(t *testing.T) {
			resp, err := client(t, "http://u:p@"+host).Get(target)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			if string(b) != "ok" {
				t.Fatalf("got %q, want %q", b, "ok")
			}
		})
	}
}

func TestProxyLine(t *testing.T) {
	for addr, want := range map[string]string{
		":8080":          "1.2.3.4:8080:u:p",
		"0.0.0.0:1080":   "1.2.3.4:1080:u:p",
		"10.0.0.9:3128":  "10.0.0.9:3128:u:p",
		"127.0.0.1:1080": "127.0.0.1:1080:u:p",
	} {
		if got := proxyLine(addr, "u:p", "1.2.3.4"); got != want {
			t.Errorf("proxyLine(%q) = %q, want %q", addr, got, want)
		}
	}
}

func TestDumpCapturesBothDirections(t *testing.T) {
	dumpDir = t.TempDir()
	defer func() { dumpDir = "" }()

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer secure.Close()
	proxy := httptest.NewServer(newHandler("u:p"))
	defer proxy.Close()

	resp, err := client(t, "http://u:p@"+proxy.URL[len("http://"):]).Get(secure.URL)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	files, err := filepath.Glob(filepath.Join(dumpDir, "*.dump"))
	if err != nil || len(files) != 1 {
		t.Fatalf("got %d dump files, want 1 (%v)", len(files), err)
	}
	b, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"C>S", "S>C"} {
		if !bytes.Contains(b, []byte(tag)) {
			t.Errorf("dump captured no %s traffic:\n%s", tag, b)
		}
	}
}

// socksHandshake authenticates against a freshly accepted SOCKS5 connection and
// returns the reply to the given request (VER CMD RSV ATYP ADDR PORT).
func socksHandshake(t *testing.T, c net.Conn, req []byte) []byte {
	t.Helper()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	reply := make([]byte, 10)
	for _, step := range [][]byte{
		{5, 1, 2},           // greeting, username/password only
		{1, 1, 'u', 1, 'p'}, // auth u:p
	} {
		if _, err := c.Write(step); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(c, reply[:2]); err != nil {
			t.Fatal(err)
		}
		if reply[1] != 0 && reply[1] != 2 {
			t.Fatalf("handshake refused: % x", reply[:2])
		}
	}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("request refused with code %d", reply[1])
	}
	return reply
}

func TestSocksUDPAssociate(t *testing.T) {
	// The "game server": a UDP echo on loopback.
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFrom(b)
			if err != nil {
				return
			}
			echo.WriteTo(append([]byte("echo:"), b[:n]...), from)
		}
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	served := make(chan struct{})
	go func() {
		defer close(served)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		socksConn(c, bufio.NewReader(c), "u:p")
	}()

	ctrl, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// Close the control connection and wait: the relay goroutine reads settings
	// a later test may write, so it must be done before this test is.
	t.Cleanup(func() { ctrl.Close(); <-served })

	// UDP ASSOCIATE, announcing 0.0.0.0:0 the way real clients do.
	reply := socksHandshake(t, ctrl, []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	relay := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:]))}

	conn, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	target := echo.LocalAddr().(*net.UDPAddr)
	if _, err := conn.Write(append(udpHeader(target), "ping"...)); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n < 10 {
		t.Fatalf("reply too short: % x", buf[:n])
	}
	if got, want := string(buf[10:n]), "echo:ping"; got != want {
		t.Fatalf("relayed payload = %q, want %q", got, want)
	}
	if port := int(binary.BigEndian.Uint16(buf[8:10])); port != target.Port {
		t.Errorf("reply header names port %d, want %d from the echo server", port, target.Port)
	}
}

// TestDotEnvReachesDump pins the ordering bug that made DUMP_DIR in .env do
// nothing: the setting was read into a package-level var, which Go initialises
// before main gets the chance to load .env.
func TestDotEnvReachesDump(t *testing.T) {
	defer func(old string) { dumpDir = old }(dumpDir)
	dumpDir = ""

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("DUMP_DIR=-\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// .env only fills in what the environment leaves unset, by design.
	if old, ok := os.LookupEnv("DUMP_DIR"); ok {
		os.Unsetenv("DUMP_DIR")
		defer os.Setenv("DUMP_DIR", old)
	}

	loadConfig(filepath.Join(dir, ".env"))
	if dumpDir != "-" {
		t.Fatalf("dumpDir = %q after loading .env, want %q", dumpDir, "-")
	}
}

// TestMongoFailureDoesNotStopTheProxy pins a regression: wiring the capture to
// MongoDB made an unreachable database fatal, so a deploy that carried the
// same .env to a host without mongo could not start the proxy at all. The
// recorder may degrade, the proxy may not.
func TestMongoFailureDoesNotStopTheProxy(t *testing.T) {
	defer func(dir string, sink *mongoSink) { dumpDir, mongoLog = dir, sink }(dumpDir, mongoLog)
	dumpDir, mongoLog = "", nil

	dir := t.TempDir()
	env := "DUMP_DIR=mongo\nMONGO_URI=mongodb://%zz-not-a-host\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"DUMP_DIR", "MONGO_URI"} {
		if old, ok := os.LookupEnv(k); ok {
			os.Unsetenv(k)
			defer os.Setenv(k, old)
		}
	}

	loadConfig(filepath.Join(dir, ".env")) // must return, not exit

	if mongoLog != nil {
		t.Error("a sink was kept for a database that cannot be reached")
	}
	if dumpDir != "-" {
		t.Errorf("dumpDir = %q, want %q so the capture still lands in the log", dumpDir, "-")
	}
}

// TestDumpMongoWithoutURIStillCaptures pins a silent failure: DUMP_DIR=mongo
// with no MONGO_URI left newDump with nothing to write to, so the proxy ran
// and recorded absolutely nothing without a word about it.
func TestDumpMongoWithoutURIStillCaptures(t *testing.T) {
	defer func(dir, note string, sink *mongoSink) {
		dumpDir, mongoNote, mongoLog = dir, note, sink
	}(dumpDir, mongoNote, mongoLog)
	dumpDir, mongoNote, mongoLog = "", "", nil

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("DUMP_DIR=mongo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"DUMP_DIR", "MONGO_URI"} {
		if old, ok := os.LookupEnv(k); ok {
			os.Unsetenv(k)
			defer os.Setenv(k, old)
		}
	}

	loadConfig(filepath.Join(dir, ".env"))

	if dumpDir != "-" {
		t.Errorf("dumpDir = %q, want %q so packets still reach the log", dumpDir, "-")
	}
	if mongoNote == "" {
		t.Error("no note explaining why the capture is not going to mongo")
	}
}
