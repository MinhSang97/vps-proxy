// dumpread turns a proxy capture back into messages. It reads proxy.log just
// as well as a DUMP_DIR file, because both carry the same record line:
// "<time> dump <proto> <peer> <dir> <n> bytes" followed by a hex block.
// TCP records are reassembled into a stream and split into messages; UDP
// records are already whole datagrams.
//
//	go build -o dumpread ./cmd/dumpread && ./dumpread proxy.log
package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	proto := flag.String("proto", "auto", "protocol: auto, nro (Ngoc Rong Online), or raw to skip decoding")
	frame := flag.String("frame", "auto", "framing to use: auto, none, or a name from the table dumpread prints")
	max := flag.Int("max", 64, "payload bytes to print per message, 0 for all")
	peer := flag.String("peer", "", "only this peer, e.g. 42.112.1.2:8085")
	key := flag.String("key", "rose", "NRO key to fall back on when the capture missed the handshake, empty to not try")
	mongoURI := flag.String("mongo", os.Getenv("MONGO_URI"), "read from this MongoDB instead of a file, used when no file is named")
	mongoDB := flag.String("mongo-db", envOr("MONGO_DB", "vps_proxy"), "database holding the capture")
	mongoColl := flag.String("mongo-coll", envOr("MONGO_COLL", "logs"), "collection holding the capture")
	flag.Parse()

	// No file named: read the capture out of the database the proxy writes to.
	if flag.NArg() == 0 {
		if *mongoURI == "" {
			fmt.Fprintln(os.Stderr, "usage: dumpread [-proto nro|raw] [-frame NAME] [-max N] [-peer HOST:PORT] proxy.log|file.dump ...")
			fmt.Fprintln(os.Stderr, "       dumpread            reads from MONGO_URI when no file is named")
			os.Exit(2)
		}
		recs, err := readMongo(*mongoURI, *mongoDB, *mongoColl, *peer)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mongo: %v\n", err)
			os.Exit(1)
		}
		show(*mongoDB+"."+*mongoColl+" in mongo", recs, *proto, *frame, []byte(*key), *max)
		return
	}
	for _, path := range flag.Args() {
		if err := report(path, *proto, *frame, *peer, []byte(*key), *max); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
		}
	}
}

// ---------- reading a capture ----------

// record is one chunk the proxy wrote: one read from the socket for TCP, one
// whole datagram for UDP.
type record struct {
	when  string
	proto string
	peer  string
	dir   string // C>S or S>C
	data  []byte
}

func parse(path, only string) ([]record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var recs []record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // a 64KB datagram dumps to a long block
	for sc.Scan() {
		line := sc.Text()
		if b, ok := hexLine(line); ok {
			if len(recs) > 0 {
				recs[len(recs)-1].data = append(recs[len(recs)-1].data, b...)
			}
			continue
		}
		r, ok := header(line)
		if !ok || (only != "" && r.peer != only) {
			continue
		}
		recs = append(recs, r)
	}
	return recs, sc.Err()
}

// header reads a record line. Everything before the word "dump" is the
// timestamp, which the log writes as a date and the files as a clock time.
func header(line string) (record, bool) {
	f := strings.Fields(line)
	i := -1
	for n, w := range f {
		if w == "dump" {
			i = n
			break
		}
	}
	// dump proto peer dir n bytes
	if i < 0 || len(f) != i+6 || f[i+5] != "bytes" {
		return record{}, false
	}
	if _, err := strconv.Atoi(f[i+4]); err != nil {
		return record{}, false
	}
	return record{
		when:  strings.Join(f[:i], " "),
		proto: f[i+1],
		peer:  f[i+2],
		dir:   f[i+3],
	}, true
}

// hexLine recognises one line of hex.Dump output and returns the bytes it
// holds. The ASCII column may itself contain a pipe, so the cut takes the
// first one, which is always the opening delimiter.
func hexLine(line string) ([]byte, bool) {
	if len(line) < 10 || strings.TrimLeft(line[:8], "0123456789abcdef") != "" {
		return nil, false
	}
	cut, _, _ := strings.Cut(line[10:], "|")
	b, err := hex.DecodeString(strings.ReplaceAll(cut, " ", ""))
	return b, err == nil
}

// ---------- splitting a stream into messages ----------

// framing describes how a stream marks message boundaries: a fixed header
// carrying a big-endian length, and optionally a command byte.
type framing struct {
	name      string
	header    int  // header size in bytes
	lenAt     int  // where the length starts inside the header
	lenSize   int  // 2 or 4
	cmdAt     int  // where the command byte sits, -1 when the framing has none
	inclusive bool // true when the length counts the header too
}

// Ordered most likely first: the first one that accounts for the whole stream wins.
var framings = []framing{
	{"cmd1+len2be", 3, 1, 2, 0, false},
	{"len2be+cmd1", 3, 0, 2, 2, false},
	{"len2be", 2, 0, 2, -1, false},
	{"len2be-inclusive", 2, 0, 2, -1, true},
	{"len4be", 4, 0, 4, -1, false},
	// Last on purpose: a game protocol should win the tie. When this one fits,
	// the tunnel carries TLS and the payload below is ciphertext, not messages.
	{"tls-record", 5, 3, 2, 0, false},
}

// split cuts a stream into messages and reports how many bytes it could not
// account for. A wrong guess shows up as leftover bytes, which is the whole
// point: zero leftover across a long stream is not a coincidence.
func (f framing) split(b []byte) (msgs [][]byte, leftover int) {
	for off := 0; off < len(b); {
		if off+f.header > len(b) {
			return msgs, len(b) - off
		}
		n := int(beUint(b[off+f.lenAt : off+f.lenAt+f.lenSize]))
		if f.inclusive {
			n -= f.header
		}
		end := off + f.header + n
		if n < 0 || end > len(b) {
			return msgs, len(b) - off
		}
		msgs = append(msgs, b[off:end])
		off = end
	}
	return msgs, 0
}

func beUint(b []byte) uint32 {
	var v uint32
	for _, c := range b {
		v = v<<8 | uint32(c)
	}
	return v
}

// ---------- the report ----------

func report(path, proto, want, only string, key []byte, max int) error {
	recs, err := parse(path, only)
	if err != nil {
		return err
	}
	show(path, recs, proto, want, key, max)
	return nil
}

// show prints a capture, whatever it was read from.
func show(label string, recs []record, proto, want string, key []byte, max int) {
	fmt.Printf("== %s\n", label)
	if len(recs) == 0 {
		fmt.Println("   no captured packets here")
		return
	}
	for _, peer := range peers(recs) {
		fmt.Printf("\n== peer %s\n", peer)
		mine := pick(recs, peer)
		if mine[0].proto == "udp" {
			// Each record is already one whole datagram: nothing to reassemble.
			for i, r := range mine {
				fmt.Printf("\n#%d  %s  %s  %s  %d bytes\n%s", i+1, r.when, r.dir, r.peer, len(r.data), indent(r.data, max))
			}
			continue
		}
		if proto != "raw" && reportNRO(mine, proto == "nro", key, max) {
			continue
		}
		for _, dir := range []string{"C>S", "S>C"} {
			reportStream(mine, dir, want, max)
		}
	}
}

// envOr reads a setting with a fallback, the same way the proxy does.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func reportStream(recs []record, dir, want string, max int) {
	stream, marks := join(recs, dir)
	if len(stream) == 0 {
		return
	}
	fmt.Printf("\n-- %s: %d bytes in %d reads\n", dir, len(stream), len(marks))
	f, msgs := guess(stream, want)
	if f.name == "none" {
		fmt.Printf("   no framing fits, printing the raw stream\n%s", indent(stream, max))
		return
	}
	fmt.Printf("   framing %s: %d messages\n", f.name, len(msgs))
	off := 0
	for i, m := range msgs {
		cmd := ""
		if f.cmdAt >= 0 {
			cmd = fmt.Sprintf("cmd=0x%02x ", m[f.cmdAt])
		}
		fmt.Printf("\n#%d  %s  %s  %s%d bytes\n%s",
			i+1, when(marks, off), dir, cmd, len(m)-f.header, indent(m[f.header:], max))
		off += len(m)
	}
}

// reportNRO prints the session as game messages and says whether it managed
// to. On "auto" a stream that is not this protocol simply falls through to the
// generic framing guesser; when the user asked for nro, the reason is printed.
func reportNRO(recs []record, asked bool, key []byte, max int) bool {
	up, upMarks := join(recs, "C>S")
	down, downMarks := join(recs, "S>C")
	s, err := nroDecode(up, down, upMarks, downMarks, key)
	if err != nil {
		if asked {
			fmt.Printf("   not decodable as NRO: %v\n", err)
		}
		return false
	}
	from := "from the handshake in this capture"
	if s.resynced {
		from = "no handshake captured, so this key was assumed and the stream realigned to it"
	}
	fmt.Printf("   NRO session, key %q (% x), %s\n", s.key, s.key, from)
	// The client version only becomes visible when command 12 shows up, because
	// that is the single command the two versions frame differently.
	if s.sawExtraBig {
		fmt.Printf("   client %s\n", map[bool]string{true: "2.4.2 or newer", false: "older than 2.4.2"}[s.longVersion])
	}
	for _, dir := range []string{"C>S", "S>C"} {
		if n := s.dropped[dir]; n > 0 {
			fmt.Printf("   %s: first %d bytes dropped, the capture starts inside a message\n", dir, n)
		}
		if n := s.tail[dir]; n > 0 {
			fmt.Printf("   %s: %d bytes left undecoded, either the capture was cut or the stream never lined up\n", dir, n)
		}
	}
	for i, m := range s.msgs {
		clear := ""
		if m.clear {
			clear = " (before the key, plaintext)"
		}
		fmt.Printf("\n#%d  %s  %s  cmd=%d %s  %d bytes%s\n", i+1, m.when, m.dir, m.cmd, m.name(), len(m.data), clear)
		if texts := nroText(m.data); len(texts) > 0 {
			for _, t := range texts {
				fmt.Printf("    text: %q\n", t)
			}
		}
		fmt.Print(indent(m.data, max))
	}
	return true
}

// guess reports which framing to use. On "auto" it prints every candidate it
// tried, so a capture that fits none still says why.
func guess(stream []byte, want string) (framing, [][]byte) {
	for _, f := range framings {
		if want != "auto" && want != f.name {
			continue
		}
		msgs, left := f.split(stream)
		if want == "auto" {
			if left == 0 {
				fmt.Printf("   try %-17s %d messages, nothing left over\n", f.name, len(msgs))
			} else {
				fmt.Printf("   try %-17s gave up after %d messages, %d bytes left over\n", f.name, len(msgs), left)
			}
		}
		if left == 0 {
			return f, msgs
		}
	}
	return framing{name: "none"}, nil
}

// peers lists the hosts in the capture, first seen first.
func peers(recs []record) []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range recs {
		if !seen[r.peer] {
			seen[r.peer] = true
			out = append(out, r.peer)
		}
	}
	return out
}

func pick(recs []record, peer string) []record {
	var out []record
	for _, r := range recs {
		if r.peer == peer {
			out = append(out, r)
		}
	}
	return out
}

// mark remembers where a read landed in the reassembled stream, so a message
// can be dated by the read it started in.
type mark struct {
	off  int
	when string
}

func join(recs []record, dir string) (stream []byte, marks []mark) {
	for _, r := range recs {
		if r.dir != dir {
			continue
		}
		marks = append(marks, mark{off: len(stream), when: r.when})
		stream = append(stream, r.data...)
	}
	return stream, marks
}

func when(marks []mark, off int) string {
	at := marks[0].when
	for _, m := range marks {
		if m.off > off {
			break
		}
		at = m.when
	}
	return at
}

func indent(b []byte, max int) string {
	note := ""
	if max > 0 && len(b) > max {
		note = fmt.Sprintf("    ... %d more bytes\n", len(b)-max)
		b = b[:max]
	}
	out := hex.Dump(b)
	if out == "" {
		return "    (no payload)\n"
	}
	return "    " + strings.ReplaceAll(strings.TrimSuffix(out, "\n"), "\n", "\n    ") + "\n" + note
}
