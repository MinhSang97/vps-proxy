package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

// dumpOf renders a record the way the proxy writes one, so the test breaks if
// the two formats ever drift apart.
func dumpOf(when, proto, peer, dir string, b []byte) string {
	return fmt.Sprintf("%s dump %s %s %s %d bytes\n%s\n", when, proto, peer, dir, len(b), hex.Dump(b))
}

func TestParseAndFrame(t *testing.T) {
	// Two messages framed as cmd(1) + length(2), split across two reads the way
	// TCP really delivers them: the second message arrives in halves.
	msgs := [][]byte{
		append([]byte{0x7b, 0x00, 0x04}, "ping"...),
		append([]byte{0x0a, 0x00, 0x06}, "pongly"...),
	}
	all := append(append([]byte{}, msgs[0]...), msgs[1]...)

	capture := "2026/10/23 09:40:37 proxy listening on :8080\n" +
		dumpOf("2026/10/23 09:40:38", "tcp", "1.2.3.4:8085", "C>S", all[:6]) +
		"2026/10/23 09:40:38 socks5 noise in between\n" +
		dumpOf("2026/10/23 09:40:39", "tcp", "1.2.3.4:8085", "C>S", all[6:])

	path := t.TempDir() + "/proxy.log"
	if err := os.WriteFile(path, []byte(capture), 0o600); err != nil {
		t.Fatal(err)
	}

	recs, err := parse(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("parsed %d records, want 2", len(recs))
	}
	if recs[0].proto != "tcp" || recs[0].peer != "1.2.3.4:8085" || recs[0].dir != "C>S" {
		t.Fatalf("header parsed as proto=%q peer=%q dir=%q", recs[0].proto, recs[0].peer, recs[0].dir)
	}

	stream, marks := join(recs, "C>S")
	if !bytes.Equal(stream, all) {
		t.Fatalf("reassembled % x, want % x", stream, all)
	}
	if len(marks) != 2 || marks[1].off != 6 {
		t.Fatalf("marks = %+v, want the second read at offset 6", marks)
	}

	f, got := guess(stream, "cmd1+len2be")
	if f.name != "cmd1+len2be" {
		t.Fatalf("framing %q did not fit", f.name)
	}
	if len(got) != len(msgs) {
		t.Fatalf("split into %d messages, want %d", len(got), len(msgs))
	}
	for i := range msgs {
		if !bytes.Equal(got[i], msgs[i]) {
			t.Errorf("message %d = % x, want % x", i+1, got[i], msgs[i])
		}
	}

	// The wrong framing must not quietly look right.
	if _, left := framings[1].split(stream); left == 0 {
		t.Errorf("framing %s accounted for the whole stream, it should not", framings[1].name)
	}
}

func TestPeerFilter(t *testing.T) {
	capture := dumpOf("09:40:38.100", "udp", "1.1.1.1:53", "C>S", []byte("a")) +
		dumpOf("09:40:38.200", "udp", "2.2.2.2:99", "C>S", []byte("b"))
	path := t.TempDir() + "/x.dump"
	if err := os.WriteFile(path, []byte(capture), 0o600); err != nil {
		t.Fatal(err)
	}
	recs, err := parse(path, "2.2.2.2:99")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || string(recs[0].data) != "b" {
		t.Fatalf("peer filter kept %+v, want only the 2.2.2.2:99 record", recs)
	}
}
