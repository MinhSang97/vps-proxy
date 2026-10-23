package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"testing"
)

// nroWriter builds a stream the way the game server does, so the decoder is
// tested against the encoding it claims to undo rather than against itself.
type nroWriter struct {
	out []byte
	key []byte
	idx int
	on  bool
}

func (w *nroWriter) put(b byte) byte {
	if !w.on {
		return b
	}
	c := w.key[w.idx] ^ b
	w.idx = (w.idx + 1) % len(w.key)
	return c
}

// msg appends one message. big picks the three-byte length the server uses for
// a handful of commands, where each byte is written as writeKey(x) - 128.
func (w *nroWriter) msg(cmd int8, data []byte, big bool) {
	w.out = append(w.out, w.put(byte(cmd)))
	size := len(data)
	if big {
		for _, shift := range []uint{0, 8, 16} {
			w.out = append(w.out, w.put(byte(size>>shift))-128)
		}
	} else {
		w.out = append(w.out, w.put(byte(size>>8)), w.put(byte(size)))
	}
	for _, b := range data {
		w.out = append(w.out, w.put(b))
	}
}

// utf encodes a string the way Java's writeUTF does: a two-byte length, then
// the bytes. Vietnamese text rides through unchanged.
func utf(s string) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(len(s)))
	return append(b, s...)
}

// keyBody is the payload of the server's -27 message: the key length, the
// first key byte, then each following byte XOR'd with the one before it.
func keyBody(key []byte) []byte {
	b := []byte{byte(len(key)), key[0]}
	for i := 1; i < len(key); i++ {
		b = append(b, key[i]^key[i-1])
	}
	b = append(b, utf("username")...)
	b = binary.BigEndian.AppendUint32(b, 14445)
	return append(b, 0)
}

func TestNRODecode(t *testing.T) {
	key := []byte{0x12, 0x5a, 0x7f, 0x03, 0x41, 0x9c, 0x28}

	// Server side: the plaintext key message, then encrypted traffic including
	// one command that uses the three-byte length.
	down := &nroWriter{key: key}
	down.msg(-27, keyBody(key), false)
	down.on = true
	down.msg(-29, utf("Dang nhap thanh cong"), false)
	down.msg(-66, make([]byte, 400), true) // GET_EFFDATA, three-byte length

	// Client side: the plaintext key request, then encrypted traffic.
	up := &nroWriter{key: key}
	up.msg(-27, nil, false)
	up.on = true
	up.msg(-29, append(utf("sangnm"), utf("matkhau")...), false)

	s, err := nroDecode(up.out, down.out, nil, nil, nil)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if string(s.key) != string(key) {
		t.Fatalf("recovered key % x, want % x", s.key, key)
	}
	for dir, n := range s.tail {
		if n != 0 {
			t.Errorf("%s left %d bytes undecoded, want 0", dir, n)
		}
	}

	type got struct {
		dir  string
		cmd  int8
		size int
	}
	want := []got{
		{"C>S", -27, 0}, {"C>S", -29, 17},
		{"S>C", -27, len(keyBody(key))}, {"S>C", -29, 22}, {"S>C", -66, 400},
	}
	if len(s.msgs) != len(want) {
		for _, m := range s.msgs {
			t.Logf("  %s cmd=%d %s %d bytes", m.dir, m.cmd, m.name(), len(m.data))
		}
		t.Fatalf("decoded %d messages, want %d", len(s.msgs), len(want))
	}
	for i, w := range want {
		m := s.msgs[i]
		if m.dir != w.dir || m.cmd != w.cmd || len(m.data) != w.size {
			t.Errorf("message %d = %s cmd=%d %d bytes, want %s cmd=%d %d bytes",
				i+1, m.dir, m.cmd, len(m.data), w.dir, w.cmd, w.size)
		}
	}

	// The point of decrypting: the payload reads as text again.
	if names := nroText(s.msgs[1].data); len(names) != 2 || names[0] != "sangnm" || names[1] != "matkhau" {
		t.Errorf("client login strings = %q, want [sangnm matkhau]", names)
	}
	if msg := nroText(s.msgs[3].data); len(msg) != 1 || msg[0] != "Dang nhap thanh cong" {
		t.Errorf("server strings = %q, want [Dang nhap thanh cong]", msg)
	}
	if n := s.msgs[4].name(); n != "GET_EFFDATA" {
		t.Errorf("command -66 named %q, want GET_EFFDATA", n)
	}
}

// TestNRODesyncIsCaught pins the property the decoder leans on: lose one byte
// and the key stream slips, so the rest cannot keep framing. Without that, a
// wrong guess would print plausible nonsense.
func TestNRODesyncIsCaught(t *testing.T) {
	key := []byte{0x12, 0x5a, 0x7f}
	down := &nroWriter{key: key}
	down.msg(-27, keyBody(key), false)
	down.on = true
	for i := 0; i < 40; i++ {
		down.msg(-29, make([]byte, 600), false)
	}
	up := &nroWriter{key: key}
	up.msg(-27, nil, false)

	if _, err := nroDecode(up.out, down.out, nil, nil, nil); err != nil {
		t.Fatalf("the intact session should decode: %v", err)
	}

	cut := append([]byte{}, down.out...)
	cut = append(cut[:len(keyBody(key))+4], cut[len(keyBody(key))+5:]...) // drop one byte after the handshake
	if _, err := nroDecode(up.out, cut, nil, nil, nil); err == nil {
		t.Error("a stream missing one byte decoded cleanly, the desync check is not working")
	}
}

// chatter fills a stream with the kind of traffic a session really carries:
// many messages in a row, each landing exactly on the next.
func chatter(w *nroWriter, prefix string, n int) {
	cmds := []int8{-72, -71, -29, -63, -50}
	for i := 0; i < n; i++ {
		w.msg(cmds[i%len(cmds)], utf(fmt.Sprintf("%s %d", prefix, i)), false)
	}
}

// TestNROResyncWithoutHandshake covers a recording started in the middle of a
// session: no key message was captured, and the first bytes land inside a
// message. The server builds every session on the same key, so the traffic is
// still readable once the stream is lined up again.
func TestNROResyncWithoutHandshake(t *testing.T) {
	key := []byte("rose")

	down := &nroWriter{key: key, on: true}
	down.idx = 3 // mid cycle, as it would be after a while of traffic
	chatter(down, "server noi", 12)

	up := &nroWriter{key: key, on: true}
	up.idx = 1
	chatter(up, "client noi", 12)

	// Cut into the first message of each direction, the way a late start does.
	s, err := nroDecode(up.out[5:], down.out[9:], nil, nil, key)
	if err != nil {
		t.Fatalf("resync failed: %v", err)
	}
	if !s.resynced {
		t.Error("session reported as decoded from a handshake, but there was none")
	}

	var texts []string
	for _, m := range s.msgs {
		texts = append(texts, nroText(m.data)...)
	}
	for _, want := range []string{"client noi 11", "server noi 11", "client noi 3"} {
		found := false
		for _, got := range texts {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("message %q not recovered out of %d strings", want, len(texts))
		}
	}

	// A key that is not the server's must not produce readable traffic.
	if _, err := nroDecode(up.out[5:], down.out[9:], nil, nil, []byte("xxxx")); err == nil {
		t.Error("a wrong key decoded the session, the fit check is not working")
	}
}

// TestNROResyncRejectsLuckyAlignment pins why realignment anchors on the
// command set. Cut into a login message and one wrong starting point frames
// "matkhau123" as a message of its own under a command the game has no case
// for. Length alone cannot tell that apart; the command can.
func TestNROResyncRejectsLuckyAlignment(t *testing.T) {
	key := []byte("rose")
	up := &nroWriter{key: key}
	up.msg(-27, nil, false)
	up.on = true
	up.msg(-29, append(utf("sangnm"), utf("matkhau123")...), false)
	chatter(up, "client noi", 10)

	down := &nroWriter{key: key}
	down.msg(-27, keyBody(key), false)
	down.on = true
	chatter(down, "server noi", 10)

	s, err := nroDecode(up.out[9:], down.out[28:], nil, nil, key)
	if err != nil {
		t.Fatalf("resync failed: %v", err)
	}
	for _, m := range s.msgs {
		if !nroCommands[m.cmd] {
			t.Errorf("decoded a message on command %d, which the game has no case for: %q",
				m.cmd, m.data)
		}
	}
	for _, m := range s.msgs {
		if m.dir == "C>S" {
			if m.cmd == -29 || len(nroText(m.data)) == 0 {
				t.Errorf("first client message is cmd=%d %q, want a real chat message",
					m.cmd, m.data)
			}
			break
		}
	}
}

// TestNROResyncRejectsForeignTraffic pins the bug that realignment used to
// have: a TLS tunnel through the same proxy decoded as a game session, naming
// random bytes PLAYER_ATTACK_PLAYER. Any byte string yields a short lucky
// chain, so the bar is a long run of messages covering the whole stream.
func TestNROResyncRejectsForeignTraffic(t *testing.T) {
	// A TLS handshake record followed by application data, which is what the
	// proxy sees for any https tunnel.
	rnd := rand.New(rand.NewSource(1))
	var tls []byte
	for _, n := range []int{517, 1400, 2800, 900} {
		body := make([]byte, n)
		rnd.Read(body)
		tls = append(tls, 0x16, 0x03, 0x01, byte(n>>8), byte(n))
		tls = append(tls, body...)
	}
	other := make([]byte, 3000)
	rnd.Read(other)

	if s, err := nroDecode(tls, other, nil, nil, []byte("rose")); err == nil {
		t.Errorf("TLS traffic decoded as an NRO session with %d messages, first cmd=%d",
			len(s.msgs), s.msgs[0].cmd)
	}
	if s, err := nroDecode(other, tls, nil, nil, []byte("rose")); err == nil {
		t.Errorf("random traffic decoded as an NRO session with %d messages", len(s.msgs))
	}
}
