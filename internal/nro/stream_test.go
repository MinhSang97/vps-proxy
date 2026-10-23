package nro

import (
	"encoding/binary"
	"testing"
)

// writer builds a stream exactly as the game encodes one, so the decoder is
// tested against the encoding it undoes, not against itself.
type writer struct {
	out []byte
	key []byte
	idx int
	on  bool
}

func (w *writer) put(b byte) byte {
	if !w.on {
		return b
	}
	c := w.key[w.idx] ^ b
	w.idx = (w.idx + 1) % len(w.key)
	return c
}

func (w *writer) msg(cmd int8, data []byte) {
	w.out = append(w.out, w.put(byte(cmd)))
	w.out = append(w.out, w.put(byte(len(data)>>8)), w.put(byte(len(data))))
	for _, b := range data {
		w.out = append(w.out, w.put(b))
	}
}

func utf(s string) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(s))), s...)
}

func keyBody(key []byte) []byte {
	b := []byte{byte(len(key)), key[0]}
	for i := 1; i < len(key); i++ {
		b = append(b, key[i]^key[i-1])
	}
	return b
}

// feedChunks splits b into pieces of size n and feeds them, to prove the
// decoder stitches a message that arrives split across several socket reads.
func feedChunks(c *Conn, toServer bool, b []byte, n int) []Message {
	var out []Message
	for i := 0; i < len(b); i += n {
		j := i + n
		if j > len(b) {
			j = len(b)
		}
		out = append(out, c.Feed(toServer, b[i:j])...)
	}
	return out
}

func TestConnDecodesBothDirections(t *testing.T) {
	key := []byte("rose")

	up := &writer{key: key}
	up.msg(GetKey, nil) // client requests the key, plaintext
	up.on = true
	up.msg(-29, append(utf("sangnm"), utf("matkhau")...))
	up.msg(-72, utf("di Namek di ban oi"))

	down := &writer{key: key}
	down.msg(GetKey, keyBody(key)) // server reply carries the key, plaintext
	down.on = true
	down.msg(-29, utf("Dang nhap thanh cong"))

	c := NewConn(true)
	// Feed server first so the key is known, then client, each 3 bytes at a time
	// to force message reassembly across chunks.
	msgs := feedChunks(c, false, down.out, 3)
	msgs = append(msgs, feedChunks(c, true, up.out, 3)...)

	type want struct {
		dir  string
		cmd  int8
		text string
	}
	wants := []want{
		{"S>C", GetKey, ""},
		{"S>C", -29, "Dang nhap thanh cong"},
		{"C>S", GetKey, ""},
		{"C>S", -29, "sangnm"},
		{"C>S", -72, "di Namek di ban oi"},
	}
	if len(msgs) != len(wants) {
		for _, m := range msgs {
			t.Logf("  %s cmd=%d %s %q", m.Dir, m.Cmd, m.Name(), Text(m.Data))
		}
		t.Fatalf("decoded %d messages, want %d", len(msgs), len(wants))
	}
	for i, w := range wants {
		m := msgs[i]
		if m.Dir != w.dir || m.Cmd != w.cmd {
			t.Errorf("msg %d = %s cmd=%d, want %s cmd=%d", i, m.Dir, m.Cmd, w.dir, w.cmd)
		}
		if w.text != "" {
			got := Text(m.Data)
			if len(got) == 0 || got[0] != w.text {
				t.Errorf("msg %d text = %q, want %q", i, got, w.text)
			}
		}
	}
}

// TestConnClientBeforeServerKey covers the ordering where client bytes arrive
// before the server has handed over the key: those bytes must wait, not decode
// wrong, and drain once the key lands.
func TestConnClientBeforeServerKey(t *testing.T) {
	key := []byte("rose")
	up := &writer{key: key}
	up.msg(GetKey, nil)
	up.on = true
	up.msg(-72, utf("hello"))

	down := &writer{key: key}
	down.msg(GetKey, keyBody(key))

	c := NewConn(true)
	// All client bytes first: only the plaintext -27 can decode; the rest waits.
	early := c.Feed(true, up.out)
	if len(early) != 1 || early[0].Cmd != GetKey {
		t.Fatalf("before key, decoded %d messages, want just the handshake", len(early))
	}
	// Key arrives on S>C; the waiting client message must now come out.
	after := c.Feed(false, down.out)
	var client []Message
	for _, m := range after {
		if m.Dir == "C>S" {
			client = append(client, m)
		}
	}
	if len(client) != 1 || client[0].Cmd != -72 || Text(client[0].Data)[0] != "hello" {
		t.Fatalf("after key, client messages = %+v, want one -72 hello", client)
	}
}

// TestConnRejectsNonNRO pins that traffic which does not open with the handshake
// (plain TLS here) produces no messages, so no garbage is stored.
func TestConnRejectsNonNRO(t *testing.T) {
	// A TLS record: cmd byte 0x16, then 0x0301 read as a 769-byte length. Feed
	// enough that this bogus first message frames fully, so the "first message
	// must be the handshake" check fires instead of just waiting for more bytes.
	tls := []byte{0x16, 0x03, 0x01}
	tls = append(tls, make([]byte, 769)...)
	c := NewConn(true)
	if msgs := c.Feed(true, tls); len(msgs) != 0 {
		t.Fatalf("TLS decoded as %d NRO messages, want 0", len(msgs))
	}
	if !c.bad {
		t.Error("connection not marked as non-NRO")
	}
}
