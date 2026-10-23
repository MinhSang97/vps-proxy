// Package nro decodes the Ngoc Rong Online wire protocol, read from the game
// server at ngocrongonline_server (game/Session_ME.java: readMessage,
// doSendMessage, readKey, writeKey, getKey).
//
// A message is cmd(1) + size(2, big-endian) + data(size). The session opens in
// the clear: the client asks for the key with command -27 and the server
// answers with -27 carrying it. From then on every byte is XOR'd with that
// key, one key byte per traffic byte, each direction keeping its own index.
//
// This package holds the primitives shared by the proxy (live decoding) and the
// dumpread tool (offline decoding), so the framing and the generated command
// tables live in one place.
package nro

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

// GetKey is the command that carries the XOR key in its body.
const GetKey = -27

// ErrTruncated means the buffer ran out mid-message: normal at the end of a
// stream, fatal anywhere else.
var ErrTruncated = errors.New("stream ends mid-message")

// Name returns the readable command name, or "?" when unknown.
func Name(cmd int8) string {
	if n, ok := Names[cmd]; ok {
		return n
	}
	return "?"
}

// bigSize lists the commands the server sends with a three-byte length instead
// of two. Command 12 only joins the list for client 2.4.2 and newer.
func bigSize(cmd int8, long bool) bool {
	switch cmd {
	case -32, -66, 11, -67, -74, -87, 66:
		return true
	case 12:
		return long
	}
	return false
}

// Key rebuilds the XOR key from the body of the server's -27 message. The
// server sends key[0] as is and every later byte XOR'd with the one before it.
func Key(body []byte) ([]byte, error) {
	if len(body) < 2 {
		return nil, errors.New("key message has no body")
	}
	n := int(body[0])
	if n <= 0 || len(body) < 1+n {
		return nil, fmt.Errorf("key message claims %d key bytes but carries %d", n, len(body)-1)
	}
	key := make([]byte, n)
	key[0] = body[1]
	for i := 1; i < n; i++ {
		key[i] = body[1+i] ^ key[i-1]
	}
	return key, nil
}

// Reader walks one direction of a session, decrypting as it goes once the key
// is in play. Every byte consumed advances the key index, so losing a single
// byte desynchronises everything after it: that is why a wrong guess shows up
// immediately as a nonsense length.
type Reader struct {
	B   []byte
	Off int
	Key []byte // nil until the key is in play
	Idx int
}

func (r *Reader) next() (byte, bool) {
	if r.Off >= len(r.B) {
		return 0, false
	}
	c := r.B[r.Off]
	r.Off++
	if r.Key != nil {
		c ^= r.Key[r.Idx]
		r.Idx = (r.Idx + 1) % len(r.Key)
	}
	return c, true
}

// next2 undoes the "+128 then key" encoding the three-byte length uses. The
// shift happens on the wire, before the key, so it is undone first.
func (r *Reader) next2(shift byte) (byte, bool) {
	if r.Off >= len(r.B) {
		return 0, false
	}
	c := r.B[r.Off] + shift
	r.Off++
	if r.Key != nil {
		c ^= r.Key[r.Idx]
		r.Idx = (r.Idx + 1) % len(r.Key)
	}
	return c, true
}

// Message reads one message, or reports ErrTruncated when the buffer runs out
// mid-message, leaving Off and Idx untouched so the read can be retried later
// with more bytes.
func (r *Reader) Message(fromServer, long bool) (cmd int8, data []byte, wire int, err error) {
	start, startIdx := r.Off, r.Idx
	rewind := func() { r.Off, r.Idx = start, startIdx }

	c, ok := r.next()
	if !ok {
		rewind()
		return 0, nil, 0, ErrTruncated
	}
	cmd = int8(c)

	var size int
	if fromServer && bigSize(cmd, long) {
		var parts [3]int
		for i := range parts {
			b, ok := r.next2(128)
			if !ok {
				rewind()
				return 0, nil, 0, ErrTruncated
			}
			parts[i] = int(b)
		}
		size = parts[0] | parts[1]<<8 | parts[2]<<16
	} else {
		hi, ok1 := r.next()
		lo, ok2 := r.next()
		if !ok1 || !ok2 {
			rewind()
			return 0, nil, 0, ErrTruncated
		}
		size = int(hi)<<8 | int(lo)
	}
	if size < 0 || r.Off+size > len(r.B) {
		rewind()
		return 0, nil, 0, ErrTruncated
	}
	data = make([]byte, size)
	for i := range data {
		data[i], _ = r.next()
	}
	return cmd, data, r.Off - start, nil
}

// Text pulls the strings out of a payload. The game writes them with Java's
// writeUTF: two bytes of length then the bytes, so a length that lands exactly
// on a run of readable text is a string, not a coincidence.
func Text(b []byte) []string {
	var out []string
	for i := 0; i+2 <= len(b); {
		n := int(binary.BigEndian.Uint16(b[i:]))
		if n >= 2 && i+2+n <= len(b) {
			if s := string(b[i+2 : i+2+n]); readable(s) {
				out = append(out, s)
				i += 2 + n
				continue
			}
		}
		i++
	}
	return out
}

func readable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsGraphic(r) {
			return false
		}
	}
	return true
}
