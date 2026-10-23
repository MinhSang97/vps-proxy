// NRO protocol decoding, read from the game server at
// ngocrongonline_server/src/main/java/com/nro/dragon/game/Session_ME.java
// (readMessage, doSendMessage, readKey, writeKey, getKey).
//
// A message is cmd(1) + size(2, big-endian) + data(size). The session opens in
// the clear: the client asks for the key with command -27 and the server
// answers with -27 carrying it. From then on every byte is XOR'd with that
// key, one key byte per traffic byte, each direction keeping its own index.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

const nroGetKey = -27

// nroBigSize lists the commands the server sends with a three-byte length
// instead of two. Command 12 only joins the list for client 2.4.2 and newer,
// which is what longVersion decides.
func nroBigSize(cmd int8, longVersion bool) bool {
	switch cmd {
	case -32, -66, 11, -67, -74, -87, 66:
		return true
	case 12:
		return longVersion
	}
	return false
}

// nroMessage is one decoded game message.
type nroMessage struct {
	when  string
	dir   string
	cmd   int8
	data  []byte
	wire  int  // bytes this message took on the wire, header included
	clear bool // the handshake messages travel before the key exists
}

func (m nroMessage) name() string {
	if n, ok := nroNames[m.cmd]; ok {
		return n
	}
	return "?"
}

// nroKey rebuilds the XOR key from the body of the server's -27 message. The
// server sends key[0] as is and every later byte XOR'd with the one before it.
func nroKey(body []byte) ([]byte, error) {
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

// nroReader walks one direction of a session, decrypting as it goes once the
// key is in play. Every byte consumed advances the key index, so losing a
// single byte desynchronises everything after it: that is why a wrong guess
// shows up immediately as a nonsense length.
type nroReader struct {
	b   []byte
	off int
	key []byte // nil until the handshake has been seen
	idx int
}

func (r *nroReader) next() (byte, bool) {
	if r.off >= len(r.b) {
		return 0, false
	}
	c := r.b[r.off]
	r.off++
	if r.key != nil {
		c ^= r.key[r.idx]
		r.idx = (r.idx + 1) % len(r.key)
	}
	return c, true
}

// message reads one message, or reports that the capture ran out mid-message,
// which is normal at the end of a capture and fatal anywhere else.
func (r *nroReader) message(fromServer, longVersion bool) (int8, []byte, int, error) {
	start, startIdx := r.off, r.idx
	rewind := func() { r.off, r.idx = start, startIdx }

	c, ok := r.next()
	if !ok {
		rewind()
		return 0, nil, 0, errNroTruncated
	}
	cmd := int8(c)

	var size int
	if fromServer && nroBigSize(cmd, longVersion) {
		// The server writes these as writeKey(byte) - 128, low byte first.
		var parts [3]int
		for i := range parts {
			b, ok := r.next2(128)
			if !ok {
				rewind()
				return 0, nil, 0, errNroTruncated
			}
			parts[i] = int(b)
		}
		size = parts[0] | parts[1]<<8 | parts[2]<<16
	} else {
		hi, ok1 := r.next()
		lo, ok2 := r.next()
		if !ok1 || !ok2 {
			rewind()
			return 0, nil, 0, errNroTruncated
		}
		size = int(hi)<<8 | int(lo)
	}
	if size < 0 || r.off+size > len(r.b) {
		rewind()
		return 0, nil, 0, errNroTruncated
	}
	data := make([]byte, size)
	for i := range data {
		data[i], _ = r.next()
	}
	return cmd, data, r.off - start, nil
}

// next2 undoes the "+128 then key" encoding the three-byte length uses. The
// shift happens on the wire, before the key, so it is undone first.
func (r *nroReader) next2(shift byte) (byte, bool) {
	if r.off >= len(r.b) {
		return 0, false
	}
	c := r.b[r.off] + shift
	r.off++
	if r.key != nil {
		c ^= r.key[r.idx]
		r.idx = (r.idx + 1) % len(r.key)
	}
	return c, true
}

var errNroTruncated = errors.New("capture ends mid-message")

// nroSession is one decoded conversation.
type nroSession struct {
	key         []byte
	resynced    bool // the handshake was missing, so the key came from -key
	longVersion bool
	sawExtraBig bool           // a command 12 appeared, which is the only thing that tells the versions apart
	msgs        []nroMessage   // both directions, each in its own order
	tail        map[string]int // bytes at the end that did not decode
	dropped     map[string]int // bytes at the start that fell inside a message
}

// nroDecode decodes both directions. It finds the key in the server's stream,
// then replays each direction. The client turns the key on after it receives
// that message, and nothing it sent before then was encrypted, so the number of
// plaintext client messages is settled by trying the few possibilities and
// keeping the one that decodes furthest: a wrong choice desynchronises the key
// and dies within a message or two.
func nroDecode(toServer, toClient []byte, upMarks, downMarks []mark, fallback []byte) (*nroSession, error) {
	var first error
	for _, long := range []bool{false, true} {
		s, err := decodeWith(toServer, toClient, upMarks, downMarks, long)
		if err == nil {
			return s, nil
		}
		if first == nil {
			first = err
		}
	}
	// No handshake in the capture, which is what a recording started in the
	// middle of a session looks like. This server builds every session on the
	// same hardcoded key, so the traffic is still readable once the stream is
	// lined up again.
	if len(fallback) > 0 {
		for _, long := range []bool{false, true} {
			if s, err := resync(toServer, toClient, upMarks, downMarks, long, fallback); err == nil {
				return s, nil
			}
		}
		return nil, fmt.Errorf("%w, and the key %q did not line up either", first, fallback)
	}
	return nil, first
}

// resync decodes a capture that never saw the handshake. Two things are
// unknown: where the first whole message starts, because the recording may
// have begun mid-message, and where the key index sits in its cycle. Both are
// small, so every pair is tried and the one that keeps framing wins.
func resync(toServer, toClient []byte, upMarks, downMarks []mark, long bool, key []byte) (*nroSession, error) {
	upMsgs, upEnd, upSkip := resyncOne(toServer, key, false, long)
	downMsgs, downEnd, downSkip := resyncOne(toClient, key, true, long)
	// Two messages anywhere is the bar. Each one had to start on a command the
	// server handles and carry a length that landed on the next one, which a
	// wrong key or a wrong alignment does not manage twice in a row.
	if len(upMsgs)+len(downMsgs) < 2 {
		return nil, errors.New("the key does not fit either direction")
	}
	s := &nroSession{key: key, longVersion: long, resynced: true,
		tail: map[string]int{
			"C>S": len(toServer) - upEnd,
			"S>C": len(toClient) - downEnd,
		},
		dropped: map[string]int{"C>S": upSkip, "S>C": downSkip},
	}
	for _, m := range downMsgs {
		if m.cmd == 12 {
			s.sawExtraBig = true
		}
	}
	s.msgs = append(stamp(upMsgs, upMarks), stamp(downMsgs, downMarks)...)
	return s, nil
}

// resyncOne finds the best starting point for one direction and decodes from
// there. The search looks only a few messages ahead per candidate, because a
// wrong pair gives up almost immediately; the winner is then walked in full.
func resyncOne(b, key []byte, fromServer, long bool) ([]nroMessage, int, int) {
	const lookAhead = 8
	maxSkip := len(b)
	if maxSkip > 1024 {
		maxSkip = 1024
	}
	bestSkip, bestPhase, bestFit := -1, 0, 0
	for skip := 0; skip < maxSkip; skip++ {
		for phase := 0; phase < len(key); phase++ {
			if fit := probe(b, key, skip, phase, fromServer, long, lookAhead); fit > bestFit {
				bestSkip, bestPhase, bestFit = skip, phase, fit
			}
		}
	}
	if bestFit < 1 {
		return nil, 0, len(b)
	}
	r := &nroReader{b: b, off: bestSkip, key: key, idx: bestPhase}
	msgs := drain(r, fromServer, long)

	// Matching a few messages proves nothing. There are a thousand places to
	// start and four key phases to try, and roughly a quarter of all byte
	// values name a real command, so random traffic will always produce a
	// short lucky chain: TLS once decoded here as PLAYER_ATTACK_PLAYER. Real
	// traffic is different in kind, not degree, because every message lands
	// exactly on the next one all the way to the end of the stream.
	//
	// The commands themselves are not re-checked here: probe already refused
	// any starting point that did not open on a real one, and rejecting a
	// decoded session over a command missing from the table would throw away
	// good data to guard against nothing.
	rest := len(b) - bestSkip
	if len(msgs) < minResyncRun || (r.off-bestSkip)*10 < rest*9 {
		return nil, 0, len(b)
	}
	return msgs, r.off, bestSkip
}

// minResyncRun is how many messages in a row a realignment must produce before
// it is believed. Combined with the coverage test it is what separates a real
// session from a lucky fit.
const minResyncRun = 6

// probe counts how many messages a starting point yields before it stops
// making sense, looking at most want of them. A starting point whose first
// message is not a command the server handles is not a message boundary at
// all, just a lucky length, so it scores nothing.
func probe(b, key []byte, skip, phase int, fromServer, long bool, want int) int {
	r := &nroReader{b: b, off: skip, key: key, idx: phase}
	n := 0
	for n < want {
		cmd, _, _, err := r.message(fromServer, long)
		if err != nil {
			break
		}
		if n == 0 && !nroCommands[cmd] {
			return 0
		}
		n++
	}
	return n
}

func decodeWith(toServer, toClient []byte, upMarks, downMarks []mark, long bool) (*nroSession, error) {
	// The server's side: plaintext until the -27 reply, encrypted after it.
	down := &nroReader{b: toClient}
	var downMsgs []nroMessage
	var key []byte
	for key == nil {
		cmd, data, wire, err := down.message(true, long)
		if err != nil {
			return nil, fmt.Errorf("no key handshake in the server stream: %w", err)
		}
		downMsgs = append(downMsgs, nroMessage{dir: "S>C", cmd: cmd, data: data, wire: wire, clear: true})
		if cmd == nroGetKey {
			if key, err = nroKey(data); err != nil {
				return nil, err
			}
		}
	}
	down.key, down.idx = key, 0
	downMsgs = append(downMsgs, drain(down, true, long)...)

	// The client's side: try each plausible number of plaintext messages and
	// keep the one that accounts for the most bytes.
	best := -1
	s0sawExtraBig := false
	var bestMsgs []nroMessage
	for clear := 1; clear <= 3; clear++ {
		up := &nroReader{b: toServer}
		var msgs []nroMessage
		ok := true
		for i := 0; i < clear; i++ {
			cmd, data, wire, err := up.message(false, long)
			if err != nil {
				ok = false
				break
			}
			msgs = append(msgs, nroMessage{dir: "C>S", cmd: cmd, data: data, wire: wire, clear: true})
		}
		if !ok {
			continue
		}
		up.key, up.idx = key, 0
		msgs = append(msgs, drain(up, false, long)...)
		if up.off > best {
			best, bestMsgs = up.off, msgs
		}
	}
	if best < 0 {
		return nil, errors.New("client stream does not start with a plaintext message")
	}

	for _, m := range downMsgs {
		if m.cmd == 12 {
			s0sawExtraBig = true
		}
	}
	s := &nroSession{key: key, longVersion: long, sawExtraBig: s0sawExtraBig, tail: map[string]int{
		"C>S": len(toServer) - best,
		"S>C": len(toClient) - down.off,
	}}
	s.msgs = append(stamp(bestMsgs, upMarks), stamp(downMsgs, downMarks)...)
	// A desynchronised key eats the rest of the stream in one bogus message,
	// so a large tail means the guess was wrong, not that the capture was cut.
	if s.tail["S>C"] > 4096 {
		return nil, fmt.Errorf("server stream left %d bytes undecoded", s.tail["S>C"])
	}
	return s, nil
}

func drain(r *nroReader, fromServer, long bool) []nroMessage {
	var out []nroMessage
	dir := "C>S"
	if fromServer {
		dir = "S>C"
	}
	for {
		cmd, data, wire, err := r.message(fromServer, long)
		if err != nil {
			return out
		}
		out = append(out, nroMessage{dir: dir, cmd: cmd, data: data, wire: wire})
	}
}

// stamp dates each message by the read its first byte fell in. Messages come
// back in stream order, so walking the marks alongside them is enough.
func stamp(msgs []nroMessage, marks []mark) []nroMessage {
	off := 0
	for i := range msgs {
		if len(marks) > 0 {
			msgs[i].when = when(marks, off)
		}
		off += msgs[i].wire
	}
	return msgs
}

// nroText pulls the strings out of a payload. The game writes them with Java's
// writeUTF: two bytes of length then the bytes themselves, so a length that
// lands exactly on a run of readable text is a string, not a coincidence.
func nroText(b []byte) []string {
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
