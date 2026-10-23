// Offline NRO decoding for a whole capture. The wire primitives live in
// internal/nro; this file holds the orchestration that is specific to reading a
// finished capture: finding the handshake, trying both client versions, and
// realigning a capture that started mid-session.
package main

import (
	"errors"
	"fmt"

	"vps-proxy/internal/nro"
)

// nroMessage is one decoded game message with its place in the capture.
type nroMessage struct {
	when  string
	dir   string
	cmd   int8
	data  []byte
	wire  int  // bytes this message took on the wire, header included
	clear bool // the handshake messages travel before the key exists
}

func (m nroMessage) name() string { return nro.Name(m.cmd) }

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
	r := &nro.Reader{B: b, Off: bestSkip, Key: key, Idx: bestPhase}
	msgs := drain(r, fromServer, long)

	// Matching a few messages proves nothing. There are a thousand places to
	// start and four key phases to try, and roughly a quarter of all byte
	// values name a real command, so random traffic will always produce a
	// short lucky chain: TLS once decoded here as PLAYER_ATTACK_PLAYER. Real
	// traffic is different in kind, not degree, because every message lands
	// exactly on the next one all the way to the end of the stream.
	rest := len(b) - bestSkip
	if len(msgs) < minResyncRun || (r.Off-bestSkip)*10 < rest*9 {
		return nil, 0, len(b)
	}
	return msgs, r.Off, bestSkip
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
	r := &nro.Reader{B: b, Off: skip, Key: key, Idx: phase}
	n := 0
	for n < want {
		cmd, _, _, err := r.Message(fromServer, long)
		if err != nil {
			break
		}
		if n == 0 && !nro.Commands[cmd] {
			return 0
		}
		n++
	}
	return n
}

func decodeWith(toServer, toClient []byte, upMarks, downMarks []mark, long bool) (*nroSession, error) {
	// The server's side: plaintext until the -27 reply, encrypted after it.
	down := &nro.Reader{B: toClient}
	var downMsgs []nroMessage
	var key []byte
	for key == nil {
		cmd, data, wire, err := down.Message(true, long)
		if err != nil {
			return nil, fmt.Errorf("no key handshake in the server stream: %w", err)
		}
		downMsgs = append(downMsgs, nroMessage{dir: "S>C", cmd: cmd, data: data, wire: wire, clear: true})
		if cmd == nro.GetKey {
			if key, err = nro.Key(data); err != nil {
				return nil, err
			}
		}
	}
	down.Key, down.Idx = key, 0
	downMsgs = append(downMsgs, drain(down, true, long)...)

	// The client's side: try each plausible number of plaintext messages and
	// keep the one that accounts for the most bytes.
	best := -1
	sawExtraBig := false
	var bestMsgs []nroMessage
	for clear := 1; clear <= 3; clear++ {
		up := &nro.Reader{B: toServer}
		var msgs []nroMessage
		ok := true
		for i := 0; i < clear; i++ {
			cmd, data, wire, err := up.Message(false, long)
			if err != nil {
				ok = false
				break
			}
			msgs = append(msgs, nroMessage{dir: "C>S", cmd: cmd, data: data, wire: wire, clear: true})
		}
		if !ok {
			continue
		}
		up.Key, up.Idx = key, 0
		msgs = append(msgs, drain(up, false, long)...)
		if up.Off > best {
			best, bestMsgs = up.Off, msgs
		}
	}
	if best < 0 {
		return nil, errors.New("client stream does not start with a plaintext message")
	}

	for _, m := range downMsgs {
		if m.cmd == 12 {
			sawExtraBig = true
		}
	}
	s := &nroSession{key: key, longVersion: long, sawExtraBig: sawExtraBig, tail: map[string]int{
		"C>S": len(toServer) - best,
		"S>C": len(toClient) - down.Off,
	}}
	s.msgs = append(stamp(bestMsgs, upMarks), stamp(downMsgs, downMarks)...)
	// A desynchronised key eats the rest of the stream in one bogus message,
	// so a large tail means the guess was wrong, not that the capture was cut.
	if s.tail["S>C"] > 4096 {
		return nil, fmt.Errorf("server stream left %d bytes undecoded", s.tail["S>C"])
	}
	return s, nil
}

func drain(r *nro.Reader, fromServer, long bool) []nroMessage {
	var out []nroMessage
	dir := "C>S"
	if fromServer {
		dir = "S>C"
	}
	for {
		cmd, data, wire, err := r.Message(fromServer, long)
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
