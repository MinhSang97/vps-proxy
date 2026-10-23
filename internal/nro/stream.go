package nro

// Message is one decoded game message.
type Message struct {
	Dir  string // "C>S" client to server, or "S>C" server to client
	Cmd  int8
	Data []byte // decrypted payload, the data inside the command
}

func (m Message) Name() string { return Name(m.Cmd) }

// Conn decodes both directions of one live session as bytes cross the proxy.
// Feed it each chunk and it returns whole messages the moment they complete,
// buffering the partial tail until the rest arrives.
//
// The key is taken from the server's -27 reply, so a connection watched from
// its first byte decodes with no configuration. A connection whose first
// message in either direction is not the -27 handshake is taken to be something
// else (a mid-session join, or plain TLS) and is abandoned, so garbage is never
// emitted; the raw capture is the fallback for those.
type Conn struct {
	long bool
	key  []byte
	bad  bool
	up   stream // C>S
	down stream // S>C
}

type stream struct {
	buf     []byte
	idx     int
	keyOn   bool
	needKey bool // past the handshake, waiting for the key before decoding more
	seenAny bool
}

// NewConn makes a decoder. long is the client-version flag (2.4.2+), which only
// changes how a few server commands frame their length.
func NewConn(long bool) *Conn { return &Conn{long: long} }

// Feed appends one chunk for one direction and returns the messages that became
// complete. toServer reports whether the bytes travel client to server.
func (c *Conn) Feed(toServer bool, b []byte) []Message {
	if c.bad {
		return nil
	}
	if toServer {
		c.up.buf = append(c.up.buf, b...)
	} else {
		c.down.buf = append(c.down.buf, b...)
	}
	hadKey := c.key != nil
	out := c.drain(toServer)
	// The key only ever appears on S>C. The moment it does, the client stream
	// may hold encrypted bytes that were waiting for it, so drain that side too.
	if !hadKey && c.key != nil && !c.bad {
		out = append(out, c.drain(!toServer)...)
	}
	return out
}

func (c *Conn) drain(toServer bool) []Message {
	s := &c.down
	dir := "S>C"
	if toServer {
		s = &c.up
		dir = "C>S"
	}
	var out []Message
	for !c.bad {
		if s.needKey && !s.keyOn {
			if c.key == nil {
				break // handshake done on this side, key not here yet
			}
			s.keyOn, s.idx, s.needKey = true, 0, false
		}
		r := &Reader{B: s.buf, Idx: s.idx}
		if s.keyOn {
			r.Key = c.key
		}
		cmd, data, wire, err := r.Message(!toServer, c.long)
		if err != nil {
			break // need more bytes
		}
		// Before the key, the only thing that may cross is the -27 handshake.
		// Anything else means this is not an NRO session seen from its start.
		if !s.seenAny && cmd != GetKey {
			c.bad = true
			return nil
		}
		s.seenAny = true
		s.buf = s.buf[wire:]
		s.idx = r.Idx
		out = append(out, Message{Dir: dir, Cmd: cmd, Data: append([]byte(nil), data...)})

		if cmd == GetKey && !s.keyOn {
			if !toServer { // the server reply carries the key
				if k, e := Key(data); e == nil {
					c.key = k
				}
			}
			s.needKey = true
			if c.key != nil {
				s.keyOn, s.idx, s.needKey = true, 0, false
			}
		}
	}
	return out
}
