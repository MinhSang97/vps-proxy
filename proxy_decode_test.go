package main

import (
	"encoding/binary"
	"testing"

	"vps-proxy/internal/nro"
)

// nroStream builds one direction the way the game encodes it, so the live
// decoder in the proxy is tested against the real encoding.
type nroStream struct {
	out []byte
	key []byte
	idx int
	on  bool
}

func (w *nroStream) put(b byte) byte {
	if !w.on {
		return b
	}
	c := w.key[w.idx] ^ b
	w.idx = (w.idx + 1) % len(w.key)
	return c
}

func (w *nroStream) msg(cmd int8, data []byte) {
	w.out = append(w.out, w.put(byte(cmd)))
	w.out = append(w.out, w.put(byte(len(data)>>8)), w.put(byte(len(data))))
	for _, b := range data {
		w.out = append(w.out, w.put(b))
	}
}

func nroUTF(s string) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(s))), s...)
}

// TestLiveDecodeStoresMessageRows proves the proxy, while capturing raw bytes to
// the sink, also decodes the NRO stream and queues one message row per message
// with its direction, command and decrypted payload.
func TestLiveDecodeStoresMessageRows(t *testing.T) {
	key := []byte("rose")

	down := &nroStream{key: key}
	down.msg(nro.GetKey, []byte{byte(len(key)), key[0], key[1] ^ key[0], key[2] ^ key[1], key[3] ^ key[2]})
	down.on = true
	down.msg(-29, nroUTF("Dang nhap thanh cong"))

	up := &nroStream{key: key}
	up.msg(nro.GetKey, nil)
	up.on = true
	up.msg(-72, nroUTF("chao ca nha"))

	sink := &mongoSink{ch: make(chan logRecord, 100)}
	d := &dumpFile{sink: sink, conn: nro.NewConn(true), proto: "tcp", peer: "dragonsuper3.teamobi.com:14445"}

	// Server first so the key is known, then client.
	d.write(d.peer, "S>C", down.out)
	d.write(d.peer, "C>S", up.out)
	close(sink.ch)

	var packets, messages int
	type got struct {
		dir  string
		cmd  int8
		text string
	}
	var msgs []got
	for r := range sink.ch {
		switch r.Kind {
		case "packet":
			packets++
		case "message":
			messages++
			if r.Cmd == nil {
				t.Fatalf("message row has no cmd: %+v", r)
			}
			text := ""
			if ts := nro.Text(r.Data); len(ts) > 0 {
				text = ts[0]
			}
			msgs = append(msgs, got{r.Dir, *r.Cmd, text})
		}
	}

	if packets != 2 {
		t.Errorf("stored %d packet rows, want 2 (raw is kept alongside)", packets)
	}
	want := []got{
		{"S>C", nro.GetKey, ""},
		{"S>C", -29, "Dang nhap thanh cong"},
		{"C>S", nro.GetKey, ""},
		{"C>S", -72, "chao ca nha"},
	}
	if messages != len(want) {
		for _, m := range msgs {
			t.Logf("  %s cmd=%d %q", m.dir, m.cmd, m.text)
		}
		t.Fatalf("stored %d message rows, want %d", messages, len(want))
	}
	for i, w := range want {
		if msgs[i] != w {
			t.Errorf("message row %d = %+v, want %+v", i, msgs[i], w)
		}
	}
}

// TestLiveDecodeSkipsNonNRO proves a tunnel that is not the game (plain TLS) is
// captured raw but produces no message rows, so Mongo is not filled with garbage.
func TestLiveDecodeSkipsNonNRO(t *testing.T) {
	sink := &mongoSink{ch: make(chan logRecord, 100)}
	d := &dumpFile{sink: sink, conn: nro.NewConn(true), proto: "tcp", peer: "api.ipify.org:443"}

	tls := []byte{0x16, 0x03, 0x01}
	tls = append(tls, make([]byte, 769)...)
	d.write(d.peer, "C>S", tls)
	close(sink.ch)

	for r := range sink.ch {
		if r.Kind == "message" {
			t.Fatalf("TLS traffic produced a message row: cmd set=%v", r.Cmd != nil)
		}
	}
}
