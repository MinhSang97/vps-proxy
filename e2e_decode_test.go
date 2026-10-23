package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"vps-proxy/internal/nro"
)

// TestEndToEndLiveDecode pushes a real NRO handshake and one message each way
// through the proxy's HTTP CONNECT tunnel and checks the decoded message rows
// land in mongo. Guarded by MONGO_TEST_URI so the normal suite needs no DB.
func TestEndToEndLiveDecode(t *testing.T) {
	uri := os.Getenv("MONGO_TEST_URI")
	if uri == "" {
		t.Skip("set MONGO_TEST_URI to run the end-to-end decode test")
	}
	db, coll := "vps_proxy_e2e_test", "logs"
	cli, err := mongo.Connect(options.Client().ApplyURI(uri).SetServerSelectionTimeout(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	defer cli.Disconnect(ctx)
	cli.Database(db).Collection(coll).Drop(ctx)

	sink, err := openMongo(uri, db, coll)
	if err != nil {
		t.Fatal(err)
	}
	defer func(d string, m *mongoSink) { dumpDir, mongoLog = d, m }(dumpDir, mongoLog)
	dumpDir, mongoLog, nroLong = "mongo", sink, true

	// Build the two streams with the real encoding.
	key := []byte("rose")
	down := &nroStream{key: key}
	down.msg(nro.GetKey, []byte{byte(len(key)), key[0], key[1] ^ key[0], key[2] ^ key[1], key[3] ^ key[2]})
	down.on = true
	down.msg(-29, nroUTF("Dang nhap thanh cong"))
	up := &nroStream{key: key}
	up.msg(nro.GetKey, nil)
	up.on = true
	up.msg(-72, nroUTF("chao ca nha"))

	// A loopback "game server": write its stream, read the client's.
	gl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer gl.Close()
	go func() {
		c, err := gl.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write(down.out)
		io.Copy(io.Discard, c)
	}()

	// The proxy.
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: newHandler("u:p")}
	go srv.Serve(&sniffListener{Listener: pl, cred: "u:p"})
	defer srv.Close()

	// Client: CONNECT through the proxy to the game server, then exchange.
	pc, err := net.Dial("tcp", pl.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	auth := base64.StdEncoding.EncodeToString([]byte("u:p"))
	fmt.Fprintf(pc, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		gl.Addr(), gl.Addr(), auth)
	br := bufio.NewReader(pc)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading CONNECT reply: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	pc.Write(up.out)
	io.ReadAll(io.LimitReader(br, int64(len(down.out)))) // drain server bytes
	pc.Close()

	time.Sleep(300 * time.Millisecond) // let the proxy finish copying
	sink.close()                       // flush to mongo

	n, err := cli.Database(db).Collection(coll).CountDocuments(ctx, bson.M{"kind": "message"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("stored %d message rows, want 4 (two each way)", n)
	}
	// Spot-check one decoded payload is human-readable again.
	var row struct {
		Data []byte `bson:"data"`
	}
	err = cli.Database(db).Collection(coll).FindOne(ctx, bson.M{"kind": "message", "cmd": -29}).Decode(&row)
	if err != nil {
		t.Fatal(err)
	}
	if ts := nro.Text(row.Data); len(ts) == 0 || ts[0] != "Dang nhap thanh cong" {
		t.Errorf("decoded -29 payload = %q, want 'Dang nhap thanh cong'", nro.Text(row.Data))
	}
	cli.Database(db).Collection(coll).Drop(ctx)
}
