package main

import (
	"context"
	"os"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// TestMongoMessageRowRoundTrip checks that a decoded message row, cmd pointer
// and all, survives a real insert and read. It only runs when MONGO_TEST_URI is
// set, so the normal suite does not need a database.
func TestMongoMessageRowRoundTrip(t *testing.T) {
	uri := os.Getenv("MONGO_TEST_URI")
	if uri == "" {
		t.Skip("set MONGO_TEST_URI to run against a real mongo")
	}
	db, coll := "vps_proxy_rt_test", "logs"

	// Clean slate.
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
	cmd := int8(-72)
	sink.put(logRecord{Kind: "message", Proto: "tcp", Peer: "game:14445", Dir: "C>S",
		Cmd: &cmd, Name: "CHAT_PLAYER", N: 5, Dump: "hexdump here", Text: []string{"hello"}})
	sink.close() // flushes

	var got struct {
		Kind string   `bson:"kind"`
		Dir  string   `bson:"dir"`
		Cmd  *int8    `bson:"cmd"`
		Name string   `bson:"name"`
		Dump string   `bson:"dump"`
		Text []string `bson:"text"`
	}
	err = cli.Database(db).Collection(coll).FindOne(ctx, bson.M{"kind": "message"}).Decode(&got)
	if err != nil {
		t.Fatalf("read back failed: %v", err)
	}
	if got.Cmd == nil || *got.Cmd != -72 {
		t.Errorf("cmd round-tripped as %v, want -72", got.Cmd)
	}
	if got.Name != "CHAT_PLAYER" || got.Dir != "C>S" || len(got.Text) != 1 || got.Text[0] != "hello" {
		t.Errorf("row = %+v, want CHAT_PLAYER C>S hello", got)
	}
	cli.Database(db).Collection(coll).Drop(ctx)
}
