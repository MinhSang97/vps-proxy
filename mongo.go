// Storing the capture in MongoDB.
//
// The proxy sits in the middle of a live game session, so nothing here may
// hold up the bytes going through. Records are handed to a buffered channel
// and one goroutine batches them into the database. When that channel is full
// the record is dropped and counted: a slow database must cost lines in the
// log, never lag in the game.
package main

import (
	"context"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// logRecord is one row. A packet carries the bytes, an event carries a line of
// the ordinary log, and both live in one collection so a session reads back in
// the order it happened.
type logRecord struct {
	At    time.Time `bson:"at"`
	Seq   int64     `bson:"seq"` // breaks ties inside one run, which timestamps alone cannot
	Kind  string    `bson:"kind"`
	Proto string    `bson:"proto,omitempty"`
	Peer  string    `bson:"peer,omitempty"`
	Dir   string    `bson:"dir,omitempty"`
	N     int       `bson:"n,omitempty"`
	Data  []byte    `bson:"data,omitempty"`
	Line  string    `bson:"line,omitempty"`
}

type mongoSink struct {
	ch      chan logRecord
	client  *mongo.Client
	coll    *mongo.Collection
	seq     atomic.Int64
	dropped atomic.Int64
	done    chan struct{}
}

// openMongo connects and starts the writer. It fails fast rather than letting
// the proxy run while quietly recording nothing.
func openMongo(uri, db, coll string) (*mongoSink, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	opts := options.Client().ApplyURI(uri).SetServerSelectionTimeout(8 * time.Second)
	// Credentials as settings of their own rather than buried in the URI. A
	// password holding @ : / ? or # has to be percent-encoded to survive a
	// URI, and getting that wrong surfaces as "authentication failed", which
	// reads exactly like a wrong password and sends you looking in the wrong
	// place. Credentials already inside the URI still work.
	if user := os.Getenv("MONGO_USERNAME"); user != "" {
		opts.SetAuth(options.Credential{Username: user, Password: os.Getenv("MONGO_PASS")})
	}
	client, err := mongo.Connect(opts)
	if err != nil {
		return nil, err
	}
	if err := client.Ping(ctx, nil); err != nil {
		client.Disconnect(context.Background())
		return nil, err
	}
	s := &mongoSink{
		ch:     make(chan logRecord, 4096),
		client: client,
		coll:   client.Database(db).Collection(coll),
		done:   make(chan struct{}),
	}
	go s.run()
	return s, nil
}

// run batches whatever has arrived. A batch goes out when it is full or when a
// second has passed, so a quiet session still reaches the database promptly.
func (s *mongoSink) run() {
	defer close(s.done)
	const batchSize = 200
	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	batch := make([]any, 0, batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if _, err := s.coll.InsertMany(ctx, batch); err != nil {
			log.Printf("mongo  insert failed, %d records lost: %v", len(batch), err)
		}
		cancel()
		batch = batch[:0]
	}
	for {
		select {
		case r, ok := <-s.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, r)
			if len(batch) >= batchSize {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

// put never blocks. Dropping is the correct answer here: the alternative is
// stalling a socket the game is waiting on.
func (s *mongoSink) put(r logRecord) {
	r.At, r.Seq = time.Now(), s.seq.Add(1)
	select {
	case s.ch <- r:
	default:
		s.dropped.Add(1)
	}
}

// Write lets the sink stand in as a log destination: one call is one line.
func (s *mongoSink) Write(b []byte) (int, error) {
	s.put(logRecord{Kind: "event", Line: strings.TrimRight(string(b), "\n")})
	return len(b), nil
}

// close drains what is queued and reports anything that never made it, so a
// gap in the capture is never silent.
func (s *mongoSink) close() {
	close(s.ch)
	<-s.done
	if n := s.dropped.Load(); n > 0 {
		log.Printf("mongo  %d records were dropped because the writer could not keep up", n)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.client.Disconnect(ctx)
}
