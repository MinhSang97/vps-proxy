// Reading a capture back out of MongoDB. A row carries the same fields a log
// line does, so once it is turned into a record the rest of the tool cannot
// tell where it came from.
package main

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func readMongo(uri, db, coll, only string) ([]record, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := mongo.Connect(options.Client().ApplyURI(uri).SetServerSelectionTimeout(8 * time.Second))
	if err != nil {
		return nil, err
	}
	defer client.Disconnect(context.Background())

	filter := bson.M{"kind": "packet"}
	if only != "" {
		filter["peer"] = only
	}
	// Timestamps alone cannot order rows written in the same millisecond, which
	// a busy session does constantly, so the sequence settles it.
	sort := options.Find().SetSort(bson.D{{Key: "at", Value: 1}, {Key: "seq", Value: 1}})
	cur, err := client.Database(db).Collection(coll).Find(ctx, filter, sort)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var out []record
	for cur.Next(ctx) {
		var r struct {
			At    time.Time `bson:"at"`
			Proto string    `bson:"proto"`
			Peer  string    `bson:"peer"`
			Dir   string    `bson:"dir"`
			Data  []byte    `bson:"data"`
		}
		if err := cur.Decode(&r); err != nil {
			return nil, err
		}
		out = append(out, record{
			when:  r.At.Local().Format("2006/01/02 15:04:05.000"),
			proto: r.Proto,
			peer:  r.Peer,
			dir:   r.Dir,
			data:  r.Data,
		})
	}
	return out, cur.Err()
}
