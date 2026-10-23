// Reading a capture back out of MongoDB. A row carries the same fields a log
// line does, so once it is turned into a record the rest of the tool cannot
// tell where it came from.
package main

import (
	"context"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"vps-proxy/internal/nro"
)

func readMongo(uri, db, coll, only string) ([]record, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	opts := options.Client().ApplyURI(uri).SetServerSelectionTimeout(8 * time.Second)
	// Credentials as their own settings, matching the proxy: a password with
	// special characters would otherwise have to be percent-encoded into the URI.
	if user := os.Getenv("MONGO_USERNAME"); user != "" {
		opts.SetAuth(options.Credential{Username: user, Password: os.Getenv("MONGO_PASS")})
	}
	client, err := mongo.Connect(opts)
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

// backfillText fills the text field on message rows captured before that field
// existed, so their readable strings (logins, chat) show up in Atlas too. It
// only touches rows that have no text yet and whose payload actually decodes to
// some text, and never changes the stored data. Returns how many rows it set.
func backfillText(uri, db, coll string) (int, error) {
	opts := options.Client().ApplyURI(uri).SetServerSelectionTimeout(8 * time.Second)
	if user := os.Getenv("MONGO_USERNAME"); user != "" {
		opts.SetAuth(options.Credential{Username: user, Password: os.Getenv("MONGO_PASS")})
	}
	client, err := mongo.Connect(opts)
	if err != nil {
		return 0, err
	}
	ctx := context.Background()
	defer client.Disconnect(ctx)
	c := client.Database(db).Collection(coll)

	cur, err := c.Find(ctx, bson.M{"kind": "message", "text": bson.M{"$exists": false}})
	if err != nil {
		return 0, err
	}
	defer cur.Close(ctx)

	var models []mongo.WriteModel
	for cur.Next(ctx) {
		var r struct {
			ID   bson.ObjectID `bson:"_id"`
			Data []byte        `bson:"data"`
		}
		if err := cur.Decode(&r); err != nil {
			return 0, err
		}
		texts := nro.Text(r.Data)
		if len(texts) == 0 {
			continue
		}
		models = append(models, mongo.NewUpdateOneModel().
			SetFilter(bson.M{"_id": r.ID}).
			SetUpdate(bson.M{"$set": bson.M{"text": texts}}))
	}
	if err := cur.Err(); err != nil {
		return 0, err
	}
	if len(models) == 0 {
		return 0, nil
	}
	res, err := c.BulkWrite(ctx, models)
	if err != nil {
		return 0, err
	}
	return int(res.ModifiedCount), nil
}
