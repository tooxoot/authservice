package main

import (
	"context"
	"fmt"

	"cloud.google.com/go/datastore"
	"golang.org/x/crypto/bcrypt"
)

// UserData contains the the user's persisted data
type UserData struct {
	ID string
	Hash string
	key *datastore.Key `datastore:"__key__"`
}

var generateFromPassword = bcrypt.GenerateFromPassword
var compareHashAndPassword = bcrypt.CompareHashAndPassword
var incompleteKey = datastore.IncompleteKey
var put func(ctx context.Context, key *datastore.Key, src interface{}) (*datastore.Key, error)
var getAll func(ctx context.Context, q *datastore.Query, dst interface{}) (keys []*datastore.Key, err error)
var newQuery = datastore.NewQuery

// NewUserData created a new UserData object
func NewUserData(id, pw string) *UserData {
	hash, err := generateFromPassword([]byte(pw), bcrypt.MinCost)
	
	if err != nil {
		return nil
	}

	return &UserData{
		ID: id,
		Hash: string(hash),
	}
}

func (ud *UserData) compare(pw string) bool {
	if ud == nil {
		return false
	}

	return nil == compareHashAndPassword([]byte(ud.Hash), []byte(pw))
}

func (ud *UserData) writeToDB() error {
	if ud == nil {
		return nil
	}
	usedKey :=ud.key

	if usedKey == nil {
		usedKey = incompleteKey("USER", nil)
	}

	k, err := put(context.TODO(), usedKey, ud)

	if err != nil  { 
		return err
	}

	ud.key = k

	return nil
}

func (ud *UserData) readFromDB() error {
	if ud == nil {
		return nil
	}

	q := newQuery("USER").Filter("ID =", ud.ID).Limit(1)
	dst  := []*UserData{}
	_, err := getAll(context.TODO(), q, &dst)
	
	if err != nil {
		return err
	}

	if (len(dst) == 0) {
		return fmt.Errorf("No Results for ID '%v'", ud.ID)
	}

	if (len(dst) != 1) {
		return fmt.Errorf("Got %v results for ID '%v'", len(dst), ud.ID)
	}

	*ud = *dst[0]

	return nil
}