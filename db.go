package main

import (
	"context"
	"errors"
	"fmt"

	"cloud.google.com/go/datastore"
	"golang.org/x/crypto/bcrypt"
)

// UserData contains the user's persisted data
type UserData struct {
	ID string
	Hash string
	Token string
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

func writeToDB(ud *UserData) error {
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

func readUserData(query *datastore.Query) (*UserData, error) {
	if query == nil {
		return nil, errors.New("nil query")
	}

	dst  := []*UserData{}
	_, err := getAll(context.TODO(), query, &dst)
	
	if err != nil {
		return nil, err
	}

	if (len(dst) == 0) {
		return nil, fmt.Errorf("No Results for Query '%v'", query)
	}

	if (len(dst) != 1) {
		return nil, fmt.Errorf("Got %v results for Query '%v'", len(dst), query)
	}

	return dst[0], nil
}

func readTokenByID(id string) (*UserData, error) {
	if id == "" {
		return nil, errors.New("empty id")
	}

	q := newQuery("USER").Filter("ID =", id).Project("ID", "Token")

	return readUserData(q)
}

func readComplete(id string) (*UserData, error) {
	if id == "" {
		return nil, errors.New("empty id")
	}

	q := newQuery("USER").Filter("ID =", id)

	return readUserData(q)
}
