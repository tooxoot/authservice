package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"cloud.google.com/go/datastore"
)

func TestNewUserData(T *testing.T) {
	generateFromPassword = func (_ []byte, _ int) ([]byte, error) { return []byte("generatedHash"), nil }
	
	newUserData := NewUserData("SomeID", "SomePW")
	if newUserData.ID != "SomeID" || newUserData.Hash != "generatedHash" {
		T.Errorf("NewUserData failed! Valid ID and Hash expected. Expexted 'SomeID', 'generatedHash' got '%v', '%v'", newUserData.ID, newUserData.Hash)
	}

	generateFromPassword = func (b []byte, c int) ([]byte, error) { return []byte{}, errors.New("") }
	newUserData = NewUserData("SomeID", "SomePW")

	if newUserData != nil {
		T.Errorf("NewUserData failed! Expected nil on hashing error. Got '%+v'", newUserData)
	}
}

func TestCompare(T *testing.T) {
	userData := &UserData{}

	compareHashAndPassword = func(_ []byte, _ []byte) error { return nil }

	if !userData.compare("SomePW") {
		T.Errorf("UserData.compare failed! Expected true on nil error")
	}
	
	compareHashAndPassword = func(_ []byte, _ []byte) error { return errors.New("") }

	if userData.compare("SomePW") {
		T.Errorf("UserData.compare failed! Expected false on error")
	}

	userData = nil

	if userData.compare("SomePW") {
		T.Errorf("UserData.compare failed! Expected false on nil pointer")
	}
}

func CheckExpectations(expectations map[string]bool, T *testing.T) {
	for msg, ok := range expectations {
		if !ok {
			T.Errorf("Expectation `%v` not met!", msg)
		}
	}
}

func TestWriteToDB(T *testing.T) {
	T.Run("Nil UserData", func(t *testing.T){
		expectations := map[string]bool{}
		var userData *UserData
		
		expectations["Nil error on nil UserData"] = userData.writeToDB() == nil
	
		CheckExpectations(expectations, t)
	})

	T.Run("Valid UserData without key", func(t *testing.T){
		expectations := map[string]bool{}
		usedKey1, usedKey2 := &datastore.Key{}, &datastore.Key{}
		userData := &UserData{}
	
		incompleteKey = func(_ string, _ *datastore.Key) *datastore.Key {
			expectations["Call incompleteKey"] = true
			return usedKey1 
		} 
	
		put = func(ctx context.Context, key *datastore.Key, src interface{}) (*datastore.Key, error) {
			expectations["Call put"] = true
			expectations["Use key from inclompleteKey"] = key == usedKey1
			expectations["Use given UserData as src"] = src == userData
			return usedKey2, nil
		}
		
		expectations["Nil error on valid UserData"] = userData.writeToDB() == nil 
		expectations["Set UserData key to key from put"] = userData.key == usedKey2 
		
		CheckExpectations(expectations, T)
	})

	T.Run("Valid UserData with key", func(t *testing.T){
		expectations := map[string]bool{}
		usedKey1, usedKey2 := &datastore.Key{}, &datastore.Key{}
		userData := &UserData{}
		userData.key = usedKey1
	
		incompleteKey = func(_ string, _ *datastore.Key) *datastore.Key {
			expectations["Do not call incompleteKey"] = false
			return usedKey1 
		} 
	
		put = func(ctx context.Context, key *datastore.Key, src interface{}) (*datastore.Key, error) {
			expectations["Call put"] = true
			expectations["Use key from userData"] = key == usedKey1
			expectations["Use given UserData as src"] = src == userData
			return usedKey2, nil
		}
		
		expectations["Nil error on valid UserData"] = userData.writeToDB() == nil 
		expectations["Set UserData key to key from put"] = userData.key == usedKey2 
		
		CheckExpectations(expectations, T)
	})

	T.Run("Error on Put", func(t *testing.T){
		expectations := map[string]bool{}
		userData := &UserData{}
		thrownError := errors.New("")
	
		incompleteKey = func(_ string, _ *datastore.Key) *datastore.Key {
			expectations["Call incompleteKey"] = true
			return &datastore.Key{}
		} 
	
		put = func(ctx context.Context, key *datastore.Key, src interface{}) (*datastore.Key, error) {
			expectations["Call put"] = true
			return &datastore.Key{}, thrownError
		}
		
		expectations["Return error from put"] = userData.writeToDB() == thrownError 
		expectations["Nil key on UserData"] = userData.key == nil 
		
		CheckExpectations(expectations, T)
	})
}

func TestReadFromDB(T *testing.T) {
	T.Run("Nil UserData", func(t *testing.T){
		expectations := map[string]bool{}
		var userData *UserData
		
		expectations["Nil error on nil UserData"] = userData.readFromDB() == nil
	
		CheckExpectations(expectations, t)
	})

	T.Run("Valid UserData", func(t *testing.T){
		expectations := map[string]bool{}
		userDataFromRead := &UserData{"ID1", "Hash1", nil}
		userData := &UserData{"ID2", "Hash2", nil}
		
		newQuery = func(kind string) *datastore.Query {
			expectations["Call newQuery"] = true
			return datastore.NewQuery(kind)
		}
	
		getAll = func(ctx context.Context, q *datastore.Query, dst interface{}) ([]*datastore.Key, error) {
			expectations["Call getAll"] = true
			expectedQuery := fmt.Sprint(datastore.NewQuery("USER").Filter("ID =", "ID2").Limit(1))
			expectations["Use query with UserDataId and limit of 1"] = fmt.Sprint(q) == fmt.Sprint(expectedQuery)
			slice, ok := dst.(*[]*UserData)
			expectations["Use type *[]*UserData in getAll dst"] = ok
			*slice = append(*slice, userDataFromRead)
			return nil, nil	
		}
	
		expectations["Nil Error on valid UserData"] = userData.readFromDB() == nil 
		expectations["Set UserData on DB read"] = fmt.Sprint(userData) == fmt.Sprint(userDataFromRead)
	
		CheckExpectations(expectations, T)
	})

	T.Run("Error on getAll", func(t *testing.T){
		expectations := map[string]bool{}
		userData := &UserData{"ID2", "Hash2", nil}
		thrownError := errors.New("")
		
		newQuery = func(kind string) *datastore.Query {
			expectations["Call newQuery"] = true
			return datastore.NewQuery(kind)
		}
	
		getAll = func(ctx context.Context, q *datastore.Query, dst interface{}) ([]*datastore.Key, error) {
			expectations["Call getAll"] = true
			return nil, thrownError	
		}
	
		expectations["Return error from getAll"] = userData.readFromDB() == thrownError 
		expectations["Do not set UserData on Error"] = fmt.Sprint(userData) != "&{ ID1 Hash2 <nil>}"
	
		CheckExpectations(expectations, T)
	})

	T.Run("No results", func(t *testing.T){
		expectations := map[string]bool{}
		userData := &UserData{"ID1", "Hash2", nil}
		
		newQuery = func(kind string) *datastore.Query {
			expectations["Call newQuery"] = true
			return datastore.NewQuery(kind)
		}
	
		getAll = func(ctx context.Context, q *datastore.Query, dst interface{}) ([]*datastore.Key, error) {
			expectations["Call getAll"] = true
			return nil, nil	
		}
	
		expectations["Return error on empty result list"] = userData.readFromDB().Error() == "No Results for ID 'ID1'" 
		expectations["Do not set UserData on Error"] = fmt.Sprint(userData) != "&{ ID1 Hash2 <nil>}"
	
		CheckExpectations(expectations, T)
	})

	T.Run("Too many results", func(t *testing.T){
		expectations := map[string]bool{}
		userDataFromRead := &UserData{"ID1", "Hash1", nil}
		userData := &UserData{"ID1", "Hash2", nil}
		
		newQuery = func(kind string) *datastore.Query {
			expectations["Call newQuery"] = true
			return datastore.NewQuery(kind)
		}
	
		getAll = func(ctx context.Context, q *datastore.Query, dst interface{}) ([]*datastore.Key, error) {
			expectations["Call getAll"] = true
			slice, _ := dst.(*[]*UserData)
			*slice = append(*slice, userDataFromRead)
			*slice = append(*slice, userDataFromRead)
			return nil, nil	
		}
	
		expectations["Return error on empty result list"] = userData.readFromDB().Error() == "Got 2 results for ID 'ID1'" 
		expectations["Do not set UserData on Error"] = fmt.Sprint(userData) != "&{ ID1 Hash2 <nil>}"
	
		CheckExpectations(expectations, T)
	})
}