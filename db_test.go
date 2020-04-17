package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"cloud.google.com/go/datastore"
	"golang.org/x/crypto/bcrypt"
)

func TestNewUserData(T *testing.T) {
	expectations := map[string]bool{}

	generateFromPassword = func (b []byte, c int) ([]byte, error) { 
		expectations["Call generateFromPassword"] = true
		expectations["Pass password to generateFromPassword"] = string(b) == "SomePW"
		expectations["Pass MinCost"] = c == bcrypt.MinCost
		return []byte("generatedHash"), nil 
	}
	userData := NewUserData("SomeID", "SomePW")
	expectations["Return correct Userdata"] = fmt.Sprintf("%+v", userData) == "&{ID:SomeID Hash:generatedHash Token: key:<nil>}"

	generateFromPassword = func (b []byte, c int) ([]byte, error) { 
		return nil, errors.New("") 
	}	
	expectations["Return nil on hashing error"] = NewUserData("SomeID", "SomePW") == nil

	CheckExpectations(expectations, T)
}

func TestCompare(T *testing.T) {
	expectations := map[string]bool{}
	usedPW := "SomePW"

	var userData *UserData
	expectations["Return false on nil UserData"] = userData.compare(usedPW)

	userData = &UserData{"ID1", "Hash1", "Token1", nil}


	compareHashAndPassword = func(b1 []byte, b2 []byte) error { 
		expectations["Call compareHashAndPassword"] = true
		expectations["Pass Hash"] = string(b1) == userData.Hash
		expectations["Pass Password"] = string(b1) == usedPW
		return nil 
	}
	expectations["Return true on nil error"] = userData.compare(usedPW)
	
	compareHashAndPassword = func(_ []byte, _ []byte) error { 
		return errors.New("") 
	}
	expectations["Return false on error"] = userData.compare(usedPW)
}



func TestWriteToDB(T *testing.T) {
	T.Run("Nil UserData", func(t *testing.T){
		expectations := map[string]bool{}
		var userData *UserData
		
		expectations["Nil error on nil UserData"] = writeToDB(userData) == nil
	
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
		
		expectations["Nil error on valid UserData"] = writeToDB(userData) == nil 
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
		
		expectations["Nil error on valid UserData"] = writeToDB(userData) == nil 
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
		
		expectations["Return error from put"] = writeToDB(userData) == thrownError 
		expectations["Nil key on UserData"] = userData.key == nil 
		
		CheckExpectations(expectations, T)
	})
}

func TestReadUserData(T *testing.T) {
	T.Run("Nil Query", func(t *testing.T){
		expectations := map[string]bool{}
		
		result, err := readUserData(nil)

		expectations["Nil result on nil Query"] =  result == nil
		expectations["Error on nil Query"] =  err.Error() == "nil query" 
	
		CheckExpectations(expectations, t)
	})

	T.Run("Valid UserData", func(t *testing.T){
		expectations := map[string]bool{}
		userDataFromRead := &UserData{"ID1", "Hash1", "Token1", nil}
		query := &datastore.Query{}
	
		getAll = func(ctx context.Context, q *datastore.Query, dst interface{}) ([]*datastore.Key, error) {
			expectations["Call getAll"] = true
			expectations["Use query with UserDataId and limit of 1"] = q == query
			slice, ok := dst.(*[]*UserData)
			expectations["Use type *[]*UserData in getAll dst"] = ok
			*slice = append(*slice, userDataFromRead)
			return nil, nil	
		}

		result, err := readUserData(query)
	
		expectations["Return UserData from getAll"] = result == userDataFromRead
		expectations["Nil Error on valid UserData"] = err == nil 
	
		CheckExpectations(expectations, T)
	})

	T.Run("Error on getAll", func(t *testing.T){
		expectations := map[string]bool{}
		thrownError := errors.New("")
		
		newQuery = func(kind string) *datastore.Query {
			expectations["Call newQuery"] = true
			return datastore.NewQuery(kind)
		}
	
		getAll = func(ctx context.Context, q *datastore.Query, dst interface{}) ([]*datastore.Key, error) {
			expectations["Call getAll"] = true
			return nil, thrownError	
		}
	
		result, err := readUserData(&datastore.Query{})

		expectations["Do not return UserData"] = result == nil
		expectations["Return error from getAll"] = err == thrownError 
	
		CheckExpectations(expectations, T)
	})

	T.Run("No results", func(t *testing.T){
		expectations := map[string]bool{}
		
		newQuery = func(kind string) *datastore.Query {
			expectations["Call newQuery"] = true
			return datastore.NewQuery(kind)
		}
	
		getAll = func(ctx context.Context, q *datastore.Query, dst interface{}) ([]*datastore.Key, error) {
			expectations["Call getAll"] = true
			return nil, nil	
		}
	
		result, err := readUserData(&datastore.Query{})

		expectations["Do not return UserData"] = result == nil
		expectations["Return error on empty result list"] = err.Error() == fmt.Sprintf("No Results for Query '%v'", &datastore.Query{})
	
		CheckExpectations(expectations, T)
	})

	T.Run("Too many results", func(t *testing.T){
		expectations := map[string]bool{}
		userDataFromRead := &UserData{"ID1", "Hash1", "Token1", nil}
		
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
	
		result, err := readUserData(&datastore.Query{})
	
		expectations["Do not return UserData"] = result == nil
		expectations["Return error on empty result list"] = err.Error() == fmt.Sprintf("Got 2 results for Query '%v'", &datastore.Query{})
	
		CheckExpectations(expectations, T)
	})
}

func TestReadTokenByID(T *testing.T) {
	T.Run("Empty String", func(t *testing.T){
		expectations := map[string]bool{}
		
		result, err := readTokenByID("")

		expectations["Return nil result"] =  result == nil
		expectations["Return error"] =  err.Error() == "empty id" 
	
		CheckExpectations(expectations, t)
	})

	T.Run("Valid id", func(t *testing.T){
		expectations := map[string]bool{}
		userDataFromRead := &UserData{"ID1", "Hash1", "Token1", nil}
		

		getAll = func(ctx context.Context, q *datastore.Query, dst interface{}) ([]*datastore.Key, error) {
			expectations["Call getAll"] = true
			expectedQuery := newQuery("USER").Filter("ID =", "ID1").Project("ID", "Token")
			expectations["Use projected id query"] = fmt.Sprint(q) == fmt.Sprint(expectedQuery)
			slice, _ := dst.(*[]*UserData)
			*slice = append(*slice, userDataFromRead)
			return nil, nil	
		}
		
		result, err := readTokenByID("ID1")

		expectations["Return read UserData"] = fmt.Sprint(result) == fmt.Sprint(userDataFromRead)
		expectations["Return nil error"] =  err == nil
	
		CheckExpectations(expectations, t)
	})
}

func TestReadComplete(T *testing.T) {
	T.Run("Valid id", func(t *testing.T){
		expectations := map[string]bool{}
		userDataFromRead := &UserData{"ID1", "Hash1", "Token1", nil}
		

		getAll = func(ctx context.Context, q *datastore.Query, dst interface{}) ([]*datastore.Key, error) {
			expectations["Call getAll"] = true
			expectedQuery := newQuery("USER").Filter("ID =", "ID1")
			expectations["Use projected id query"] = fmt.Sprint(q) == fmt.Sprint(expectedQuery)
			slice, _ := dst.(*[]*UserData)
			*slice = append(*slice, userDataFromRead)
			return nil, nil	
		}
		
		result, err := readComplete("ID1")

		expectations["Return read UserData"] = fmt.Sprint(result) == fmt.Sprint(userDataFromRead)
		expectations["Return nil error"] =  err == nil
	
		CheckExpectations(expectations, t)
	})
}