package main

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Dependency for injection
var now = func() time.Time {
	return time.Now()
}

// Claims contain a go representation of the jwt claims in use.
type Claims struct {
	Exp time.Time `json:"exp"`
	Iat time.Time `json:"iat"`
	ID string `json:"id"`
	Iss string	`json:"iss"`
}

// NewClaims correctly produces new Claims object with given id. 
// Returns nil for empty id.
func NewClaims(id string) *Claims {
	if id == "" {
		return nil
	}

	currentTime := now()
	
	return &Claims{
		Exp: currentTime.Add(24 * time.Hour),
		Iat: currentTime,
		ID: id,
		Iss: "tooxoot",
	}
}

// Valid returns a jwt.ValidationError if the Claims object is invalid
func (c Claims) Valid() error {
	currentTime := now()
	if c.Iss != "tooxoot" {
		return jwt.NewValidationError("Issuer must be tooxoot", 1)
	}

	if c.Exp.Before(currentTime.Add(-5 * time.Minute)) {
		return jwt.NewValidationError("Token is expired", 2)
	}

	if c.Iat.After(currentTime.Add(5 * time.Minute)) {
		return jwt.NewValidationError("Token is issued in the future", 3)
	}

	if c.ID == "" {
		return jwt.NewValidationError("Token's ID is empty", 4)
	}

	return nil
}
