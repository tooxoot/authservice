package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

var privateKey *rsa.PrivateKey

func readRSAKEY(keyString string) (*rsa.PrivateKey, error) {
	if keyString == "" {
		return nil, errors.New("Empty RSAKEY")
	}

	block, _ := pem.Decode([]byte(keyString))

	if block == nil {
		return nil, errors.New("Unable to decode RSAKEY")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)

	if err != nil {
		return nil, fmt.Errorf("Unable to parse RSAKEY: %w", err)
	}

	return key, nil
}

func signClaims(c *Claims) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodRS256, c).SignedString(privateKey)
}

func parse(signedString string) (*jwt.Token, *Claims, error) {
	claims := &Claims{}
	keyFunc := func(token *jwt.Token) (interface{}, error) { return &privateKey.PublicKey, nil }
	token, err := jwt.ParseWithClaims(signedString, claims, keyFunc)

	return token, claims, err
}
