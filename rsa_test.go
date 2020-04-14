package main

import "testing"

func TestReadRSAKEY(T *testing.T) {

	T.Run("Empty RSAKEY", func(t *testing.T) {
		key, err := readRSAKEY("")
		expected := "Empty RSAKEY"

		if key != nil || err == nil || err.Error() != expected {
			T.Errorf("RSAKEY setup failed! Expected '<nil>', '%v' got '%v', '%v'", expected, key, err)
		}
	})

	T.Run("Undecodable RSAKEY", func(t *testing.T) {
		key, err := readRSAKEY("AAA")
		expected := "Unable to decode RSAKEY"

		if key != nil || err == nil || err.Error() != expected {
			T.Errorf("RSAKEY setup failed! Expected '<nil>', '%v' got '%v', '%v'", expected, key, err)
		}
	})

	T.Run("Unparsable RSAKEY", func(t *testing.T) {
		key, err := readRSAKEY(Pkcs8Key)
		expected := "Unable to parse RSAKEY: x509: failed to parse private key (use ParsePKCS8PrivateKey instead for this key format)"

		if key != nil || err == nil || err.Error() != expected {
			T.Errorf("RSAKEY setup failed! Expected '<nil>', '%v' got '%v', '%v'", expected, key, err)
		}
	})

	T.Run("Valid RSAKEY", func(t *testing.T) {
		key, err := readRSAKEY(Pkcs1Key)

		if key == nil || err != nil {
			T.Errorf("RSAKEY setup failed! Expected error to be '<nil>' got '%v'", err)
		}
	})
}

func TestSignClaims(T *testing.T) {
	claims := &Claims{}
	claims.ID = "SomeID"
	claims.Iss="tooxoot"

	result, err := signClaims(claims)
	expected := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOiIwMDAxLTAxLTAxVDAwOjAwOjAwWiIsImlhdCI6IjAwMDEtMDEtMDFUMDA6MDA6MDBaIiwiaWQiOiJTb21lSUQiLCJpc3MiOiJ0b294b290In0.E3kFFHu4NJ8zVc76OisGrNGhfvqqTvzwMLDOgnw8WQG64bbLCeCXEwl3OsYfn5ed_WML4ujG3KXkXrxGP_NoUDEpB8X7Bqivrr2B7iPWv9RjRnnO7eAHolvHkzyzmZjPgxP-vXclAekZZdXvqlt-ZeFEhqQL1Zegxgn7f9unBykePInydYy-G8JRPr1DL27h8xHHz-zCALOBNLIKOwqK02sIKcEjEEFbY74OWMgG58FFZ9bueSctvBwfiQwnUzI3lUuqyfgi8tLX-xnb0uGx4Mb8pjGoc4kB13uPsPINs7aHYXGeyvkllJqnr-Sr_KiKG1GI-TrTx2rsDjU3Y-G3QQ"

	if err != nil || result != expected {
		T.Errorf("signClaims failed! Expected '%v', '<nil>' got '%v', '%v", expected, result, err)
	}
}
func TestParse(T *testing.T) {
	token, claims, err := parse("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOiIwMDAxLTAxLTAxVDAwOjAwOjAwWiIsImlhdCI6IjAwMDEtMDEtMDFUMDA6MDA6MDBaIiwiaWQiOiJTb21lSUQiLCJpc3MiOiJ0b294b290In0.E3kFFHu4NJ8zVc76OisGrNGhfvqqTvzwMLDOgnw8WQG64bbLCeCXEwl3OsYfn5ed_WML4ujG3KXkXrxGP_NoUDEpB8X7Bqivrr2B7iPWv9RjRnnO7eAHolvHkzyzmZjPgxP-vXclAekZZdXvqlt-ZeFEhqQL1Zegxgn7f9unBykePInydYy-G8JRPr1DL27h8xHHz-zCALOBNLIKOwqK02sIKcEjEEFbY74OWMgG58FFZ9bueSctvBwfiQwnUzI3lUuqyfgi8tLX-xnb0uGx4Mb8pjGoc4kB13uPsPINs7aHYXGeyvkllJqnr-Sr_KiKG1GI-TrTx2rsDjU3Y-G3QQ")

	if token == nil || claims == nil || err != nil {
		T.Errorf("parse failed! token: '%+v' claims: '%+v' error: '%v", token, claims, err)
	}
}