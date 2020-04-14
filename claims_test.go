
package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestClaimsJsonKeys(T *testing.T) {
	serializedClaims, err := json.Marshal(Claims{})
	if err != nil {
		T.Error("Serialization of Claims failed with Error: ", err)
	}

	expectedSerialization := `{"exp":"0001-01-01T00:00:00Z","iat":"0001-01-01T00:00:00Z","id":"","iss":""}`
	if string(serializedClaims) != expectedSerialization {
		T.Errorf("Serialization of Claims returned %s but expected %s", serializedClaims, expectedSerialization)
	}
}

func TestNewClaims(T *testing.T) {
	expected := Claims{
		Exp: testtime.Add(24 * time.Hour),
		Iat: testtime,
		ID : "SomeID",
		Iss: "tooxoot",
	}

	newClaims := NewClaims("SomeID")
	
	expectations := []bool{
		newClaims.Exp == expected.Exp,
		newClaims.Iat == expected.Iat,
		newClaims.ID == expected.ID,
		newClaims.Iss == expected.Iss,
	} 

	for _, fulfilled := range expectations {
		if !fulfilled {
			T.Errorf("NewClaims failed! Expected: %+v Got: %+v", expected, newClaims)
		}
	}

	if NewClaims("") != nil {
		T.Errorf("NewClaims failed! Expected nil for empty id")
	}

}

func TestClaimValidation(T *testing.T) {
	foreignClaims := NewClaims("SomeID")
	foreignClaims.Iss = "notTooxoot"

	expiredClaims := NewClaims("SomeID")
	expiredClaims.Exp = testtime.Add(-6 * time.Minute)

	futureClaims := NewClaims("SomeID")
	futureClaims.Iat = testtime.Add(6 * time.Minute)

	idlessClaims := NewClaims("SomeID")
	idlessClaims.ID = ""

	validClaims := NewClaims("SomeID")
	validClaims.Exp.Add(10 * time.Minute)
	validClaims.Iat.Add(-10 * time.Minute)

	errorCases := map[*Claims]string{
		{}: "Issuer must be tooxoot",
		foreignClaims: "Issuer must be tooxoot",
		expiredClaims: "Token is expired",
		futureClaims: "Token is issued in the future",
		idlessClaims: "Token's ID is empty",
	}
	
	for testedClaims, expectation := range errorCases {
		result := testedClaims.Valid()
		if result == nil || result.Error() != expectation {
			T.Errorf("Claims validation failed! Expected '%v' but got '%v' for %+v on testTime '%v'", expectation, result, testedClaims, testtime)
		}
	}


	if validClaims.Valid() != nil || NewClaims("SomeID").Valid() != nil{
		T.Errorf("Claims validation failed for valid claims!")
	} 
}
