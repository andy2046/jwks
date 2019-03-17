package jws

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Parse validate and return a token.
func Parse(tokenString string) (*Token, error) {
	return ParseWithClaims(tokenString, MapClaims{})
}

// ParseWithClaims validate with given Claims and return a token.
func ParseWithClaims(tokenString string, claims Claims) (*Token, error) {
	// TODO: Validate Claims
	return ParseUnverified(tokenString, claims)
}

// ParseUnverified parses the token but doesn't validate the signature.
func ParseUnverified(tokenString string, claims Claims) (token *Token, err error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token contains an invalid number of segments")
	}

	token = &Token{Raw: tokenString}
	token.Signature = parts[2]

	// parse Header
	var headerBytes []byte
	if headerBytes, err = DecodeSegment(parts[0]); err != nil {
		return token, fmt.Errorf("token Header is malformed %s", err)
	}
	if err = json.Unmarshal(headerBytes, &token.Header); err != nil {
		return token, fmt.Errorf("token Header is malformed %s", err)
	}

	// parse Claims
	var claimBytes []byte
	token.Claims = claims

	if claimBytes, err = DecodeSegment(parts[1]); err != nil {
		return token, fmt.Errorf("token Claims is malformed %s", err)
	}
	dec := json.NewDecoder(bytes.NewBuffer(claimBytes))

	// JSON Decode.  Special case for map type to avoid weird pointer behavior
	if c, ok := token.Claims.(MapClaims); ok {
		err = dec.Decode(&c)
	} else {
		err = dec.Decode(&claims)
	}
	if err != nil {
		return token, fmt.Errorf("token Claims is malformed %s", err)
	}

	return token, nil
}
