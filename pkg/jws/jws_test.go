package jws

import (
	"fmt"
	"testing"
)

var tokenStr = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2FuZHkyMDQ2LmlvIiwic3ViIjoiYWRtaW5AYW5keTIwNDYuaW8iLCJuYmYiOjE1NTI4MTEwNDgsImV4cCI6MTU1MjgxNDY0OCwiaWF0IjoxNTUyODExMDQ4LCJqdGkiOiJpZDEyMzQ1NiIsInR5cCI6Imh0dHBzOi8vYW5keTIwNDYuaW8vcmVnaXN0ZXIifQ."

// {
// 	"typ": "JWT",
// 	"alg": "none"
// }
// {
// 	"iss": "https://andy2046.io",
// 	"sub": "admin@andy2046.io",
// 	"nbf": 1552811048,
// 	"exp": 1552814674,
// 	"iat": 1552811048,
// 	"jti": "id123456",
// 	"typ": "https://andy2046.io/register"
// }

func TestParseUnverified(t *testing.T) {
	token, err := Parse(tokenStr)
	assert(t, err == nil, fmt.Sprintf("problem parsing token string %s", err))

	claims := &StandardClaims{}
	token, err = ParseWithClaims(tokenStr, claims)
	assert(t, err == nil, fmt.Sprintf("problem parsing token string %s", err))

	header := token.Header
	expectedAlg := "none"
	alg := header["alg"].(string)
	assert(t, alg == expectedAlg, fmt.Sprintf("problem checking header expected %s got %s", expectedAlg, alg))

	expectedSub := "admin@andy2046.io"
	sub := claims.Subject
	assert(t, sub == expectedSub, fmt.Sprintf("problem checking claims expected %s got %s", expectedSub, sub))
}
