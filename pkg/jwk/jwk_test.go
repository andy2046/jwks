package jwk

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

var rsaTestKey, _ = rsa.GenerateKey(rand.Reader, 2048)

// Test X.509 certificates
var testCertificates, _ = x509.ParseCertificates(fromBase64Bytes(`
MIICUjCCAbugAwIBAgIBADANBgkqhkiG9w0BAQ0FADBGMQswCQYDVQQGEwJzZzES
MBAGA1UECAwJU2luZ2Fwb3JlMQ0wCwYDVQQKDARnb2dvMRQwEgYDVQQDDAthbmR5
MjA0Ni5pbzAeFw0xOTAzMTcwMzM1MzJaFw0yMDAzMTYwMzM1MzJaMEYxCzAJBgNV
BAYTAnNnMRIwEAYDVQQIDAlTaW5nYXBvcmUxDTALBgNVBAoMBGdvZ28xFDASBgNV
BAMMC2FuZHkyMDQ2LmlvMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC82ebD
ixTp5zWxNtYspSwNwK7BlgPpLdxEk9/yF0tUXXpjvXT5xPFbeKrIg1r+TZsR/nwN
4jSE/ih5ANK/A6HEFbjc0gFPjuzoPv25vOx8tSWv9r2UdCVwK5J8ZN8d6/Bo9K3/
QNjyhtwP5+5DQqhcFHMnKJbtb1Qdl61p/+OuhQIDAQABo1AwTjAdBgNVHQ4EFgQU
3bFLUKwvvabaIoYz3avKlR+SC70wHwYDVR0jBBgwFoAU3bFLUKwvvabaIoYz3avK
lR+SC70wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQC1mFDNM0sQIyWY
9iLD+J0KCg3JgHdiRmAmXo1TvqfsUrQOPpDqEECHpWGmA/gMyrBLAIzgT98iIlFk
cyr2ZlHqLRSUvzH0HMgFWIa8IRU1ahE1+ERWWQtJQ0lnHhX6As4imE8nn1kG3f8q
iUIzoYraAoJgn+oXajLbqtN3Q5qouw==`))

func TestX5C(t *testing.T) {
	jwk := JSONWebKey{
		Key:          &rsaTestKey.PublicKey,
		KeyID:        "bar",
		Algorithm:    "RS256",
		Certificates: testCertificates,
	}

	jsonbar, err := jwk.MarshalJSON()
	assert(t, err == nil, fmt.Sprintf("problem marshaling %s", err))

	var jwk2 JSONWebKey
	err = jwk2.UnmarshalJSON(jsonbar)
	assert(t, err == nil, fmt.Sprintf("problem unmarshalling %s", err))

	assert(t, reflect.DeepEqual(testCertificates, jwk2.Certificates),
		fmt.Sprintf("Certificates not equal %v %v", jwk.Certificates, jwk2.Certificates))

	jsonbar2, err := jwk2.MarshalJSON()
	assert(t, err == nil, fmt.Sprintf("problem marshaling %s", err))

	assert(t, bytes.Equal(jsonbar, jsonbar2), fmt.Sprintf("it should not lose info"))
}

func TestMarshalUnmarshal(t *testing.T) {
	kid, use := "ABCDEF", "sig"

	for _, key := range []interface{}{&rsaTestKey.PublicKey} {
		jwk := JSONWebKey{Key: key, KeyID: kid, Algorithm: "RS256", Use: use}

		jsonbar, err := jwk.MarshalJSON()
		assert(t, err == nil, fmt.Sprintf("problem marshalling %s", err))

		var jwk2 JSONWebKey
		err = jwk2.UnmarshalJSON(jsonbar)
		assert(t, err == nil, fmt.Sprintf("problem unmarshalling %s", err))

		jsonbar2, err := jwk2.MarshalJSON()
		assert(t, err == nil, fmt.Sprintf("problem marshalling %s", err))
		assert(t, bytes.Equal(jsonbar, jsonbar2), fmt.Sprintf("it should not lose info"))
		assert(t, jwk2.KeyID == kid, fmt.Sprintf("kid not match"))
		assert(t, jwk2.Algorithm == "RS256", fmt.Sprintf("alg not match"))
		assert(t, jwk2.Use == use, fmt.Sprintf("use not match"))
	}
}

func TestMarshalUnmarshalJWKSet(t *testing.T) {
	jwk1 := JSONWebKey{Key: &rsaTestKey.PublicKey, KeyID: "ABCDEFG", Algorithm: "RS256"}
	jwk2 := JSONWebKey{Key: &rsaTestKey.PublicKey, KeyID: "GFEDCBA", Algorithm: "RS256"}
	var set JSONWebKeySet
	set.Keys = append(set.Keys, jwk1)
	set.Keys = append(set.Keys, jwk2)

	jsonbar, err := json.Marshal(&set)
	assert(t, err == nil, fmt.Sprintf("problem marshalling set %s", err))

	var set2 JSONWebKeySet
	err = json.Unmarshal(jsonbar, &set2)
	assert(t, err == nil, fmt.Sprintf("problem unmarshalling set %s", err))

	jsonbar2, err := json.Marshal(&set2)
	assert(t, err == nil, fmt.Sprintf("problem marshalling set %s", err))
	assert(t, bytes.Equal(jsonbar, jsonbar2), fmt.Sprintf("it should not lose info"))
}

func TestJWKSetKey(t *testing.T) {
	jwk1 := JSONWebKey{Key: &rsaTestKey.PublicKey, KeyID: "ABCDEFG", Algorithm: "RS256"}
	jwk2 := JSONWebKey{Key: &rsaTestKey.PublicKey, KeyID: "GFEDCBA", Algorithm: "RS256"}
	var set JSONWebKeySet
	set.Keys = append(set.Keys, jwk1)
	set.Keys = append(set.Keys, jwk2)
	k := set.Key("ABCDEFG")
	assert(t, len(k) == 1, fmt.Sprintf("it should return key set with one key not %d", len(k)))
	assert(t, k[0].KeyID == "ABCDEFG", fmt.Sprintf("it should return key with ID ABCDEFG"))
}

func TestWebKeyInvalid(t *testing.T) {
	keys := []string{
		// Invalid JSON
		"{X",
		// Empty key
		"{}",
		// Invalid RSA keys
		`{"kty":"RSA"}`,
		`{"kty":"RSA","e":""}`,
		`{"kty":"RSA","e":"XXXX"}`,
	}

	for _, key := range keys {
		var jwk2 JSONWebKey
		err := jwk2.UnmarshalJSON([]byte(key))
		assert(t, err != nil, fmt.Sprintf("managed to parse invalid key %s", key))
	}
}

func TestJWKValid(t *testing.T) {
	rsaPub := rsaTestKey.PublicKey

	cases := []struct {
		key              interface{}
		expectedValidity bool
	}{
		{nil, false},
		{&rsa.PublicKey{}, false},
		{&rsaPub, true},
		{&rsa.PrivateKey{}, false},
	}

	for _, tc := range cases {
		k := &JSONWebKey{Key: tc.key}
		valid := k.Valid()
		assert(t, valid == tc.expectedValidity,
			fmt.Sprintf("expected Valid to return %t, got %t", tc.expectedValidity, valid))
	}
}
