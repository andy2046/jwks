package jwk

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
)

type (
	rawJSONWebKey struct {
		Use string      `json:"use,omitempty"`
		Kty string      `json:"kty,omitempty"`
		Kid string      `json:"kid,omitempty"`
		Alg string      `json:"alg,omitempty"`
		N   *byteBuffer `json:"n,omitempty"`
		E   *byteBuffer `json:"e,omitempty"`
		X5c []string    `json:"x5c,omitempty"` // Certificates
	}

	// JSONWebKey represents a RSA public key in JWK format.
	JSONWebKey struct {
		Key          interface{}
		Certificates []*x509.Certificate
		KeyID        string
		Algorithm    string
		Use          string
	}

	// JSONWebKeySet represents a JWK Set object.
	JSONWebKeySet struct {
		Keys []JSONWebKey `json:"keys"`
	}
)

// MarshalJSON returns JSON representation of the given key.
func (key JSONWebKey) MarshalJSON() ([]byte, error) {
	var raw *rawJSONWebKey

	switch k := key.Key.(type) {
	case *rsa.PublicKey:
		raw = fromRsaPublicKey(k)
	default:
		return nil, fmt.Errorf("Unknown key type '%s'", reflect.TypeOf(k))
	}

	raw.Kid = key.KeyID
	raw.Alg = key.Algorithm
	raw.Use = key.Use

	for _, cert := range key.Certificates {
		raw.X5c = append(raw.X5c, base64.StdEncoding.EncodeToString(cert.Raw))
	}

	return json.Marshal(raw)
}

// UnmarshalJSON returns the key from JSON representation.
func (key *JSONWebKey) UnmarshalJSON(data []byte) (err error) {
	var raw rawJSONWebKey
	err = json.Unmarshal(data, &raw)
	if err != nil {
		return
	}

	var k interface{}
	switch raw.Kty {
	case "RSA":
		k, err = raw.rsaPublicKey()
	default:
		err = fmt.Errorf("Unknown json web key type '%s'", raw.Kty)
	}
	if err != nil {
		return
	}

	*key = JSONWebKey{Key: k, KeyID: raw.Kid, Algorithm: raw.Alg, Use: raw.Use}
	key.Certificates, err = parseCertificateChain(raw.X5c)
	if err != nil {
		return fmt.Errorf("Fail to unmarshal x5c field: %s", err)
	}

	return
}

// Thumbprint returns thumbprint of the given key using the provided hash.
func (key *JSONWebKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	var (
		input string
		err   error
	)

	switch k := key.Key.(type) {
	case *rsa.PublicKey:
		input, err = rsaThumbprintInput(k.N, k.E)
	default:
		err = fmt.Errorf("Unknown key type '%s'", reflect.TypeOf(k))
	}

	if err != nil {
		return nil, err
	}

	h := hash.New()
	h.Write([]byte(input))
	return h.Sum(nil), nil
}

// Valid checks the given key.
func (key *JSONWebKey) Valid() bool {
	if key.Key == nil {
		return false
	}

	switch k := key.Key.(type) {
	case *rsa.PublicKey:
		if k.N == nil || k.E == 0 {
			return false
		}
	default:
		return false
	}

	return true
}

// Key returns keys by key ID.
func (set *JSONWebKeySet) Key(kid string) []JSONWebKey {
	var keys []JSONWebKey
	for _, key := range set.Keys {
		if key.KeyID == kid {
			keys = append(keys, key)
		}
	}

	return keys
}

func (k rawJSONWebKey) rsaPublicKey() (*rsa.PublicKey, error) {
	if k.N == nil || k.E == nil {
		return nil, fmt.Errorf("Invalid RSA key, missing n/e values")
	}

	return &rsa.PublicKey{
		N: k.N.bigInt(),
		E: k.E.toInt(),
	}, nil
}
