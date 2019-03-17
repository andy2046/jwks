package jws

import (
	"encoding/base64"
	"strings"
	"testing"
)

type (
	// Claims represents JWT Claims Section.
	Claims interface {
		Valid() error
	}

	// Token represents a JWT Token.
	Token struct {
		Raw       string                 // The raw token
		Header    map[string]interface{} // The first segment of the token
		Claims    Claims                 // The second segment of the token
		Signature string                 // The third segment of the token
	}

	// MapClaims represents Claims type using the map[string]interface{} for JSON decoding.
	MapClaims map[string]interface{}

	// StandardClaims represents Structured version of JWT Claims Section.
	StandardClaims struct {
		Audience  string `json:"aud,omitempty"`
		ExpiresAt int64  `json:"exp,omitempty"`
		ID        string `json:"jti,omitempty"`
		IssuedAt  int64  `json:"iat,omitempty"`
		Issuer    string `json:"iss,omitempty"`
		NotBefore int64  `json:"nbf,omitempty"`
		Subject   string `json:"sub,omitempty"`
	}
)

// Valid forever.
func (c StandardClaims) Valid() error {
	return nil
}

// Valid forever.
func (m MapClaims) Valid() error {
	return nil
}

// EncodeSegment Encode JWT specific base64url encoding with padding stripped.
func EncodeSegment(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

// DecodeSegment Decode JWT specific base64url encoding with padding stripped.
func DecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}

func assert(t *testing.T, condition bool, msg string) {
	if !condition {
		t.Error(msg)
	}
}
