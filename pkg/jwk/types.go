package jwk

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"testing"
	"time"
)

const rsaThumbprintTemplate = `{"e":"%s","kty":"RSA","n":"%s"}`

// byteBuffer represents url-safe base64 serializable bytes data.
type byteBuffer struct {
	data []byte
}

func newBuffer(data []byte) *byteBuffer {
	if data == nil {
		return nil
	}
	return &byteBuffer{
		data: data,
	}
}

func newBufferFromInt(num uint64) *byteBuffer {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, num)
	return newBuffer(bytes.TrimLeft(data, "\x00"))
}

func (b *byteBuffer) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.base64())
}

func (b *byteBuffer) UnmarshalJSON(data []byte) error {
	var encoded string
	err := json.Unmarshal(data, &encoded)
	if err != nil {
		return err
	}

	if encoded == "" {
		return nil
	}

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}

	*b = *newBuffer(decoded)

	return nil
}

func (b *byteBuffer) base64() string {
	return base64.RawURLEncoding.EncodeToString(b.data)
}

func (b *byteBuffer) bytes() []byte {
	if b == nil {
		return nil
	}
	return b.data
}

func (b byteBuffer) bigInt() *big.Int {
	return new(big.Int).SetBytes(b.data)
}

func (b byteBuffer) toInt() int {
	return int(b.bigInt().Int64())
}

func rsaThumbprintInput(n *big.Int, e int) (string, error) {
	return fmt.Sprintf(rsaThumbprintTemplate,
		newBufferFromInt(uint64(e)).base64(),
		newBuffer(n.Bytes()).base64()), nil
}

func fromRsaPublicKey(pub *rsa.PublicKey) *rawJSONWebKey {
	return &rawJSONWebKey{
		Kty: "RSA",
		N:   newBuffer(pub.N.Bytes()),
		E:   newBufferFromInt(uint64(pub.E)),
	}
}

func parseCertificateChain(chain []string) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(chain))
	for i, cert := range chain {
		raw, err := base64.StdEncoding.DecodeString(cert)
		if err != nil {
			return nil, err
		}
		certs[i], err = x509.ParseCertificate(raw)
		if err != nil {
			return nil, err
		}
	}
	return certs, nil
}

type watchdog struct {
	period time.Duration
	ticker *time.Ticker
}

func createWatchdog(period time.Duration) *watchdog {
	return &watchdog{period, time.NewTicker(period)}
}

func (w *watchdog) resetTicker() {
	w.ticker.Stop()
	w.ticker = time.NewTicker(w.period)
}

func (w *watchdog) stop() {
	w.ticker.Stop()
	w.ticker = nil
}

// Decode base64-encoded string into byte array for testing.
func fromBase64Bytes(b64 string) []byte {
	re := regexp.MustCompile(`\s+`)
	val, err := base64.StdEncoding.DecodeString(re.ReplaceAllString(b64, ""))
	if err != nil {
		panic("Invalid test data")
	}
	return val
}

// Decode base64-urlencoded string into byte array for testing.
func fromBase64URLBytes(b64 string) []byte {
	re := regexp.MustCompile(`\s+`)
	val, err := base64.RawURLEncoding.DecodeString(re.ReplaceAllString(b64, ""))
	if err != nil {
		panic("Invalid test data")
	}
	return val
}

// Build big int from base64-encoded string for testing.
func fromBase64Int(encoded string) *big.Int {
	re := regexp.MustCompile(`\s+`)
	val, err := base64.RawURLEncoding.DecodeString(re.ReplaceAllString(encoded, ""))
	if err != nil {
		panic("Invalid test data: " + err.Error())
	}
	return new(big.Int).SetBytes(val)
}

func assert(t *testing.T, condition bool, msg string) {
	if !condition {
		t.Error(msg)
	}
}
