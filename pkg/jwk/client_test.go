package jwk

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

func TestConfigDefaults(t *testing.T) {
	config := DefaultClientConfig
	assert(t, config.CacheTimeout == defaultCacheTimeout, "CacheTimeout config")
	assert(t, config.RequestTimeout == defaultRequestTimeout, "RequestTimeout config")
	assert(t, config.DisableStrictTLS == false, "DisableStrictTLS config")
	assert(t, config.EnableDebug == false, "EnableDebug config")
}

var testCertificatesStr = "MIIC+DCCAeCgAwIBAgIJBIGjYW6hFpn2MA0GCSqGSIb3DQEBBQUAMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTAeFw0xNjExMjIyMjIyMDVaFw0zMDA4MDEyMjIyMDVaMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMnjZc5bm/eGIHq09N9HKHahM7Y31P0ul+A2wwP4lSpIwFrWHzxw88/7Dwk9QMc+orGXX95R6av4GF+Es/nG3uK45ooMVMa/hYCh0Mtx3gnSuoTavQEkLzCvSwTqVwzZ+5noukWVqJuMKNwjL77GNcPLY7Xy2/skMCT5bR8UoWaufooQvYq6SyPcRAU4BtdquZRiBT4U5f+4pwNTxSvey7ki50yc1tG49Per/0zA4O6Tlpv8x7Red6m1bCNHt7+Z5nSl3RX/QYyAEUX1a28VcYmR41Osy+o2OUCXYdUAphDaHo4/8rbKTJhlu8jEcc1KoMXAKjgaVZtG/v5ltx6AXY0CAwEAAaMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUQxFG602h1cG+pnyvJoy9pGJJoCswDQYJKoZIhvcNAQEFBQADggEBAGvtCbzGNBUJPLICth3mLsX0Z4z8T8iu4tyoiuAshP/Ry/ZBnFnXmhD8vwgMZ2lTgUWwlrvlgN+fAtYKnwFO2G3BOCFw96Nm8So9sjTda9CCZ3dhoH57F/hVMBB0K6xhklAc0b5ZxUpCIN92v/w+xZoz1XQBHe8ZbRHaP1HpRM4M7DJk2G5cgUCyu3UBvYS41sHvzrxQ3z7vIePRA4WF4bEkfX12gvny0RsPkrbVMXX1Rj9t6V7QXrbPYBAO+43JvDGYawxYVvLhz+BJ45x50GFQmHszfY3BR9TPK8xmMmQwtIvLu1PMttNCs7niCYkSiUv2sc2mlq1i3IashGkkgmo="

type mockSuccessTransport struct{}

func (t *mockSuccessTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response := &http.Response{
		Header:     make(http.Header),
		Request:    req,
		StatusCode: http.StatusOK,
	}
	responseBody := fmt.Sprintf(
		`{"keys":[{"alg":"RS256","kty":"RSA","use":"sig","x5c":["%s"],"n":"VKOoRQ","e":"AQAB","kid":"ABCDEFG"}]}`,
		testCertificatesStr)
	response.Body = ioutil.NopCloser(strings.NewReader(responseBody))
	return response, nil
}

func TestSuccessHttpRequest(t *testing.T) {
	httpClient := http.DefaultClient
	httpClient.Transport = &mockSuccessTransport{}
	jwkClient := NewClient("http://andy2046.io")
	jwkClient.httpClient = httpClient
	jwkClient.config.EnableDebug = true

	err := jwkClient.Start()
	assert(t, err == nil, fmt.Sprintf("fail to Start %s", err))

	keySet := jwkClient.KeySet()
	assert(t, len(keySet.Keys) == 1, fmt.Sprintf("it should return key set with one key not %d", len(keySet.Keys)))

	jwkClient.ForceRefresh()
	assert(t, jwkClient.closed == false, "jwkClient should NOT be closed")
	jwkClient.Stop()
	assert(t, jwkClient.closed == true, "jwkClient should be closed")
	jwkClient.ForceRefresh()
}
