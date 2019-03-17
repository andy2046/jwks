package jwk

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	defaultRequestTimeout = 30 * time.Second
	defaultCacheTimeout   = 600 * time.Second
)

type (
	// ClientConfig used to init JWKS client.
	ClientConfig struct {
		DisableStrictTLS bool
		EnableDebug      bool
		logger           *log.Logger
		CacheTimeout     time.Duration
		RequestTimeout   time.Duration
	}

	// Client fetch keys from a JSON Web Key set endpoint.
	Client struct {
		config      *ClientConfig
		httpClient  *http.Client
		endpointURL string
		keySet      *JSONWebKeySet
		mutex       sync.RWMutex
		doneChan    chan struct{}
		dog         *watchdog
		closed      bool
	}

	// Option applies config to Client Config.
	Option = func(*ClientConfig) error
)

var (
	// DefaultClientConfig is the default Client Config.
	DefaultClientConfig = ClientConfig{
		logger:         log.New(os.Stdout, "jwks:", log.LstdFlags|log.Lshortfile),
		CacheTimeout:   defaultCacheTimeout,
		RequestTimeout: defaultRequestTimeout,
	}
)

// NewClient returns a new JWKS client.
func NewClient(jwksEndpoint string, options ...Option) *Client {
	config := DefaultClientConfig
	setOption(&config, options...)

	client := &Client{
		config:      &config,
		endpointURL: jwksEndpoint,
		keySet:      &JSONWebKeySet{},
		doneChan:    make(chan struct{}),
		dog:         createWatchdog(config.CacheTimeout),
		httpClient: &http.Client{
			Timeout: config.RequestTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: config.DisableStrictTLS},
			},
		},
	}
	return client
}

// Start to fetch and cache JWKS.
func (client *Client) Start() error {
	if err := client.fetchJWKS(); err != nil {
		return err
	}

	closed := client.isClosed()
	if closed {
		client.config.logger.Println("Warning from Start: Client closed")
		return fmt.Errorf("Client closed")
	}

	go client.watch()
	return nil
}

func (client *Client) watch() {
	fetch := func() {
		if err := client.fetchJWKS(); err != nil {
			client.config.logger.Printf("Error from fetchJWKS: %s\n", err)
		}
	}

	for {
		select {
		case <-client.dog.ticker.C:
			fetch()
		case _, open := <-client.doneChan:
			if !open {
				if client.config.EnableDebug {
					client.config.logger.Println("exit watch")
				}
				client.dog.stop()
				return
			}
			if client.config.EnableDebug {
				client.config.logger.Println("force cache refresh and resetTicker")
			}
			fetch()
			client.dog.resetTicker()
		}
	}
}

// ForceRefresh refresh cache while called.
func (client *Client) ForceRefresh() {
	closed := client.isClosed()
	if closed {
		client.config.logger.Println("Warning from ForceRefresh: Client closed")
		return
	}
	client.doneChan <- struct{}{}
}

// Stop updating cache periodically.
func (client *Client) Stop() {
	client.mutex.Lock()
	defer client.mutex.Unlock()

	if client.closed {
		client.config.logger.Println("Warning from Stop: Client closed")
		return
	}
	client.closed = true
	close(client.doneChan)
}

// KeySet returns the cached JSONWebKeySet.
func (client *Client) KeySet() *JSONWebKeySet {
	client.mutex.RLock()
	defer client.mutex.RUnlock()

	return client.keySet
}

func (client *Client) isClosed() bool {
	client.mutex.RLock()
	defer client.mutex.RUnlock()
	return client.closed
}

func (client *Client) fetchJWKS() (err error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()

	if client.config.EnableDebug {
		client.config.logger.Printf("fetchJWKS from %s (period %s)\n", client.endpointURL, client.dog.period)
	}

	var resp *http.Response
	if resp, err = client.httpClient.Get(client.endpointURL); err != nil {
		return
	} else if resp.StatusCode >= 400 {
		return fmt.Errorf("fetchJWKS request returned non-success StatusCode %d", resp.StatusCode)
	}
	defer closeBody(resp)

	err = json.NewDecoder(resp.Body).Decode(client.keySet)
	return
}

func setOption(c *ClientConfig, options ...func(*ClientConfig) error) error {
	for _, opt := range options {
		if err := opt(c); err != nil {
			return err
		}
	}
	return nil
}

func closeBody(resp *http.Response) {
	// Drain and close the body to let the Transport reuse the connection
	if resp != nil {
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
	}
}
