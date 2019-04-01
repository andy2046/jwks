

# jwk
`import "github.com/andy2046/jwks/pkg/jwk"`

* [Overview](#pkg-overview)
* [Index](#pkg-index)

## <a name="pkg-overview">Overview</a>



## <a name="pkg-index">Index</a>
* [Variables](#pkg-variables)
* [type Client](#Client)
  * [func NewClient(jwksEndpoint string, options ...Option) (*Client, error)](#NewClient)
  * [func (client *Client) ForceRefresh()](#Client.ForceRefresh)
  * [func (client *Client) KeySet() *JSONWebKeySet](#Client.KeySet)
  * [func (client *Client) Start() error](#Client.Start)
  * [func (client *Client) Stop()](#Client.Stop)
* [type ClientConfig](#ClientConfig)
* [type JSONWebKey](#JSONWebKey)
  * [func (key JSONWebKey) MarshalJSON() ([]byte, error)](#JSONWebKey.MarshalJSON)
  * [func (key *JSONWebKey) Thumbprint(hash crypto.Hash) ([]byte, error)](#JSONWebKey.Thumbprint)
  * [func (key *JSONWebKey) UnmarshalJSON(data []byte) (err error)](#JSONWebKey.UnmarshalJSON)
  * [func (key *JSONWebKey) Valid() bool](#JSONWebKey.Valid)
* [type JSONWebKeySet](#JSONWebKeySet)
  * [func (set *JSONWebKeySet) Key(kid string) []JSONWebKey](#JSONWebKeySet.Key)
* [type Option](#Option)


#### <a name="pkg-files">Package files</a>
[client.go](/src/github.com/andy2046/jwks/pkg/jwk/client.go) [jwk.go](/src/github.com/andy2046/jwks/pkg/jwk/jwk.go) [types.go](/src/github.com/andy2046/jwks/pkg/jwk/types.go) 



## <a name="pkg-variables">Variables</a>
``` go
var (
    // DefaultClientConfig is the default Client Config.
    DefaultClientConfig = ClientConfig{
        logger:         log.New(os.Stdout, "jwks:", log.LstdFlags|log.Lshortfile),
        CacheTimeout:   defaultCacheTimeout,
        RequestTimeout: defaultRequestTimeout,
    }
)
```



## <a name="Client">type</a> [Client](/src/target/client.go?s=589:810#L36)
``` go
type Client struct {
    // contains filtered or unexported fields
}
```
Client fetch keys from a JSON Web Key set endpoint.







### <a name="NewClient">func</a> [NewClient](/src/target/client.go?s=1195:1266#L61)
``` go
func NewClient(jwksEndpoint string, options ...Option) (*Client, error)
```
NewClient returns a new JWKS client.





### <a name="Client.ForceRefresh">func</a> (\*Client) [ForceRefresh](/src/target/client.go?s=2995:3031#L139)
``` go
func (client *Client) ForceRefresh()
```
ForceRefresh refresh cache while called.




### <a name="Client.KeySet">func</a> (\*Client) [KeySet](/src/target/client.go?s=3508:3553#L162)
``` go
func (client *Client) KeySet() *JSONWebKeySet
```
KeySet returns the cached JSONWebKeySet.




### <a name="Client.Start">func</a> (\*Client) [Start](/src/target/client.go?s=2100:2135#L95)
``` go
func (client *Client) Start() error
```
Start to fetch and cache JWKS.




### <a name="Client.Stop">func</a> (\*Client) [Stop](/src/target/client.go?s=3234:3262#L149)
``` go
func (client *Client) Stop()
```
Stop updating cache periodically.




## <a name="ClientConfig">type</a> [ClientConfig](/src/target/client.go?s=285:530#L24)
``` go
type ClientConfig struct {
    DisableStrictTLS bool
    EnableDebug      bool
    AppendCACert     bool
    CACertPath       string
    ServerHostName   string

    CacheTimeout   time.Duration
    RequestTimeout time.Duration
    // contains filtered or unexported fields
}
```
ClientConfig used to init JWKS client.










## <a name="JSONWebKey">type</a> [JSONWebKey](/src/target/jwk.go?s=511:661#L25)
``` go
type JSONWebKey struct {
    Key          interface{}
    Certificates []*x509.Certificate
    KeyID        string
    Algorithm    string
    Use          string
}
```
JSONWebKey represents a RSA public key in JWK format.










### <a name="JSONWebKey.MarshalJSON">func</a> (JSONWebKey) [MarshalJSON](/src/target/jwk.go?s=835:886#L40)
``` go
func (key JSONWebKey) MarshalJSON() ([]byte, error)
```
MarshalJSON returns JSON representation of the given key.




### <a name="JSONWebKey.Thumbprint">func</a> (\*JSONWebKey) [Thumbprint](/src/target/jwk.go?s=1985:2052#L90)
``` go
func (key *JSONWebKey) Thumbprint(hash crypto.Hash) ([]byte, error)
```
Thumbprint returns thumbprint of the given key using the provided hash.




### <a name="JSONWebKey.UnmarshalJSON">func</a> (\*JSONWebKey) [UnmarshalJSON](/src/target/jwk.go?s=1349:1410#L62)
``` go
func (key *JSONWebKey) UnmarshalJSON(data []byte) (err error)
```
UnmarshalJSON returns the key from JSON representation.




### <a name="JSONWebKey.Valid">func</a> (\*JSONWebKey) [Valid](/src/target/jwk.go?s=2406:2441#L113)
``` go
func (key *JSONWebKey) Valid() bool
```
Valid checks the given key.




## <a name="JSONWebKeySet">type</a> [JSONWebKeySet](/src/target/jwk.go?s=711:770#L34)
``` go
type JSONWebKeySet struct {
    Keys []JSONWebKey `json:"keys"`
}
```
JSONWebKeySet represents a JWK Set object.










### <a name="JSONWebKeySet.Key">func</a> (\*JSONWebKeySet) [Key](/src/target/jwk.go?s=2662:2716#L131)
``` go
func (set *JSONWebKeySet) Key(kid string) []JSONWebKey
```
Key returns keys by key ID.




## <a name="Option">type</a> [Option](/src/target/client.go?s=857:891#L48)
``` go
type Option = func(*ClientConfig) error
```
Option applies config to Client Config.














- - -
Generated by [godoc2md](http://godoc.org/github.com/davecheney/godoc2md)
