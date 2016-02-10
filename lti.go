// Package lti provides support for working with LTI
// more info can be checked at:
// https://www.imsglobal.org/activity/learning-tools-interoperability
// Basically it can sign http requests and also it can
// verify incoming LMI requests
package lti

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jordic/lti/oauth"
)

const (
	OAuthVersion = "1.0"
	SigHMAC      = "HMAC-SHA1"
)

// Provider is an app, that can consume LTI messages
type Provider struct {
	Secret      string
	URL         string
	ConsumerKey string
	Method      string
	values      url.Values
	r           *http.Request
	Signer      oauth.OauthSigner
}

// Default is a default provider
func Default(secret string) *Provider {
	sig := oauth.GetHMACSigner(secret, "")
	return &Provider{
		Secret: secret,
		Method: "POST",
		values: url.Values{},
		Signer: sig,
	}
}

// Get a value from the provider
func (p *Provider) Get(k string) string {
	return p.values.Get(k)
}

// Params returns request params
func (p *Provider) Params() url.Values {
	return p.values
}

// Add a new param
func (p *Provider) Add(k, v string) *Provider {
	if p.values == nil {
		p.values = url.Values{}
	}
	p.values.Set(k, v)
	return p
}

// Empty checks if a key is defined (or has something)
func (p *Provider) Empty(key string) bool {
	if p.values == nil {
		p.values = url.Values{}
	}
	return p.values.Get(key) == ""
}

// Sign a request, adding, required fields
func (p *Provider) Sign() (string, error) {
	if p.Empty("oauth_version") {
		p.Add("oauth_version", OAuthVersion)
	}
	if p.Empty("oauth_timestamp") {
		p.Add("oauth_timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	}
	if p.Empty("oauth_nonce") {
		p.Add("oauth_nonce", nonce())
	}
	if p.Empty("oauth_signature_method") {
		p.Add("oauth_signature_method", p.Signer.GetMethod())
	}
	p.Add("oauth_consumer_key", p.ConsumerKey)

	signature, err := Sign(p.values, p.URL, p.Method, p.Signer)
	if err == nil {
		p.Add("oauth_signature", signature)
	}
	return signature, err
}

// IsValid returns if lti request is valid, currently only checks
// if signature is correct
func (p *Provider) IsValid(r *http.Request) (bool, error) {
	if p.values == nil {
		r.ParseForm()
		p.values = r.Form
	}
	signature := r.Form.Get("oauth_signature")
	sig, err := Sign(r.Form, r.URL.String(), r.Method, p.Signer)
	if err != nil {
		return false, err
	}
	if sig == signature {
		return true, nil
	}
	return false, fmt.Errorf("Invalid signature, %s, expected %s", sig, signature)
}

// SetSigner oauth method
func (p *Provider) SetSigner(s oauth.OauthSigner) {
	p.Signer = s
}

// Sign a lti request using HMAC containing a u, url, a http method,
// and a secret. ts is a tokenSecret field from the oauth spec,
// that in this case must be empty.
func Sign(form url.Values, u, method string, firm oauth.OauthSigner) (string, error) {
	str, err := getBaseString(method, u, form)
	if err != nil {
		return "", err
	}
	sig, err := firm.GetSignature(str)
	if err != nil {
		return "", err
	}
	return sig, nil
}

func getBaseString(m, u string, form url.Values) (string, error) {

	var kv []oauth.KV
	for k := range form {
		if k != "oauth_signature" {
			s := oauth.KV{k, form.Get(k)}
			kv = append(kv, s)
		}
	}

	str, err := oauth.GetBaseString(m, u, kv)
	if err != nil {
		return "", err
	}
	// ugly patch for formatting string as expected.
	str = strings.Replace(str, "%2B", "%2520", -1)
	return str, nil
}

var nonceCounter uint64

// nonce returns a unique string.
func nonce() string {
	n := atomic.AddUint64(&nonceCounter, 1)
	if n == 1 {
		binary.Read(rand.Reader, binary.BigEndian, &n)
		n ^= uint64(time.Now().UnixNano())
		atomic.CompareAndSwapUint64(&nonceCounter, 1, n)
	}
	return strconv.FormatUint(n, 16)
}
