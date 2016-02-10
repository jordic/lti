// OAuth 1.0 Implementation

// Copyright (C) 2013 Damien Whitten
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in the
// Software without restriction, including without limitation the rights to use, copy,
// modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
// and to permit persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies
// or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
// FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

package oauth

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// KV is a simple struct for holding the array equivalent of map[string]string
type KV struct {
	Key string
	Val string
}

func ErrF(format string, parameters ...interface{}) error {
	return errors.New(fmt.Sprintf(format, parameters...))
}

// kvSorter sorts key value arrays according to the oauth method (keys then values)
// Not tested properly (Not sure that 'less than' for oauth and golang are the same)
type kvSorter struct {
	kvs []KV
}

func (s *kvSorter) Len() int {
	return len(s.kvs)
}

func (s *kvSorter) Swap(i, j int) {
	s.kvs[i], s.kvs[j] = s.kvs[j], s.kvs[i]
}

func (s *kvSorter) Less(i, j int) bool {
	if s.kvs[i].Key == s.kvs[j].Key {
		return s.kvs[i].Val < s.kvs[j].Val
	}
	return s.kvs[i].Key < s.kvs[j].Key
}

// OauthKvSort sorts key value arrays according to the oauth method (keys then values)
// Not tested properly (Not sure that 'less than' for oauth and golang are the same)
func OauthKvSort(kv []KV) {
	sorter := kvSorter{kv}
	sort.Sort(&sorter)
}

// MergeRequestParameters just Appends all arrays for now
func MergeRequestParameters(query, oauth, form []KV) []KV {
	allParameters := append(query, oauth...)
	allParameters = append(allParameters, form...)
	return allParameters
}

// GetBaseString returns the 'Signature Base String', which is to be encoded as the signature
func GetBaseString(method, requestUrl string, allParameters []KV) (string, error) {

	for i, kv := range allParameters {
		allParameters[i].Val = url.QueryEscape(kv.Val)
		allParameters[i].Key = url.QueryEscape(kv.Key)
	}

	OauthKvSort(allParameters)

	strs := make([]string, len(allParameters), len(allParameters))
	for i, kv := range allParameters {
		strs[i] = kv.Key + "=" + kv.Val
	}

	urlPart := url.QueryEscape(strings.ToUpper(method)) + "&" + url.QueryEscape(requestUrl)

	return urlPart + "&" + url.QueryEscape(strings.Join(strs, "&")), nil
}

// OauthSigner should have implementations for all signature methods for oAuth
type OauthSigner interface {
	GetSignature(baseString string) (string, error)
	GetMethod() string
}

// GetHMACSigner generates the HMAC-SHA1 signing algorythm
func GetHMACSigner(clientSecret, tokenSecret string) *HMACSigner {
	key := url.QueryEscape(clientSecret) + "&" + url.QueryEscape(tokenSecret)

	hms := HMACSigner{
		clientSecret: clientSecret,
		tokenSecret:  tokenSecret,
		key:          []byte(key),
	}

	return &hms
}

type HMACSigner struct {
	clientSecret string
	tokenSecret  string
	key          []byte
}

func (s *HMACSigner) GetSignature(baseString string) (string, error) {
	mac := hmac.New(sha1.New, s.key)
	mac.Write([]byte(baseString))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}
func (s *HMACSigner) GetMethod() string { return "HMAC-SHA1" }

// GetRSASigner generates the RSA-SHA1 signing algorythm
func GetRSASigner(privateKey *rsa.PrivateKey) *RSASigner {
	rs := RSASigner{
		privateKey: privateKey,
	}
	return &rs
}

type RSASigner struct {
	privateKey *rsa.PrivateKey
}

func (s *RSASigner) GetSignature(baseString string) (string, error) {

	h := sha1.New()
	h.Write([]byte(baseString))
	digest := h.Sum(nil)

	b, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA1, digest)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func (s *RSASigner) GetMethod() string { return "RSA-SHA1" }

type OAuthParameters struct {
	Signer         OauthSigner
	ConsumerKey    *string
	ConsumerSecret *string
	Token          *string
	TokenSecret    *string
	Version        *string
	Method         *string
	Nonce          *string
	Timestamp      *string
}

func (o *OAuthParameters) Build() {
	var nonceInt uint64
	binary.Read(rand.Reader, binary.LittleEndian, &nonceInt)
	nonceString := fmt.Sprintf("%d", nonceInt)
	o.Nonce = &nonceString
	timestampString := fmt.Sprintf("%d", time.Now().Unix())
	o.Timestamp = &timestampString
}

func (o *OAuthParameters) Check() error {
	if o.ConsumerKey == nil {
		return ErrF("Consumer Key not set")
	}
	if o.Token == nil {
		return ErrF("Token not set")
	}
	if o.Version == nil {
		v := "1.0"
		o.Version = &v
	}
	if o.Method == nil {
		method := o.Signer.GetMethod()
		o.Method = &method
	}
	if o.Nonce == nil || o.Timestamp == nil {
		o.Build()
	}
	return nil
}

func (o *OAuthParameters) GetOauthParameters() ([]KV, error) {

	err := o.Check()
	if err != nil {
		return []KV{}, err
	}

	oauthKeys := []KV{
		KV{"oauth_consumer_key", *o.ConsumerKey},
		KV{"oauth_nonce", *o.Nonce},
		KV{"oauth_timestamp", *o.Timestamp},
		KV{"oauth_token", *o.Token},
		KV{"oauth_signature_method", *o.Method},
		KV{"oauth_version", *o.Version},
	}
	return oauthKeys, nil
}

func (o *OAuthParameters) GetOAuthSignature(method, requestUrl string, queryString []KV) (string, error) {
	allParameters, err := o.GetOauthParameters()
	if err != nil {
		return "", err
	}

	allParameters = append(allParameters, queryString...)

	baseString, err := GetBaseString(method, requestUrl, allParameters)
	if err != nil {
		return "", err
	}

	sig, err := o.Signer.GetSignature(baseString)
	if err != nil {
		return "", err
	}

	return sig, nil
}

func (o *OAuthParameters) GetOAuthHeader(verb, requestUrl string, queryString []KV) (string, error) {
	sig, err := o.GetOAuthSignature(verb, requestUrl, queryString)
	if err != nil {
		return "", err
	}

	oauthParameters, err := o.GetOauthParameters()
	if err != nil {
		return "", err
	}
	oauthParameters = append(oauthParameters, KV{"oauth_signature", sig})

	oauthStrings := make([]string, len(oauthParameters), len(oauthParameters))
	for i, kv := range oauthParameters {
		oauthStrings[i] = fmt.Sprintf(`%s="%s"`, url.QueryEscape(kv.Key), url.QueryEscape(kv.Val))
	}

	return "OAuth " + strings.Join(oauthStrings, ", "), nil
}

func (o *OAuthParameters) DoOauthRequest(verb string, requestUrl string, queryString []KV) (string, error) {

	authHeader, err := o.GetOAuthHeader(verb, requestUrl, queryString)
	if err != nil {
		return "", err
	}

	qsParams := make([]string, len(queryString), len(queryString))
	for i, kv := range queryString {
		qsParams[i] = url.QueryEscape(kv.Key) + "=" + url.QueryEscape(kv.Val)
	}

	fullUrl := requestUrl
	if len(qsParams) > 0 {
		fullUrl = fullUrl + "?" + strings.Join(qsParams, "&")
	}

	req, err := http.NewRequest(verb, fullUrl, nil)
	if err != nil {
		return "", err
	}

	req.Header.Add("Authorization", authHeader)

	c := http.DefaultClient

	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	body, err := ioutil.ReadAll(resp.Body)
	return string(body), nil

}
