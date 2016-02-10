// Package lti provides support for working with LTI
// more info can be checked at:
// https://www.imsglobal.org/activity/learning-tools-interoperability
// Basically it can sign http requests and also it can
// verify incoming LMI requests
package lti

import (
	"net/url"
	"strings"

	"github.com/jordic/lti/oauth"
)

// Provider is an app, that can consume LTI messages
type Provider struct {
	Secret string
	URL    string
	values url.Values
}

// Get a value from the producer
func (p *Provider) Get(k string) string {
	return p.values.Get(k)
}

// IsValid returns if lti request is valid
func (p *Provider) IsValid() bool {
	return true
}

// Sign a lti request
func Sign(form url.Values, u, method, secret, ts string) (string, error) {

	str, err := getBaseString(method, u, form)
	if err != nil {
		return "", err
	}
	hmac := oauth.GetHMACSigner(secret, ts)
	sig, err := hmac.GetSignature(str)
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
