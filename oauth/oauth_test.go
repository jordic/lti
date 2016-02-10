package oauth

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"

	"encoding/pem"
	"fmt"
	"testing"
)

var pemPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC0YjCwIfYoprq/FQO6lb3asXrxLlJFuCvtinTF5p0GxvQGu5O3
gYytUvtC2JlYzypSRjVxwxrsuRcP3e641SdASwfrmzyvIgP08N4S0IFzEURkV1wp
/IpH7kH41EtbmUmrXSwfNZsnQRE5SYSOhh+LcK2wyQkdgcMv11l4KoBkcwIDAQAB
AoGAWFlbZXlM2r5G6z48tE+RTKLvB1/btgAtq8vLw/5e3KnnbcDD6fZO07m4DRaP
jRryrJdsp8qazmUdcY0O1oK4FQfpprknDjP+R1XHhbhkQ4WEwjmxPstZMUZaDWF5
8d3otc23mCzwh3YcUWFu09KnMpzZsK59OfyjtkS44EDWpbECQQDXgN0ODboKsuEA
VAhAtPUqspU9ivRa6yLai9kCnPb9GcztrsJZQm4NHcKVbmD2F2L4pDRx4Pmglhfl
V7G/a6T7AkEA1kfU0+DkXc6I/jXHJ6pDLA5s7dBHzWgDsBzplSdkVQbKT3MbeYje
ByOxzXhulOWLBQW/vxmW4HwU95KTRlj06QJASPoBYY3yb0cN/J94P/lHgJMDCNky
UEuJ/PoYndLrrN/8zow8kh91xwlJ6HJ9cTiQMmTgwaOOxPuu0eI1df4M2wJBAJJS
WrKUT1z/O+zbLDOZwGTFNPzvzRgmft4z4A1J6OlmyZ+XKpvDKloVtcRpCJoEZPn5
AwaroquID4k/PfI7rIECQHeWa6+kPADv9IrK/92mujujS0MSEiynDw5NjTnHAH0v
8TrXzs+LCWDN/gbOCKPfnWRkgwgOeC8NN3h0zUIIUtA=
-----END RSA PRIVATE KEY-----
`
var pemCertificate = `-----BEGIN CERTIFICATE-----
MIIBpjCCAQ+gAwIBAgIBATANBgkqhkiG9w0BAQUFADAZMRcwFQYDVQQDDA5UZXN0
IFByaW5jaXBhbDAeFw03MDAxMDEwODAwMDBaFw0zODEyMzEwODAwMDBaMBkxFzAV
BgNVBAMMDlRlc3QgUHJpbmNpcGFsMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQC0YjCwIfYoprq/FQO6lb3asXrxLlJFuCvtinTF5p0GxvQGu5O3gYytUvtC2JlY
zypSRjVxwxrsuRcP3e641SdASwfrmzyvIgP08N4S0IFzEURkV1wp/IpH7kH41Etb
mUmrXSwfNZsnQRE5SYSOhh+LcK2wyQkdgcMv11l4KoBkcwIDAQABMA0GCSqGSIb3
DQEBBQUAA4GBAGZLPEuJ5SiJ2ryq+CmEGOXfvlTtEL2nuGtr9PewxkgnOjZpUy+d
4TvuXJbNQc8f4AMWL/tO9w0Fk80rWKp9ea8/df4qMq5qlFWlx6yOLQxumNOmECKb
WpkUQDIDJEoFUzKMVuJf4KO/FJ345+BNLGgbJ6WujreoM1X/gYfdnJ/J
-----END CERTIFICATE-----
`

func getTestBaseString() string {
	return "GET&http%3A%2F%2Fphotos.example.net%3A8001%2FPhotos&oauth_consumer_key%3Ddpf43f3%252B%252Bp%252B%25232l4k3l03%26oauth_nonce%3Dkllo~9940~pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d%25280%25290sl2jdk%26oauth_version%3D1.0%26scenario%3D%25C3%2597%25C2%25AA%25C3%2597%25C2%2590%25C3%2597%25E2%2580%25A2%25C3%2597%25C3%2597%25E2%2580%259D%26type%3D%25C3%2597%25C2%2590%25C3%2597%25E2%2580%25A2%25C3%2597%25CB%259C%25C3%2597%25E2%2580%25A2%25C3%2597%25E2%2580%2598%25C3%2597%25E2%2580%25A2%25C3%2597%25C2%25A1"
}

func getTestPrivateKey() *rsa.PrivateKey {
	pemBlock, _ := pem.Decode([]byte(pemPrivateKey))

	pk, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		panic(err)
	}
	return pk
}

func TestBaseString(t *testing.T) {
	fmt.Println("Start")

	oauthParameters := []KV{
		KV{"oauth_consumer_key", "dpf43f3++p+#2l4k3l03"},
		KV{"oauth_token", "nnch734d(0)0sl2jdk"},
		KV{"oauth_nonce", "kllo~9940~pd9333jh"},
		KV{"oauth_timestamp", "1191242096"},
		KV{"oauth_signature_method", "HMAC-SHA1"},
		KV{"oauth_version", "1.0"},
	}
	queryParameters := []KV{
		KV{"type", "××•×˜×•×‘×•×¡"},
		KV{"scenario", "×ª××•××”"},
	}

	formParameters := []KV{}

	allParameters := MergeRequestParameters(queryParameters, oauthParameters, formParameters)

	baseUrlString, err := GetBaseString("GET", "http://photos.example.net:8001/Photos", allParameters)
	if err != nil {
		panic(err)
	}

	if baseUrlString != getTestBaseString() {
		fmt.Println("Strings didn't match")
		fmt.Println(baseUrlString)
		t.Fail()
	}

}

func TestHmac(t *testing.T) {
	hme := GetHMACSigner("kd9@4h%%4f93k423kf44", "pfkkd#hi9_sl-3r=4s00")
	hm, _ := (&hme).GetSignature(getTestBaseString())

	if hm != "YwOJt8zeOTkKa+Xs8oV+O0LXzFE=" {
		fmt.Println("Signature didn't match")
		fmt.Println(hm)
		t.Fail()
	}
}

func TestRsa(t *testing.T) {
	privateKey := getTestPrivateKey()
	r := GetRSASigner(privateKey)
	s, err := r.GetSignature(getTestBaseString())
	if err != nil {
		panic(err)
	}
	fmt.Println(s)
}

func TestUsingServerHMAC(t *testing.T) {

	fmt.Println("Test Using Server")
	ConsumerKey := "key"
	ConsumerSecret := "secret"
	Token := "accesskey"
	TokenSecret := "accesssecret"

	oa := &OAuthParameters{
		Signer:         GetHMACSigner(ConsumerSecret, TokenSecret), //GetRSASigner(getTestPrivateKey()),
		ConsumerKey:    &ConsumerKey,
		ConsumerSecret: &ConsumerSecret,
		Token:          &Token,
		TokenSecret:    &TokenSecret,
	}

	response, err := oa.DoOauthRequest("GET", "http://term.ie/oauth/example/echo_api.php", []KV{KV{"one", "two"}})
	if err != nil {
		fmt.Println("Error Testing Using Sig")
		panic(err)
	}
	if response != "one=two" {
		fmt.Println(response)
		t.Error("Response didn't echo querystring")
	}
}

func TestUsingServerRSA(t *testing.T) {

	fmt.Println("Test Using Server RSA")
	ConsumerKey := "key"
	ConsumerSecret := "secret"
	Token := "accesskey"
	TokenSecret := "accesssecret"

	oa := &OAuthParameters{
		Signer:         GetRSASigner(getTestPrivateKey()),
		ConsumerKey:    &ConsumerKey,
		ConsumerSecret: &ConsumerSecret,
		Token:          &Token,
		TokenSecret:    &TokenSecret,
	}

	response, err := oa.DoOauthRequest("GET", "http://term.ie/oauth/example/echo_api.php", []KV{KV{"one", "two"}})
	if err != nil {
		fmt.Println("Error Testing Using Sig")
		panic(err)
	}
	if response != "one=two" {
		fmt.Println(response)
		t.Error("Response didn't echo querystring")
	}
}
