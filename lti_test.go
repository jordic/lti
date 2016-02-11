package lti

import (
	"log"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jordic/lti/oauth"
)

func TestCreateRequest(t *testing.T) {
	signer := oauth.GetHMACSigner("asdf", "")

	p := &Provider{
		Secret:      "asdf",
		URL:         "http://urltest.com/",
		ConsumerKey: "12345",
		Method:      "post",
	}

	p.Add("resource_link_id", "1086").
		Add("context_id", "2").
		Add("roles", "Instructor,Administrator").
		Add("custom_username", "test").
		SetSigner(signer)

	sig, err := p.Sign()
	if err != nil {
		t.Errorf("Error signing %s", err)
	}
	if sig == "" {
		t.Errorf("Request should be signed")
	}

	if p.Get("oauth_signature") != sig {
		t.Errorf("Request should be signed, %s", p.Get("oauth_signature"))
		log.Printf("%#v", p.values)
	}

	if p.Get("oauth_signature_method") != SigHMAC {
		t.Errorf("Signature method should be HMAC")
	}

	u, _ := url.Parse("http://urltest.com/")

	r := &http.Request{
		Method: "POST",
		URL:    u,
		Body:   nil,
		Form:   p.Params(),
	}

	pp := NewProvider("asdf", "http://urltest.com/")
	pp.ConsumerKey = "12345"
	ok, err := pp.IsValid(r)
	if err != nil {
		t.Errorf("Error parsing request %s", err)
	}
	if ok != true {
		t.Errorf("Request should be valid")
	}

}

func TestHasRole(t *testing.T) {
	p := NewProvider("asdf", "http://localhost")
	p.Add("roles", "Instructor,Admin")
	if p.HasRole("Admin") != true {
		t.Error("Provicer should respond to true, with role admin")
	}
	if p.HasRole("Teacher") == true {
		t.Error("Role should fail because is not defined")
	}
	if p.HasRole("Inst") == true {
		t.Error("Should fail with substrings")
	}
}

func TestFailWrongConsumerKey(t *testing.T) {
	p := NewProvider("asdf", "http://urltest.com/")
	p.ConsumerKey = "Invalid"

	r := &http.Request{
		Method: "POST",
		Body:   nil,
		Form:   p.Params(),
	}

	ok, _ := p.IsValid(r)
	if ok == true {
		t.Error("Should fail because incorrect consumer key")
	}
}

func TestCurrentSigner(t *testing.T) {
	p := NewProvider("asdf", "http://urltest.com/")
	p.ConsumerKey = "12345"

	form := GenerateForm()
	form.Set("oauth_signature_method", "PLAINTEXT")

	r := &http.Request{
		Method: "POST",
		Body:   nil,
		Form:   form,
	}

	ok, err := p.IsValid(r)
	if ok == true {
		t.Error("Should fail because incorrect consumer key")
	}
	log.Print(err.Error())
	if !strings.Contains(err.Error(), "wrong signature") {
		t.Error("Should contain error in consumer type")
	}

}

func TestSign(t *testing.T) {

	vals := GenerateForm()

	res, err := getBaseString("post",
		"http://www.imsglobal.org/developers/LTI/test/v1p1/tool.php",
		vals)

	if err != nil {
		log.Printf("Error generating base string for oauth")
	}

	if len(res) != len(OT) {
		t.Errorf("Wrong lengths %d, %d", len(res), len(OT))
	}

	for i := range res {
		if res[i] != OT[i] {
			t.Errorf("%s, %s", res[i:(i+15)], OT[i:(i+15)])
			break
		}
	}

	if res != OT {
		t.Errorf("%s\n%s", OT, res)
	}

	signer := oauth.GetHMACSigner("secret", "")
	signed, err := Sign(vals,
		"http://www.imsglobal.org/developers/LTI/test/v1p1/tool.php",
		"post", signer)

	if err != nil {
		t.Errorf("Error sigining request %s", err)
	}

	if signed != "QWgJfKpJNDrpncgO9oXxJb8vHiE=" {
		t.Errorf("Provided %s", signed)
	}

}

func GenerateForm() url.Values {
	v := url.Values{}
	v.Add("context_id", "456434513")
	v.Add("context_label", "SI182")
	v.Add("context_title", "Design of Personal Environments")
	v.Add("launch_presentation_css_url", "http://www.imsglobal.org/developers/LTI/test/v1p1/lms.css")
	v.Add("launch_presentation_document_target", "frame")
	v.Add("launch_presentation_locale", "en-US")
	v.Add("launch_presentation_return_url", "http://www.imsglobal.org/developers/LTI/test/v1p1/lms_return.php")
	v.Add("lis_outcome_service_url", "http://www.imsglobal.org/developers/LTI/test/v1p1/common/tool_consumer_outcome.php?b64=MTIzNDU6OjpzZWNyZXQ=")
	v.Add("lis_person_contact_email_primary", "user@school.edu")
	v.Add("lis_person_name_family", "Public")
	v.Add("lis_person_name_full", "Jane Q. Public")
	v.Add("lis_person_name_given", "Given")
	v.Add("lis_person_sourcedid", "school.edu:user")
	v.Add("lis_result_sourcedid", "feb-123-456-2929::28883")
	v.Add("lti_message_type", "basic-lti-launch-request")
	v.Add("lti_version", "LTI-1p0")
	v.Add("oauth_callback", "about:blank")
	v.Add("oauth_consumer_key", "12345")
	v.Add("oauth_nonce", "93ac608e18a7d41dec8f7219e1bf6a17")
	// v.Add("oauth_signature", "QWgJfKpJNDrpncgO9oXxJb8vHiE=")
	v.Add("oauth_signature_method", "HMAC-SHA1")
	v.Add("oauth_timestamp", "1348093590")
	v.Add("oauth_version", "1.0")
	v.Add("resource_link_description", "A weekly blog.")
	v.Add("resource_link_id", "120988f929-274612")
	v.Add("resource_link_title", "Weekly Blog")
	v.Add("roles", "Instructor")
	v.Add("tool_consumer_info_product_family_code", "ims")
	v.Add("tool_consumer_info_version", "1.1")
	v.Add("tool_consumer_instance_description", "University of School (LMSng)")
	v.Add("tool_consumer_instance_guid", "lmsng.school.edu")
	v.Add("user_id", "292832126")
	return v

}

var OT = "POST&http%3A%2F%2Fwww.imsglobal.org%2Fdevelopers%2FLTI%2Ftest%2Fv1p1%2Ftool.php&context_id%3D456434513%26context_label%3DSI182%26context_title%3DDesign%2520of%2520Personal%2520Environments%26launch_presentation_css_url%3Dhttp%253A%252F%252Fwww.imsglobal.org%252Fdevelopers%252FLTI%252Ftest%252Fv1p1%252Flms.css%26launch_presentation_document_target%3Dframe%26launch_presentation_locale%3Den-US%26launch_presentation_return_url%3Dhttp%253A%252F%252Fwww.imsglobal.org%252Fdevelopers%252FLTI%252Ftest%252Fv1p1%252Flms_return.php%26lis_outcome_service_url%3Dhttp%253A%252F%252Fwww.imsglobal.org%252Fdevelopers%252FLTI%252Ftest%252Fv1p1%252Fcommon%252Ftool_consumer_outcome.php%253Fb64%253DMTIzNDU6OjpzZWNyZXQ%253D%26lis_person_contact_email_primary%3Duser%2540school.edu%26lis_person_name_family%3DPublic%26lis_person_name_full%3DJane%2520Q.%2520Public%26lis_person_name_given%3DGiven%26lis_person_sourcedid%3Dschool.edu%253Auser%26lis_result_sourcedid%3Dfeb-123-456-2929%253A%253A28883%26lti_message_type%3Dbasic-lti-launch-request%26lti_version%3DLTI-1p0%26oauth_callback%3Dabout%253Ablank%26oauth_consumer_key%3D12345%26oauth_nonce%3D93ac608e18a7d41dec8f7219e1bf6a17%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1348093590%26oauth_version%3D1.0%26resource_link_description%3DA%2520weekly%2520blog.%26resource_link_id%3D120988f929-274612%26resource_link_title%3DWeekly%2520Blog%26roles%3DInstructor%26tool_consumer_info_product_family_code%3Dims%26tool_consumer_info_version%3D1.1%26tool_consumer_instance_description%3DUniversity%2520of%2520School%2520%2528LMSng%2529%26tool_consumer_instance_guid%3Dlmsng.school.edu%26user_id%3D292832126"
