package models

import (
	"fmt"
	"net/url"

	"github.com/gophish/gophish/evilginx"
	check "gopkg.in/check.v1"
)

type mockTemplateContext struct {
	URL           string
	FromAddress   string
	EncryptionKey string
	EvilginxMode  bool
}

func (m mockTemplateContext) getFromAddress() string {
	return m.FromAddress
}

func (m mockTemplateContext) getBaseURL() string {
	return m.URL
}

func (m mockTemplateContext) getEncryptionKey() string {
	return m.EncryptionKey
}

func (m mockTemplateContext) getEvilginxMode() bool {
	return m.EvilginxMode
}

func (s *ModelsSuite) TestNewTemplateContext(c *check.C) {
	r := Result{
		BaseRecipient: BaseRecipient{
			FirstName: "Foo",
			LastName:  "Bar",
			Email:     "foo@bar.com",
		},
		RId: "1234567",
	}
	ctx := mockTemplateContext{
		URL:         "http://example.com",
		FromAddress: "From Address <from@example.com>",
	}
	expected := PhishingTemplateContext{
		URL:           fmt.Sprintf("%s?rid=%s", ctx.URL, r.RId),
		BaseURL:       ctx.URL,
		BaseRecipient: r.BaseRecipient,
		TrackingURL:   fmt.Sprintf("%s/track?rid=%s", ctx.URL, r.RId),
		BrandingURL:   "http://example.com/branding",
		From:          "From Address",
		RId:           r.RId,
	}
	expected.Tracker = "<img alt='' style='display: none' src='" + expected.TrackingURL + "'/>"
	got, err := NewPhishingTemplateContext(ctx, r.BaseRecipient, r.RId)
	c.Assert(err, check.Equals, nil)
	c.Assert(got, check.DeepEquals, expected)
}

func (s *ModelsSuite) TestNewTemplateContextEvilginxMode(c *check.C) {
	r := Result{
		BaseRecipient: BaseRecipient{
			FirstName: "Foo",
			LastName:  "Bar",
			Email:     "foo@bar.com",
		},
		RId: "1234567",
	}
	encKey := "test-encryption-key"
	lure := "https://login.example-lure.com/AbCdEf"
	custom := url.Values{}
	custom.Set("customer", "acme")
	lureURL, _ := url.Parse(lure)
	evilginx.AddPhishUrlParams(lureURL, custom, encKey)

	ctx := mockTemplateContext{
		URL:           lureURL.String(),
		FromAddress:   "From Address <from@example.com>",
		EncryptionKey: encKey,
		EvilginxMode:  true,
	}
	got, err := NewPhishingTemplateContext(ctx, r.BaseRecipient, r.RId)
	c.Assert(err, check.Equals, nil)

	// The lure path must survive; params must come back decrypted
	phish, err := url.Parse(got.URL)
	c.Assert(err, check.Equals, nil)
	c.Assert(phish.Path, check.Equals, "/AbCdEf")
	found := false
	for _, v := range phish.Query() {
		params, ok, err := evilginx.ExtractPhishUrlParams(v[0], encKey)
		if err != nil {
			c.Fatalf("decrypting phishing param failed: %v", err)
		}
		if ok {
			found = true
			c.Assert(params["rid"], check.Equals, r.RId)
			c.Assert(params["email"], check.Equals, "foo@bar.com")
			c.Assert(params["fname"], check.Equals, "Foo")
			c.Assert(params["lname"], check.Equals, "Bar")
			c.Assert(params["customer"], check.Equals, "acme")
		}
	}
	c.Assert(found, check.Equals, true)

	// Tracking URL must decrypt to rid + o=track
	track, err := url.Parse(got.TrackingURL)
	c.Assert(err, check.Equals, nil)
	c.Assert(track.Path, check.Equals, "/AbCdEf")
	found = false
	for _, v := range track.Query() {
		params, ok, err := evilginx.ExtractPhishUrlParams(v[0], encKey)
		c.Assert(err, check.Equals, nil)
		if ok {
			found = true
			c.Assert(params["rid"], check.Equals, r.RId)
			c.Assert(params["o"], check.Equals, "track")
		}
	}
	c.Assert(found, check.Equals, true)
	c.Assert(got.Tracker, check.Equals, "<img alt='' style='display: none' src='"+got.TrackingURL+"'/>")
}
