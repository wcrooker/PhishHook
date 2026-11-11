package models

import (
	"bytes"
	"net/mail"
	"net/url"
	"path"
	"text/template"

	"github.com/gophish/gophish/evilginx"
)

// TemplateContext is an interface that allows both campaigns and email
// requests to have a PhishingTemplateContext generated for them.
type TemplateContext interface {
	getFromAddress() string
	getBaseURL() string
	getEncryptionKey() string
	getEvilginxMode() bool
}

// PhishingTemplateContext is the context that is sent to any template, such
// as the email or landing page content.
type PhishingTemplateContext struct {
	From        string
	URL         string
	Tracker     string
	TrackingURL string
	RId         string
	BaseURL     string
	BaseRecipient
}

// NewPhishingTemplateContext returns a populated PhishingTemplateContext,
// parsing the correct fields from the provided TemplateContext and recipient.
func NewPhishingTemplateContext(ctx TemplateContext, r BaseRecipient, rid string) (PhishingTemplateContext, error) {
	f, err := mail.ParseAddress(ctx.getFromAddress())
	if err != nil {
		return PhishingTemplateContext{}, err
	}
	fn := f.Name
	if fn == "" {
		fn = f.Address
	}
	templateURL, err := ExecuteTemplate(ctx.getBaseURL(), r)
	if err != nil {
		return PhishingTemplateContext{}, err
	}

	// For the base URL, we'll reset the the path and the query
	// This will create a URL in the form of http://example.com
	baseURL, err := url.Parse(templateURL)
	if err != nil {
		return PhishingTemplateContext{}, err
	}
	baseURL.Path = ""
	baseURL.RawQuery = ""

	var phishURL, trackingURL *url.URL
	if ctx.getEvilginxMode() {
		var err error
		phishURL, trackingURL, err = evilginxLureContext(templateURL, ctx.getEncryptionKey(), r, rid)
		if err != nil {
			return PhishingTemplateContext{}, err
		}
	} else {
		phishURL, _ = url.Parse(templateURL)
		q := phishURL.Query()
		q.Set(RecipientParameter, rid)
		phishURL.RawQuery = q.Encode()

		trackingURL, _ = url.Parse(templateURL)
		trackingURL.Path = path.Join(trackingURL.Path, "/track")
		trackingURL.RawQuery = q.Encode()
	}

	return PhishingTemplateContext{
		BaseRecipient: r,
		BaseURL:       baseURL.String(),
		URL:           phishURL.String(),
		TrackingURL:   trackingURL.String(),
		Tracker:       "<img alt='' style='display: none' src='" + trackingURL.String() + "'/>",
		From:          fn,
		RId:           rid,
	}, nil
}

// evilginxLureContext builds the per-recipient phishing and tracking URLs
// for an evilginx lure URL: custom parameters are extracted, personalized
// values appended, and the result re-encrypted. The tracking URL carries
// rid + o=track so evilginx serves the open-pixel and reports the result.
func evilginxLureContext(templateURL, encKey string, r BaseRecipient, rid string) (*url.URL, *url.URL, error) {
	baseLureURL, err := url.Parse(templateURL)
	if err != nil {
		return nil, nil, err
	}

	q := url.Values{}
	urlQuery := url.Values{}
	for k, v := range baseLureURL.Query() {
		params, ok, _ := evilginx.ExtractPhishUrlParams(v[0], encKey)
		if ok {
			for pk, pv := range params {
				q.Set(pk, pv)
			}
		} else {
			urlQuery.Set(k, v[0])
		}
	}
	baseLureURL.RawQuery = urlQuery.Encode()

	phishURL := *baseLureURL
	q.Set("fname", r.FirstName)
	q.Set("lname", r.LastName)
	q.Set("email", r.Email)
	q.Set("rid", rid)
	evilginx.AddPhishUrlParams(&phishURL, q, encKey)

	trackingURL := *baseLureURL
	tq := url.Values{}
	tq.Set("rid", rid)
	tq.Set("o", "track")
	evilginx.AddPhishUrlParams(&trackingURL, tq, encKey)

	return &phishURL, &trackingURL, nil
}

// ExecuteTemplate creates a templated string based on the provided
// template body and data.
func ExecuteTemplate(text string, data interface{}) (string, error) {
	buff := bytes.Buffer{}
	tmpl, err := template.New("template").Parse(text)
	if err != nil {
		return buff.String(), err
	}
	err = tmpl.Execute(&buff, data)
	return buff.String(), err
}

// ValidationContext is used for validating templates and pages
type ValidationContext struct {
	FromAddress   string
	BaseURL       string
	EncryptionKey string
	EvilginxMode  bool
}

func (vc ValidationContext) getFromAddress() string {
	return vc.FromAddress
}

func (vc ValidationContext) getBaseURL() string {
	return vc.BaseURL
}

func (vc ValidationContext) getEncryptionKey() string {
	return vc.EncryptionKey
}

func (vc ValidationContext) getEvilginxMode() bool {
	return vc.EvilginxMode
}

// ValidateTemplate ensures that the provided text in the page or template
// uses the supported template variables correctly.
func ValidateTemplate(text string) error {
	vc := ValidationContext{
		FromAddress: "foo@bar.com",
		BaseURL:     "http://example.com",
	}
	td := Result{
		BaseRecipient: BaseRecipient{
			Email:     "foo@bar.com",
			FirstName: "Foo",
			LastName:  "Bar",
			Position:  "Test",
		},
		RId: "123456",
	}
	ptx, err := NewPhishingTemplateContext(vc, td.BaseRecipient, td.RId)
	if err != nil {
		return err
	}
	_, err = ExecuteTemplate(text, ptx)
	if err != nil {
		return err
	}
	return nil
}
