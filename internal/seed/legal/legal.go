// Package legal holds the first published version of each platform policy and of the MarketFlow
// Autopilot terms, as HTML bodies. cmd/seed publishes them as version 1 of a type that has no
// version yet. auth-ui renders the body inside its policy layout and builds the Contents list from
// the <h2> ids, which match the anchors of the built-in pages (#google-signin, #meta-data and so on).
// A later change is a new version published from the dashboard, never an edit of these files.
package legal

import "embed"

//go:embed *.html
var files embed.FS

// Document is one seeded legal document.
type Document struct {
	// DocType is the auth-api type as stored, for example PRIVACY_POLICY.
	DocType string
	// Title is the heading auth-ui shows above the body.
	Title string
	// File is the embedded HTML body.
	File string
}

// Documents is every seeded document, in the order the dashboard lists them.
var Documents = []Document{
	{DocType: "TERMS_OF_SERVICE", Title: "Terms of Service", File: "terms-of-service.html"},
	{DocType: "PRIVACY_POLICY", Title: "Privacy Policy", File: "privacy-policy.html"},
	{DocType: "COOKIE_POLICY", Title: "Cookie Policy", File: "cookie-policy.html"},
	{DocType: "REFUND_POLICY", Title: "Refund Policy", File: "refund-policy.html"},
	{DocType: "DATA_REQUESTS", Title: "Your data and your rights", File: "data-requests.html"},
	{DocType: "MARKETFLOW_AUTOPUBLISH_TERMS", Title: "MarketFlow Autopilot Terms", File: "marketflow-autopublish-terms.html"},
}

// HTML returns the document's body.
func (d Document) HTML() (string, error) {
	b, err := files.ReadFile(d.File)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
