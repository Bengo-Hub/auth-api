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

// Revision is a later version written in the repository instead of the dashboard, for a change
// that must ship with the code that needs it (Login with TikTok in the privacy policy). cmd/seed
// publishes it once, only while After is still the newest version of the type and no draft is
// open; a type that has moved on in the dashboard is left alone. A published version is never
// edited: a revision is always a new version.
type Revision struct {
	Document
	// Version is the new version label; After is the version it follows.
	Version string
	After   string
	// Summary is the change summary shown in the dashboard and on the version page.
	Summary string
}

// A revision is always published as a non-material change, in force from the day it is seeded:
// the seeder sends no email and asks nobody to accept again. A material change goes through the
// dashboard, which gives notice and emails every user.

// Revisions are the repository revisions, oldest first.
var Revisions = []Revision{
	{
		Document: Document{DocType: "PRIVACY_POLICY", Title: "Privacy Policy", File: "privacy-policy-v2.html"},
		Version:  "2",
		After:    "1",
		Summary:  "Adds Section 5G, Login with TikTok: the open ID, display name and avatar we receive, no email, and how to unlink. Deletion requests for Google and TikTok sign-in data go through the Data Requests page.",
	},
	{
		Document: Document{DocType: "PRIVACY_POLICY", Title: "Privacy Policy", File: "privacy-policy-v3.html"},
		Version:  "3",
		After:    "2",
		Summary:  "Google Ads: conversions are sent through Google's Data Manager API, for qualified leads, bookings and sales, with the click identifier, time, value, currency, conversion and a reference number. No names, emails or phone numbers.",
	},
}

// HTML returns the document's body.
func (d Document) HTML() (string, error) {
	b, err := files.ReadFile(d.File)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
