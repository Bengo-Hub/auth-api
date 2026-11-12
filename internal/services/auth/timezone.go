package auth

import (
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
)

// tenantTimezone is the tenant's stored zone, or "" when it has none.
func tenantTimezone(t *ent.Tenant) string {
	if t == nil || t.Timezone == nil {
		return ""
	}
	return *t.Timezone
}

// DefaultTimezone is the zone a tenant or user gets when nothing better is known. Codevertex's
// market is Kenya first, so it is East Africa Time.
const DefaultTimezone = "Africa/Nairobi"

// countryTimezones is the usual zone for the countries we serve and our customers come from, used
// when sign-up sends a country but no zone the server can use. A country with several zones (US,
// CD) gets its most populous one; the person can change it later.
var countryTimezones = map[string]string{
	"KE": "Africa/Nairobi", "UG": "Africa/Kampala", "TZ": "Africa/Dar_es_Salaam", "RW": "Africa/Kigali",
	"BI": "Africa/Bujumbura", "ET": "Africa/Addis_Ababa", "SS": "Africa/Juba", "SO": "Africa/Mogadishu",
	"DJ": "Africa/Djibouti", "ER": "Africa/Asmara", "CD": "Africa/Kinshasa", "ZM": "Africa/Lusaka",
	"MW": "Africa/Blantyre", "MZ": "Africa/Maputo", "ZW": "Africa/Harare", "ZA": "Africa/Johannesburg",
	"BW": "Africa/Gaborone", "NA": "Africa/Windhoek", "NG": "Africa/Lagos", "GH": "Africa/Accra",
	"EG": "Africa/Cairo", "MA": "Africa/Casablanca", "SN": "Africa/Dakar", "CM": "Africa/Douala",
	"GB": "Europe/London", "DE": "Europe/Berlin", "FR": "Europe/Paris", "NL": "Europe/Amsterdam",
	"AE": "Asia/Dubai", "SA": "Asia/Riyadh", "IN": "Asia/Kolkata", "CN": "Asia/Shanghai",
	"US": "America/New_York", "CA": "America/Toronto",
}

// ValidTimezone reports whether tz is an IANA zone name the server can load. "UTC" and "Local" are
// refused for people and organisations: they are what a browser or server reports when it knows
// nothing, not a choice.
func ValidTimezone(tz string) bool {
	tz = strings.TrimSpace(tz)
	if tz == "" || strings.EqualFold(tz, "UTC") || strings.EqualFold(tz, "Local") {
		return false
	}
	_, err := time.LoadLocation(tz)
	return err == nil
}

// ResolveTimezone picks a zone in order: the first valid explicit one (what the sign-up browser
// detected or the person picked), then the country's usual zone, then DefaultTimezone.
func ResolveTimezone(country string, explicit ...string) string {
	for _, tz := range explicit {
		if ValidTimezone(tz) {
			return strings.TrimSpace(tz)
		}
	}
	if tz, ok := countryTimezones[strings.ToUpper(strings.TrimSpace(country))]; ok {
		return tz
	}
	return DefaultTimezone
}
