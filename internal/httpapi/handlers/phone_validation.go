package handlers

import (
	"fmt"
	"strings"

	"github.com/nyaruka/phonenumbers"
)

// validateAndNormalizePhone parses a phone number that MUST already carry a
// country calling code (E.164, e.g. "+254743793901" — exactly what
// react-phone-number-input's PhoneInputField in auth-ui always emits) and
// returns its canonical E.164 form, or an error if it isn't a real, valid
// number. Never call this for a value the request didn't actually change —
// legacy free-text numbers already on file are left alone until re-saved.
func validateAndNormalizePhone(raw string) (string, error) {
	num, err := phonenumbers.Parse(raw, "")
	if err != nil {
		return "", fmt.Errorf("could not parse phone number: %w", err)
	}
	if !phonenumbers.IsValidNumber(num) {
		return "", fmt.Errorf("not a valid phone number")
	}
	return phonenumbers.Format(num, phonenumbers.E164), nil
}

var supportedRegions = phonenumbers.GetSupportedRegions()

// isValidCountryCode reports whether code is a real ISO 3166-1 alpha-2 region
// recognized by libphonenumber's metadata — the exact same list auth-ui's
// CountrySelect (react-phone-number-input's getCountries()) offers.
func isValidCountryCode(code string) bool {
	return supportedRegions[strings.ToUpper(code)]
}
