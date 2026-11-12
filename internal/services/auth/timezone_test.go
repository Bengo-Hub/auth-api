package auth

import "testing"

func TestResolveTimezone(t *testing.T) {
	cases := []struct {
		name, country string
		explicit      []string
		want          string
	}{
		{"browser zone wins", "KE", []string{"Africa/Kampala"}, "Africa/Kampala"},
		{"first valid explicit zone", "", []string{"Not/AZone", "Europe/London"}, "Europe/London"},
		{"UTC is not a choice, the country decides", "UG", []string{"UTC"}, "Africa/Kampala"},
		{"country fallback", "tz", nil, "Africa/Dar_es_Salaam"},
		{"nothing known: Nairobi", "", nil, DefaultTimezone},
		{"unknown country: Nairobi", "XX", []string{""}, DefaultTimezone},
	}
	for _, c := range cases {
		if got := ResolveTimezone(c.country, c.explicit...); got != c.want {
			t.Errorf("%s: ResolveTimezone = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestCountryTimezonesAreLoadable(t *testing.T) {
	for country, tz := range countryTimezones {
		if !ValidTimezone(tz) {
			t.Errorf("%s maps to %q, which does not load", country, tz)
		}
	}
}
