package handlers

import (
	"fmt"
	"strconv"
	"strings"
)

// MetadataKeyOpeningHours is the tenant metadata key holding the tenant's weekly trading hours
// (22 November 2026). auth-api owns it; every service and site reads it through the shared tenant
// cache (cache.OpeningHoursFromMetadata, cache.IsOpenAt) and evaluates it in the tenant's
// timezone, so the store, the POS and the public website all agree:
//
//	"opening_hours": {"monday": {"open": "07:30", "close": "22:30"}, ...,
//	                  "saturday": [{"open": "08:00", "close": "14:00"}, {"open": "17:00", "close": "23:00"}]}
//
// A day left out is closed. A close earlier than the open runs past midnight. No key at all means
// the tenant has not set hours, and readers treat it as always open. An outlet can still override
// it with its own hours in the owning service (ordering outlets.opening_hours).
const MetadataKeyOpeningHours = "opening_hours"

// openingHoursDays are the accepted day keys, lowercase English as Go's time.Weekday prints them.
var openingHoursDays = map[string]bool{
	"monday": true, "tuesday": true, "wednesday": true, "thursday": true,
	"friday": true, "saturday": true, "sunday": true,
}

// maxOpeningPeriodsPerDay bounds the split shifts a day can carry.
const maxOpeningPeriodsPerDay = 4

// normalizeOpeningClock checks an "HH:MM" clock (24:00 allowed as end of day) and returns it zero
// padded, so "7:30" is stored as "07:30".
func normalizeOpeningClock(day, field string, raw any) (string, error) {
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("opening_hours.%s.%s must be a time like 07:30", day, field)
	}
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("opening_hours.%s.%s must be a time like 07:30", day, field)
	}
	h, errH := strconv.Atoi(parts[0])
	m, errM := strconv.Atoi(parts[1])
	if errH != nil || errM != nil || len(parts[1]) != 2 || h < 0 || m < 0 || m > 59 || h > 24 || (h == 24 && m != 0) {
		return "", fmt.Errorf("opening_hours.%s.%s must be a time like 07:30", day, field)
	}
	return fmt.Sprintf("%02d:%02d", h, m), nil
}

// normalizeOpeningPeriod validates one {"open","close"} period.
func normalizeOpeningPeriod(day string, raw any) (map[string]any, error) {
	in, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("opening_hours.%s must be {\"open\": \"07:30\", \"close\": \"22:30\"} or a list of them", day)
	}
	for k := range in {
		if k != "open" && k != "close" {
			return nil, fmt.Errorf("opening_hours.%s.%s is not a field (use open and close)", day, k)
		}
	}
	open, err := normalizeOpeningClock(day, "open", in["open"])
	if err != nil {
		return nil, err
	}
	closing, err := normalizeOpeningClock(day, "close", in["close"])
	if err != nil {
		return nil, err
	}
	if open == closing {
		return nil, fmt.Errorf("opening_hours.%s opens and closes at the same time", day)
	}
	return map[string]any{"open": open, "close": closing}, nil
}

// normalizeTenantOpeningHours validates the opening_hours value submitted in a tenant create or
// update and returns the clean object to store. The schedule is replaced as a whole. null or an
// empty object returns nil (the caller removes the key: hours not set).
func normalizeTenantOpeningHours(submitted any) (map[string]any, error) {
	if submitted == nil {
		return nil, nil
	}
	in, ok := submitted.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("opening_hours must be an object keyed by day (monday to sunday)")
	}
	clean := map[string]any{}
	for rawDay, v := range in {
		day := strings.ToLower(strings.TrimSpace(rawDay))
		if !openingHoursDays[day] {
			return nil, fmt.Errorf("opening_hours.%s is not a day (use monday to sunday)", rawDay)
		}
		if v == nil {
			continue // closed that day
		}
		if list, isList := v.([]any); isList {
			if len(list) > maxOpeningPeriodsPerDay {
				return nil, fmt.Errorf("opening_hours.%s has more than %d periods", day, maxOpeningPeriodsPerDay)
			}
			periods := make([]any, 0, len(list))
			for _, p := range list {
				period, err := normalizeOpeningPeriod(day, p)
				if err != nil {
					return nil, err
				}
				periods = append(periods, period)
			}
			if len(periods) > 0 {
				clean[day] = periods
			}
			continue
		}
		period, err := normalizeOpeningPeriod(day, v)
		if err != nil {
			return nil, err
		}
		clean[day] = period
	}
	if len(clean) == 0 {
		return nil, nil
	}
	return clean, nil
}

// tenantOpeningHoursPayload is the schedule as published on auth.tenant.created/updated: the stored
// object, or an empty one when unset so a consumer can tell "cleared" from "not sent".
func tenantOpeningHoursPayload(meta map[string]any) map[string]any {
	if stored, ok := meta[MetadataKeyOpeningHours].(map[string]any); ok {
		return stored
	}
	return map[string]any{}
}

// applyTenantOpeningHoursMetadata validates a submitted schedule into metadata (the tenant create
// and update merge): a valid value is stored, an empty one removes the key. The error is the 400
// message.
func applyTenantOpeningHoursMetadata(metadata map[string]any, submitted any) error {
	clean, err := normalizeTenantOpeningHours(submitted)
	if err != nil {
		return err
	}
	if clean == nil {
		delete(metadata, MetadataKeyOpeningHours)
		return nil
	}
	metadata[MetadataKeyOpeningHours] = clean
	return nil
}
