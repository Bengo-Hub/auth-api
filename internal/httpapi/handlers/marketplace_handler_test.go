package handlers

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestParseUseCaseList(t *testing.T) {
	got := parseUseCaseList(" Retail, hospitality,,retail , CAFE ")
	want := []string{"retail", "hospitality", "cafe"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if len(parseUseCaseList("")) != 0 {
		t.Fatal("an empty value filters nothing")
	}
	many := make([]string, maxUseCaseFilter+10)
	for i := range many {
		many[i] = fmt.Sprintf("uc%d", i)
	}
	if n := len(parseUseCaseList(strings.Join(many, ","))); n != maxUseCaseFilter {
		t.Fatalf("list is capped at %d, got %d", maxUseCaseFilter, n)
	}
}
