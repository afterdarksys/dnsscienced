package main

import "testing"

func TestFormatActionCountsIsDeterministic(t *testing.T) {
	got := formatActionCounts(map[string]uint64{
		"remove":      3,
		"add":         2,
		"state_reset": 1,
	})
	if got != "add=2,remove=3,state_reset=1" {
		t.Fatalf("formatActionCounts = %q", got)
	}
	if got := formatActionCounts(nil); got != "none" {
		t.Fatalf("empty formatActionCounts = %q", got)
	}
}
