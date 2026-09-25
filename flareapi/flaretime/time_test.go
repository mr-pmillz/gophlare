package flaretime

import (
	"encoding/json"
	"testing"
	"time"
)

func TestUnmarshalJSONFlareFormats(t *testing.T) {
	tests := []struct {
		in   string
		want time.Time
	}{
		{`"2024-01-01T00:00:00Z"`, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		{`"2024-04-30T07:09:59+00:00"`, time.Date(2024, 4, 30, 7, 9, 59, 0, time.UTC)},
		{`"2025-02-24T02:49:48.997342+00:00"`, time.Date(2025, 2, 24, 2, 49, 48, 997342000, time.UTC)},
		{`"2019-09-20T16:30:37.589388Z"`, time.Date(2019, 9, 20, 16, 30, 37, 589388000, time.UTC)},
		{`"2026-03-04T02:22:08"`, time.Date(2026, 3, 4, 2, 22, 8, 0, time.UTC)},
		{`"2025-10-28T18:35:15.095033"`, time.Date(2025, 10, 28, 18, 35, 15, 95033000, time.UTC)},
		{`"2025-01-01"`, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
		{`null`, time.Time{}},
		{`""`, time.Time{}},
	}
	for _, tt := range tests {
		var got Time
		if err := json.Unmarshal([]byte(tt.in), &got); err != nil {
			t.Fatalf("unmarshal %s: %v", tt.in, err)
		}
		if !got.Equal(tt.want) {
			t.Errorf("unmarshal %s = %s, want %s", tt.in, got, tt.want)
		}
	}
}

func TestUnmarshalJSONRejectsUnknownFormat(t *testing.T) {
	var got Time
	if err := json.Unmarshal([]byte(`"yesterday"`), &got); err == nil {
		t.Fatal("expected an error for an unparseable timestamp")
	}
}

func TestZeroTimeIsOmittedWithOmitzero(t *testing.T) {
	type body struct {
		At Time `json:"at,omitzero"`
	}
	b, err := json.Marshal(body{})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{}` {
		t.Fatalf("zero time marshalled as %s", b)
	}
	b, err = json.Marshal(body{At: Time{time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"at":"2024-01-01T00:00:00Z"}` {
		t.Fatalf("time marshalled as %s", b)
	}
}

func TestScanAndValueRoundTrip(t *testing.T) {
	want := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	var got Time
	if err := got.Scan(want); err != nil {
		t.Fatal(err)
	}
	v, err := got.Value()
	if err != nil || v != want {
		t.Fatalf("value = %v, %v", v, err)
	}
	if err := got.Scan(nil); err != nil || !got.IsZero() {
		t.Fatalf("scan nil = %v, %v", got, err)
	}
	if v, err := got.Value(); err != nil || v != nil {
		t.Fatalf("zero value = %v, %v", v, err)
	}
	if err := got.Scan("2024-01-01"); err == nil {
		t.Fatal("expected an error scanning a string")
	}
}
