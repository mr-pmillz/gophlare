package metrics

import (
	"slices"
	"testing"
)

func TestLookupQuotaClass(t *testing.T) {
	tests := []struct {
		name     string
		endpoint Endpoint
		want     QuotaClass
		wantStr  string
	}{
		{"global events search bills quota", EndpointGlobalEventsSearch, QuotaYes, "yes"},
		{"astp credentials search does not bill", EndpointASTPCredentialsSearch, QuotaNo, "no"},
		{"astp cookies search does not bill", EndpointASTPCookiesSearch, QuotaNo, "no"},
		{"token generation does not bill", EndpointTokenGenerate, QuotaNo, "no"},
		{"activity retrieval does not bill", EndpointActivityByID, QuotaNo, "no"},
		{"bulk accounts billing is undocumented", EndpointBulkAccounts, QuotaUnknown, "?"},
		{"identity next page billing is undocumented", EndpointIdentityNext, QuotaUnknown, "?"},
		{"unregistered endpoint is unknown", Endpoint("/some/new/endpoint"), QuotaUnknown, "?"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Lookup(tt.endpoint)

			if got.Quota != tt.want {
				t.Errorf("Lookup(%q).Quota = %v, want %v", tt.endpoint, got.Quota, tt.want)
			}
			if got.Quota.String() != tt.wantStr {
				t.Errorf("Lookup(%q).Quota.String() = %q, want %q", tt.endpoint, got.Quota.String(), tt.wantStr)
			}
			if got.Endpoint != tt.endpoint {
				t.Errorf("Lookup(%q).Endpoint = %q, want %q", tt.endpoint, got.Endpoint, tt.endpoint)
			}
		})
	}
}

func TestLookupRateLimitTier(t *testing.T) {
	tests := []struct {
		name     string
		endpoint Endpoint
		want     RateLimitTier
	}{
		{"global events search is a search endpoint", EndpointGlobalEventsSearch, TierSearch},
		{"astp credentials search is a search endpoint", EndpointASTPCredentialsSearch, TierSearch},
		{"astp cookies search is a search endpoint", EndpointASTPCookiesSearch, TierSearch},
		{"activity retrieval is a basic endpoint", EndpointActivityByID, TierBasic},
		{"activity download is a basic endpoint", EndpointActivityDownload, TierBasic},
		{"token generation is a basic endpoint", EndpointTokenGenerate, TierBasic},
		{"unregistered endpoint defaults to basic", Endpoint("/some/new/endpoint"), TierBasic},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Lookup(tt.endpoint).Tier; got != tt.want {
				t.Errorf("Lookup(%q).Tier = %q, want %q", tt.endpoint, got, tt.want)
			}
		})
	}
}

func TestKnownEndpointsIsSortedAndComplete(t *testing.T) {
	got := KnownEndpoints()

	if len(got) != 9 {
		t.Errorf("KnownEndpoints() returned %d endpoints, want 9", len(got))
	}
	if !slices.IsSorted(got) {
		t.Errorf("KnownEndpoints() is not sorted: %v", got)
	}
	for _, want := range []Endpoint{EndpointGlobalEventsSearch, EndpointIdentityNext} {
		if !slices.Contains(got, want) {
			t.Errorf("KnownEndpoints() missing %q", want)
		}
	}
}

// TestOnlyGlobalSearchBillsQuota guards the report's central claim. If a future
// endpoint is added as quota-bearing, this test should be updated deliberately
// rather than incidentally.
func TestOnlyGlobalSearchBillsQuota(t *testing.T) {
	for _, e := range KnownEndpoints() {
		info := Lookup(e)
		if info.Quota == QuotaYes && e != EndpointGlobalEventsSearch {
			t.Errorf("endpoint %q is marked QuotaYes; only %q should bill", e, EndpointGlobalEventsSearch)
		}
	}
}
