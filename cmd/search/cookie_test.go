package search

import (
	"testing"
)

func TestCheckExpirationRFC3339(t *testing.T) {
	type args struct {
		epochTimestamp int64
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "expired timestamp", args: args{epochTimestamp: 1609459200}, want: true}, // Friday, January 1, 2021 12:00:00 AM
		{name: "valid timestamp", args: args{epochTimestamp: 1791210273}, want: false},  // Monday, October 5, 2026 2:24:33 PM
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsCookieEpochExpiredRFC3339(tt.args.epochTimestamp)
			if got != tt.want {
				t.Errorf("IsCookieEpochExpiredRFC3339() got = %v, want %v", got, tt.want)
			}
		})
	}
}
