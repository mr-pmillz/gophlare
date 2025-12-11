package search

import (
	"os"
	"testing"
	"time"

	"github.com/mr-pmillz/gophlare/utils"
)

func Test_dumpDicerNG(t *testing.T) {
	type args struct {
		domain         string
		flareOutputDir string
		creds          []FlareCredentialPairs
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "Test dumpDicerNG", args: args{domain: "example.com", flareOutputDir: "test", creds: []FlareCredentialPairs{
			{Email: "foo@example.com", Password: "Password123", Hash: "Password123", SourceID: "flare", Domain: "example.com", ImportedAt: time.Time{}, LeakedAt: nil, BreachedAt: nil},
			{Email: "bar@example.com", Password: "Password123!", Hash: "Password123!", SourceID: "flare", Domain: "example.com", ImportedAt: time.Time{}, LeakedAt: nil, BreachedAt: nil},
			{Email: "baz@example.com", Password: "Password123!!", Hash: "Password123!!", SourceID: "flare", Domain: "example.com", ImportedAt: time.Time{}, LeakedAt: nil, BreachedAt: nil},
			{Email: "fee@example.com", Password: "Password123@", Hash: "Password123@", SourceID: "flare", Domain: "example.com", ImportedAt: time.Time{}, LeakedAt: nil, BreachedAt: nil},
			{Email: "fi@example.com", Password: "Password123#", Hash: "Password123#", SourceID: "flare", Domain: "example.com", ImportedAt: time.Time{}, LeakedAt: nil, BreachedAt: nil},
			{Email: "foe@example.com", Password: "Password123$", Hash: "Password123$", SourceID: "flare", Domain: "example.com", ImportedAt: time.Time{}, LeakedAt: nil, BreachedAt: nil},
			{Email: "fum@example.com", Password: "Password123*", Hash: "Password123*", SourceID: "flare", Domain: "example.com", ImportedAt: time.Time{}, LeakedAt: nil, BreachedAt: nil},
			{Email: "foo@example.com", Password: "Password2025!", Hash: "Password2025!", SourceID: "flare", Domain: "example.com", ImportedAt: time.Time{}, LeakedAt: nil, BreachedAt: nil},
			{Email: "bar@example.com", Password: "Password123!!", Hash: "Password123!!", SourceID: "flare", Domain: "example.com", ImportedAt: time.Time{}, LeakedAt: nil, BreachedAt: nil},
			{Email: "baz@example.com", Password: "Password123!!!", Hash: "Password123!!!", SourceID: "flare", Domain: "example.com", ImportedAt: time.Time{}, LeakedAt: nil, BreachedAt: nil},
			{Email: "foo@example.com", Password: "Password123", Hash: "Password123", SourceID: "flare", Domain: "example.com", ImportedAt: time.Time{}, LeakedAt: nil, BreachedAt: nil},
			{Email: "foo@example.com", Password: ":Password123", Hash: ":Password123", SourceID: "flare_funkyness", Domain: "example.com", ImportedAt: time.Time{}, LeakedAt: nil, BreachedAt: nil},
			{Email: " foobarWithASpace@example.com", Password: "Password123", Hash: "Password123", SourceID: "flare_funkyness", Domain: "example.com", ImportedAt: time.Time{}, LeakedAt: nil, BreachedAt: nil},
		}}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := dumpDicerNG(tt.args.domain, tt.args.flareOutputDir, tt.args.creds); (err != nil) != tt.wantErr {
				t.Errorf("dumpDicerNG() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
		t.Cleanup(func() {
			if exists, err := utils.Exists("test/credential_stuffing"); err == nil && exists {
				if err = os.RemoveAll("test/credential_stuffing"); err != nil {
					t.Errorf("couldn't remove test dir: %v", err)
				}
			}
		})
	}
}
