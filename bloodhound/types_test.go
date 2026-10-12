package bloodhound

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mr-pmillz/gophlare/phlare"
)

// The struct-typed fields below carry json:",omitzero", so an unset value
// drops its key instead of emitting "{}" or a zero timestamp.

func TestBHCELoginResponseOmitsUnsetData(t *testing.T) {
	assertJSONKeys(t, BHCELoginResponse{}, nil, []string{"data"})

	var r BHCELoginResponse
	r.Data.SessionToken = "token"
	assertJSONKeys(t, r, []string{"data"}, nil)
}

func TestDataOmitsUnsetPropertiesAndMeta(t *testing.T) {
	assertJSONKeys(t, Data{PrimaryGroupSID: "S-1-5-21-1-513"},
		[]string{"PrimaryGroupSID"}, []string{"Properties", "meta"})

	populated := Data{
		Properties: Properties{Name: "USER@EXAMPLE.LOCAL"},
		Meta:       Meta{Count: 1},
	}
	assertJSONKeys(t, populated, []string{"Properties", "meta"}, nil)
}

func TestHoardClientHostLeaksJSONLOmitsUnsetImportTimestamp(t *testing.T) {
	assertJSONKeys(t, HoardClientHostLeaksJSONL{Username: "user"},
		[]string{"username"}, []string{"import_timestamp"})

	stamped := HoardClientHostLeaksJSONL{
		ImportTimestamp: phlare.FlareTime{Time: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)},
	}
	assertJSONKeys(t, stamped, []string{"import_timestamp"}, nil)
}

// assertJSONKeys marshals v and checks which top-level keys are present.
func assertJSONKeys(t *testing.T, v any, present, absent []string) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(b, &keys); err != nil {
		t.Fatalf("unmarshal %s: %v", b, err)
	}
	for _, k := range present {
		if _, ok := keys[k]; !ok {
			t.Errorf("%T: key %q missing from %s", v, k, b)
		}
	}
	for _, k := range absent {
		if _, ok := keys[k]; ok {
			t.Errorf("%T: key %q should be omitted from %s", v, k, b)
		}
	}
}
