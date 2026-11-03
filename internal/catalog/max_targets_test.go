package catalog

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func maxTargetsAction(t *testing.T, field string) (Action, error) {
	t.Helper()
	a, err := ParseAction([]byte(validAction + field))
	if err != nil {
		return a, err
	}
	_, err = ValidateAction(a)
	return a, err
}

func TestMaxTargetsAcceptedValues(t *testing.T) {
	for _, field := range []string{"", "max_targets: 1\n", "max_targets: 20\n", "max_targets: 2147483647\n"} {
		if _, err := maxTargetsAction(t, field); err != nil {
			t.Errorf("%q rejected: %v", field, err)
		}
	}
}

func TestMaxTargetsRangeRejected(t *testing.T) {
	for _, value := range []string{"0", "-1", "-2147483648", "2147483648", "9223372036854775807"} {
		_, err := maxTargetsAction(t, "max_targets: "+value+"\n")
		if err == nil || err.Error() != "max_targets must be an integer from 1 to 2147483647" {
			t.Errorf("max_targets %s: error=%v", value, err)
		}
	}
}

// A value that is not a YAML integer, or does not fit the field at all, fails
// to decode. "not found" would mean the field itself is unknown.
func TestMaxTargetsTypeRejected(t *testing.T) {
	for _, value := range []string{"1.5", `"2"`, "true", "[1]", "{a: 1}", "99999999999999999999"} {
		_, err := maxTargetsAction(t, "max_targets: "+value+"\n")
		if err == nil || strings.Contains(err.Error(), "not found") {
			t.Errorf("max_targets %s: error=%v", value, err)
		}
	}
}

func TestMaxTargetsInDigestAndPackage(t *testing.T) {
	base, err := maxTargetsAction(t, "")
	if err != nil {
		t.Fatal(err)
	}
	one, err := maxTargetsAction(t, "max_targets: 1\n")
	if err != nil {
		t.Fatal(err)
	}
	two, err := maxTargetsAction(t, "max_targets: 2\n")
	if err != nil {
		t.Fatal(err)
	}
	digests := map[string]string{}
	for name, a := range map[string]Action{"omitted": base, "1": one, "2": two} {
		digest, err := ActionDigest(a)
		if err != nil {
			t.Fatal(err)
		}
		if other, ok := digests[digest]; ok {
			t.Errorf("action digest of %s equals %s", name, other)
		}
		digests[digest] = name
	}
	if data, _ := CanonicalJSON(base); strings.Contains(string(data), "max_targets") {
		t.Errorf("omitted field appears in the signed action: %s", data)
	}
	p, err := Build(&Catalog{Config: Config{SchemaVersion: 1, CatalogID: "test"}, Actions: map[string]Action{one.Name: one}}, BuildOptions{Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := CanonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"max_targets":1`) {
		t.Fatalf("signed package lacks max_targets: %s", payload)
	}
	parsed, err := ParsePackage(payload)
	if err != nil {
		t.Fatal(err)
	}
	again, err := CanonicalJSON(parsed)
	if err != nil || string(again) != string(payload) {
		t.Fatalf("round trip changed the package: %v\n%s\n%s", err, payload, again)
	}
	// A reader must refuse a signed value that the validator would refuse.
	for _, value := range []string{"0", "-1", "2147483648"} {
		bad := strings.Replace(string(payload), `"max_targets":1`, `"max_targets":`+value, 1)
		if _, err := ParsePackage([]byte(bad)); err == nil || !strings.Contains(err.Error(), "max_targets must be") {
			t.Errorf("package with max_targets %s: error=%v", value, err)
		}
	}
	var decoded struct {
		Actions map[string]map[string]any `json:"actions"`
	}
	if err := json.Unmarshal(payload, &decoded); err != nil || decoded.Actions[one.Name]["max_targets"] != float64(1) {
		t.Fatalf("decoded=%v err=%v", decoded, err)
	}
}
