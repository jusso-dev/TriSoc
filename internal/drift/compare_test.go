package drift

import "testing"

func TestCompareIgnoresVolatileFields(t *testing.T) {
	previous := map[string]any{"enabled": true, "metadata": map[string]any{"etag": "one"}}
	current := map[string]any{"enabled": true, "metadata": map[string]any{"etag": "two"}}
	got, err := Compare(previous, current, []string{"metadata.etag"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Drift {
		t.Fatalf("unexpected drift: %+v", got)
	}
}
func TestCompareReportsMaterialChange(t *testing.T) {
	got, err := Compare(map[string]any{"enabled": true}, map[string]any{"enabled": false}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Drift || len(got.Changes) != 1 || got.Changes[0].Path != "enabled" {
		t.Fatalf("unexpected comparison: %+v", got)
	}
}
