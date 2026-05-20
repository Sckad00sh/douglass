package marks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/example/artifact-review/internal/model"
)

func TestExtractTimestamp(t *testing.T) {
	cases := []struct {
		row  map[string]string
		want string
	}{
		{map[string]string{"Timestamp": "2025-11-08 03:14:22"}, "2025-11-08 03:14:22"},
		{map[string]string{"TimeCreated": "2025-11-08 03:14:22"}, "2025-11-08 03:14:22"},
		{map[string]string{"LastRun": "2025-11-08 03:14:22"}, "2025-11-08 03:14:22"},
		// priority: Timestamp wins over TimeCreated
		{map[string]string{"Timestamp": "A", "TimeCreated": "B"}, "A"},
		// empty values are skipped
		{map[string]string{"Timestamp": "", "TimeCreated": "B"}, "B"},
		// nothing -> empty
		{map[string]string{"Foo": "bar"}, ""},
	}
	for _, c := range cases {
		got := ExtractTimestamp(c.row)
		if got != c.want {
			t.Errorf("ExtractTimestamp(%v) = %q, want %q", c.row, got, c.want)
		}
	}
}

func TestExtractLabel(t *testing.T) {
	cases := []struct {
		row  map[string]string
		want string
	}{
		{map[string]string{"RuleTitle": "Mimikatz"}, "Mimikatz"},
		{map[string]string{"MapDescription": "Logon"}, "Logon"},
		{map[string]string{"FileName": "evil.exe"}, "evil.exe"},
		// priority order
		{map[string]string{"RuleTitle": "A", "FileName": "B"}, "A"},
		// no recognised columns
		{map[string]string{"Foo": "bar"}, "(no label)"},
	}
	for _, c := range cases {
		got := ExtractLabel(c.row)
		if got != c.want {
			t.Errorf("ExtractLabel(%v) = %q, want %q", c.row, got, c.want)
		}
	}
}

func TestDeriveSeverity(t *testing.T) {
	cases := []struct {
		artID string
		row   map[string]string
		want  model.Severity
	}{
		{"hayabusa", map[string]string{"Level": "crit"}, model.SevCrit},
		{"hayabusa", map[string]string{"Level": "Critical"}, model.SevCrit},
		{"hayabusa", map[string]string{"Level": "high"}, model.SevHigh},
		{"hayabusa", map[string]string{"Level": "med"}, model.SevMed},
		{"hayabusa", map[string]string{"Level": "medium"}, model.SevMed},
		{"hayabusa", map[string]string{"Level": "low"}, model.SevLow},
		{"hayabusa", map[string]string{"Level": "info"}, model.SevInfo},
		{"hayabusa", map[string]string{"Level": ""}, model.SevInfo},
		{"evtx", map[string]string{"Level": "Error"}, model.SevCrit},
		{"evtx", map[string]string{"Level": "Warning"}, model.SevHigh},
		{"evtx", map[string]string{"Level": "Information"}, model.SevInfo},
		{"mft", map[string]string{}, model.SevInfo}, // non-severity artifact
	}
	for _, c := range cases {
		got := DeriveSeverity(c.artID, c.row)
		if got != c.want {
			t.Errorf("DeriveSeverity(%q, Level=%q) = %q, want %q",
				c.artID, c.row["Level"], got, c.want)
		}
	}
}

func TestRowKeyStability(t *testing.T) {
	// Same logical row should produce the same key, even if other (unused)
	// columns change.
	a := map[string]string{
		"Timestamp": "2025-11-08 03:14:22.881",
		"FileName":  "mimikatz.exe",
		"_extra":    "x",
	}
	b := map[string]string{
		"Timestamp": "2025-11-08 03:14:22.881",
		"FileName":  "mimikatz.exe",
		"_extra":    "y", // different but not in preferred list
	}
	if RowKey(a) != RowKey(b) {
		t.Errorf("RowKey unstable across non-preferred column changes")
	}

	// Different timestamps should produce different keys.
	c := map[string]string{
		"Timestamp": "2025-11-08 03:15:00.000",
		"FileName":  "mimikatz.exe",
	}
	if RowKey(a) == RowKey(c) {
		t.Errorf("RowKey collided across different timestamps")
	}

	// Empty row falls back to __row index.
	if got := RowKey(map[string]string{"__row": "42"}); got != "42" {
		t.Errorf("RowKey empty fallback = %q, want %q", got, "42")
	}
}

func TestMakeID(t *testing.T) {
	got := MakeID("HOST", "art", "rk")
	want := "HOST|art|rk"
	if got != want {
		t.Errorf("MakeID = %q, want %q", got, want)
	}
}

func TestStoreUpsertList(t *testing.T) {
	dir := t.TempDir()
	s := New()
	if err := s.Open(dir); err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	m1 := &model.Mark{
		HostID: "h1", ArtifactID: "hayabusa", RowKey: "abc",
		Timestamp: "2025-11-08 03:14:22", Label: "Mimikatz", Severity: model.SevCrit,
	}
	m2 := &model.Mark{
		HostID: "h2", ArtifactID: "evtx", RowKey: "def",
		Timestamp: "2025-11-08 04:00:00", Label: "Logon", Severity: model.SevHigh,
	}
	s.Upsert(m1)
	s.Upsert(m2)

	if all := s.List(""); len(all) != 2 {
		t.Errorf("List() = %d marks, want 2", len(all))
	}
	if h1 := s.List("h1"); len(h1) != 1 || h1[0].HostID != "h1" {
		t.Errorf("List(h1) = %v, want 1 mark for h1", h1)
	}
	// timestamp ordering
	all := s.List("")
	if len(all) == 2 && all[0].Timestamp > all[1].Timestamp {
		t.Errorf("List should be sorted by timestamp asc")
	}

	// delete one
	s.Delete(m1.ID)
	if all := s.List(""); len(all) != 1 {
		t.Errorf("after delete, List() = %d, want 1", len(all))
	}

	// idempotent re-delete
	s.Delete(m1.ID)
	if all := s.List(""); len(all) != 1 {
		t.Errorf("re-delete should be no-op")
	}
}

func TestStorePersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s1 := New()
	if err := s1.Open(dir); err != nil {
		t.Fatalf("open: %v", err)
	}
	s1.Upsert(&model.Mark{
		HostID: "h1", ArtifactID: "hayabusa", RowKey: "abc",
		Timestamp: "2025-11-08 03:14", Label: "test", Severity: model.SevCrit,
	})
	// Force a synchronous flush rather than waiting on the debouncer.
	if err := s1.flushNow(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	s1.Close()

	// File should exist now.
	if _, err := os.ReadFile(filepath.Join(dir, "marks.json")); err != nil {
		t.Fatalf("marks.json not written: %v", err)
	}

	// New store should load it back.
	s2 := New()
	if err := s2.Open(dir); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if all := s2.List(""); len(all) != 1 || all[0].Label != "test" {
		t.Errorf("after reopen, List() = %v", all)
	}
}
