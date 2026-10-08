package velociraptor

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

// writeCollectionZip builds a minimal valid collection zip with the given
// session_id + hostname into dir, returns its path.
func writeCollectionZip(t *testing.T, dir, name, sessionID, hostname string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w1, _ := zw.Create("client_info.json")
	w1.Write([]byte(`{"Hostname":"` + hostname + `","Platform":"Windows 11 Pro"}`))
	w2, _ := zw.Create("collection_context.json")
	w2.Write([]byte(`{"session_id":"` + sessionID + `"}`))
	w3, _ := zw.Create("uploads/auto/C%3A/Windows/System32/config/SYSTEM")
	w3.Write([]byte("hive"))
	zw.Close()
	f.Close()
	return p
}

// TestPlanImport_Dedup is the core dedup requirement: a collection whose
// session_id is already in the manifest is skipped with a notice; new
// ones are planned for import.
func TestPlanImport_Dedup(t *testing.T) {
	dir := t.TempDir()
	writeCollectionZip(t, dir, "Collection-A.zip", "F.AAA", "HostA")
	writeCollectionZip(t, dir, "Collection-B.zip", "F.BBB", "HostB")
	// A stray non-collection zip should be flagged, not imported.
	stray := filepath.Join(dir, "notes.zip")
	zf, _ := os.Create(stray)
	zw := zip.NewWriter(zf)
	wx, _ := zw.Create("readme.txt")
	wx.Write([]byte("hi"))
	zw.Close()
	zf.Close()

	man, err := LoadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Pre-record A as already imported.
	if err := man.Record(ManifestEntry{SessionID: "F.AAA", Hostname: "HostA", SourceZip: "Collection-A.zip"}); err != nil {
		t.Fatal(err)
	}

	plans, err := PlanImport(dir, man, false)
	if err != nil {
		t.Fatal(err)
	}

	byZip := map[string]CollectionPlan{}
	for _, p := range plans {
		byZip[p.ZipName] = p
	}
	if p := byZip["Collection-A.zip"]; p.Imported() {
		t.Error("A was already imported; should be skipped")
	} else if p.SkipWhy == "" {
		t.Error("A skip should carry a reason")
	}
	if p := byZip["Collection-B.zip"]; !p.Imported() {
		t.Errorf("B is new; should import (skip=%v why=%q err=%q)", p.Skip, p.SkipWhy, p.ReadErr)
	}
	if p := byZip["notes.zip"]; p.Imported() || p.ReadErr == "" {
		t.Error("notes.zip is not a collection; should be flagged + skipped")
	}

	// force=true re-imports even A.
	plansF, _ := PlanImport(dir, man, true)
	for _, p := range plansF {
		if p.ZipName == "Collection-A.zip" && !p.Imported() {
			t.Error("force should re-import A")
		}
	}
}

// TestManifestPersistence checks the manifest round-trips through disk.
func TestManifestPersistence(t *testing.T) {
	dir := t.TempDir()
	m1, _ := LoadManifest(dir)
	m1.Record(ManifestEntry{SessionID: "F.XYZ", Hostname: "WS9"})
	// Reload from disk.
	m2, err := LoadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !m2.Has("F.XYZ") {
		t.Error("manifest did not persist across reload")
	}
	e, ok := m2.Get("F.XYZ")
	if !ok || e.Hostname != "WS9" {
		t.Errorf("entry wrong after reload: %+v", e)
	}
	// The manifest file must exist at the expected name.
	if _, err := os.Stat(filepath.Join(dir, ManifestName)); err != nil {
		t.Errorf("manifest file missing: %v", err)
	}
}

// TestHostDirName covers hostname sanitation + fallback.
func TestHostDirName(t *testing.T) {
	cases := []struct{ host, session, want string }{
		{"Flare11", "F.X", "Flare11"},
		{"WS-01.corp", "F.X", "WS-01.corp"},
		{"bad/name:here", "F.X", "bad_name_here"},
		{"", "F.ABC", "F.ABC"},
	}
	for _, c := range cases {
		got := HostDirName(Metadata{Hostname: c.host, SessionID: c.session})
		if got != c.want {
			t.Errorf("HostDirName(%q,%q) = %q want %q", c.host, c.session, got, c.want)
		}
	}
}
