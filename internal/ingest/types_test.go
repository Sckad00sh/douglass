package ingest

import "testing"

func TestRecognize(t *testing.T) {
	cases := []struct {
		name string
		want string // expected artifact ID, or "" for no match
	}{
		// Canonical EZ Tools / Hayabusa filenames
		{"$MFT_Output.csv", "mft"},
		{"MFTECmd_$MFT_Output.csv", "mft"},

		// Amcache: split into distinct types per CSV variant
		{"Amcache_UnassociatedFileEntries.csv", "amcache"},
		{"Amcache_AssociatedFileEntries.csv", "amcache-associated"},
		{"Amcache_ProgramEntries.csv", "amcache-programs"},
		{"Amcache_DeviceContainers.csv", "amcache-devices"},
		{"Amcache_DevicePnps.csv", "amcache-devices"},
		{"Amcache_DriveBinaries.csv", "amcache-drivers"},
		{"Amcache_ShortCuts.csv", "amcache-shortcuts"},

		{"SYSTEM_AppCompatCache.csv", "shimcache"},
		{"AppCompatCache_Output.csv", "shimcache"},

		// Prefetch: split Last-Run vs flattened Timeline
		{"PECmd_Output.csv", "prefetch"},
		{"20251108112233_PECmd_Output.csv", "prefetch"},
		{"PECmd_Output_Timeline.csv", "prefetch-timeline"},
		{"20251108112233_PECmd_Output_Timeline.csv", "prefetch-timeline"},

		{"EvtxECmd_Output.csv", "evtx"},
		{"hayabusa_timeline.csv", "hayabusa"},
		{"Hayabusa_Timeline_2025-11-08.csv", "hayabusa"},
		{"SrumECmd_NetworkUsage.csv", "srum"},
		{"SrumECmd_NetworkUsageMonitor.csv", "srum"},
		{"RECmd_Batch.csv", "registry"},
		{"RECmd_Batch_kroll.csv", "registry"},
		{"20251108112233_RECmd_Batch_Kroll_Batch_Output.csv", "registry"},
		{"20251108112233_RECmd_Batch_RECmd_Batch_MC_Output.csv", "registry"},
		{"LECmd_Output.csv", "lnk"},
		{"JLECmd_Output.csv", "jumplist"},

		// Negative cases — should NOT match anything
		{"notes.txt", ""},
		{"random.csv", ""},
		{"system.log", ""},
		{"", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Recognize(c.name)
			if c.want == "" {
				if got != nil {
					t.Errorf("Recognize(%q) = %q, want no match", c.name, got.ID)
				}
				return
			}
			if got == nil {
				t.Errorf("Recognize(%q) = nil, want %q", c.name, c.want)
				return
			}
			if got.ID != c.want {
				t.Errorf("Recognize(%q) = %q, want %q", c.name, got.ID, c.want)
			}
		})
	}
}

func TestColumnsForKnownTypes(t *testing.T) {
	// Every type in the registry should have a non-empty column schema.
	for _, at := range ArtifactTypes {
		cols := ColumnsFor(at.ID)
		if len(cols) == 0 {
			t.Errorf("type %q has no columns", at.ID)
		}
	}
}

func TestColumnsForUnknown(t *testing.T) {
	if got := ColumnsFor("nonexistent"); got != nil {
		t.Errorf("ColumnsFor(nonexistent) = %v, want nil", got)
	}
}

// TestNoPatternCollisions guards against the kind of bug where one
// artifact's pattern accidentally matches another artifact's canonical
// filename (e.g. LECmd_Output.csv vs JLECmd_Output.csv). Each canonical
// example file in the registry must be claimed by exactly one type.
func TestNoPatternCollisions(t *testing.T) {
	for _, target := range ArtifactTypes {
		var matches []string
		for _, candidate := range ArtifactTypes {
			if candidate.FilenamePattern.MatchString(target.File) {
				matches = append(matches, candidate.ID)
			}
		}
		if len(matches) != 1 {
			t.Errorf("file %q matched %d types %v; want exactly 1 (%s)",
				target.File, len(matches), matches, target.ID)
		} else if matches[0] != target.ID {
			t.Errorf("file %q matched %q; want %q",
				target.File, matches[0], target.ID)
		}
	}
}

// TestCrossVariantNoMatch verifies that filenames from one tool's family
// don't accidentally claim the wrong sibling. These are the exact
// collisions that produced duplicate sidebar entries in the field.
func TestCrossVariantNoMatch(t *testing.T) {
	cases := []struct {
		filename string
		wantID   string
	}{
		// Amcache: each variant should be unambiguously claimed
		{"Amcache_UnassociatedFileEntries.csv", "amcache"},
		{"Amcache_AssociatedFileEntries.csv", "amcache-associated"},
		{"Amcache_ProgramEntries.csv", "amcache-programs"},
		{"Amcache_DeviceContainers.csv", "amcache-devices"},
		{"Amcache_DevicePnps.csv", "amcache-devices"},
		{"Amcache_DriveBinaries.csv", "amcache-drivers"},
		{"Amcache_DrivePackages.csv", "amcache-drivers"},
		{"Amcache_ShortCuts.csv", "amcache-shortcuts"},
		// PECmd: Timeline vs Output must be distinguished
		{"PECmd_Output.csv", "prefetch"},
		{"PECmd_Output_Timeline.csv", "prefetch-timeline"},
	}
	for _, c := range cases {
		got := Recognize(c.filename)
		if got == nil {
			t.Errorf("Recognize(%q) = nil, want %q", c.filename, c.wantID)
			continue
		}
		if got.ID != c.wantID {
			t.Errorf("Recognize(%q) = %q, want %q (sibling collision)",
				c.filename, got.ID, c.wantID)
		}
	}
}
