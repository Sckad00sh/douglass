package ingest

import (
	"strings"

	"github.com/example/artifact-review/internal/model"
)

// parseShellbags wraps parseCSV with a small post-processing step that
// adds a derived HiveKind column to each row. SBECmd emits separate
// CSVs per source hive (NTUSER.DAT vs UsrClass.dat) and the analyst
// often wants to filter by which hive a shellbag came from -- they
// represent semantically different things:
//
//   - NTUSER.DAT shellbags: folders the user opened in Explorer.
//     This is the "where did the user browse" view.
//
//   - UsrClass.dat shellbags: mounted folders -- drives, network
//     shares, removable media, and virtual folders like Recent.
//     Persists references to volumes that may no longer be present.
//
// Rather than make analysts juggle two tabs, we surface them in one
// table with a kind column populated by inspecting the SourceFile.
// The hive name is the last path component before the .dat extension.
//
// Falls back to "Unknown" when SourceFile is empty or unrecognised;
// row is still emitted (better to surface unknown than drop data
// silently).
func parseShellbags(path string) ([]model.Row, error) {
	rows, err := parseCSV(path)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		r["HiveKind"] = inferShellbagHiveKind(r["SourceFile"])
	}
	return rows, nil
}

// inferShellbagHiveKind maps an SBECmd SourceFile column value to a
// short human-readable label. The value comes in as a full path on
// the imaged system, e.g.:
//
//	C:\Users\bob\AppData\Local\Microsoft\Windows\UsrClass.dat
//	C:\Users\bob\NTUSER.DAT
//
// We compare the basename (without case sensitivity) to the two
// expected hive names. Anything else returns "Unknown" so analysts
// see a clear marker rather than silently mis-classified data.
func inferShellbagHiveKind(sourceFile string) string {
	if sourceFile == "" {
		return "Unknown"
	}
	// Take the basename. Shellbag CSVs from Windows machines use
	// backslash paths; the LastIndexAny covers both separators.
	base := sourceFile
	if idx := strings.LastIndexAny(base, `/\`); idx >= 0 {
		base = base[idx+1:]
	}
	lower := strings.ToLower(base)
	switch {
	case strings.HasPrefix(lower, "usrclass"):
		return "UsrClass"
	case strings.HasPrefix(lower, "ntuser"):
		return "NTUSER"
	}
	return "Unknown"
}
