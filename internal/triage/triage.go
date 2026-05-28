// Package triage derives "low-hanging fruit" findings from already-parsed
// artifacts. It is a read-only analysis layer: it never parses files
// itself, it only filters rows that ingest has already loaded. The
// output is a compact set of findings grouped by category, each linking
// back to the source artifact + row so the analyst can pivot into full
// context.
//
// Design principles:
//
//   - Filter on deterministic fields (registry KeyPath, file paths), not
//     on labels that vary across tool versions (e.g. RECmd's Category
//     column, which differs between Kroll_Batch.reb and other batches).
//
//   - Be opinionated where volume demands it. Services and execution
//     artifacts are filtered to suspicious paths only; a panel that
//     lists 150 legitimate Windows services buries the one malicious
//     entry. Low-volume categories (Run keys, Winlogon, scheduled
//     tasks) show every match.
//
//   - Never claim completeness. This panel is a triage shortcut. The
//     full artifacts remain available in the normal viewer. Heuristic
//     filters have false negatives by design (a malicious service in
//     System32 with a normal name won't flag here); that's an
//     acceptable tradeoff for signal over noise.
package triage

import (
	"sort"
	"strings"

	"github.com/example/artifact-review/internal/model"
)

// Finding is a single quick-hit row in the triage panel.
type Finding struct {
	// Primary is the headline string for the finding (e.g. the Run key's
	// ValueData, or the suspicious executable path).
	Primary string `json:"primary"`
	// Secondary is supporting context (e.g. the registry KeyPath, or the
	// Amcache publisher). May be empty.
	Secondary string `json:"secondary,omitempty"`
	// Timestamp is the finding's relevant time (registry last-write,
	// execution time) as the raw string from the source row. May be empty.
	Timestamp string `json:"timestamp,omitempty"`
	// SourceArtifact is the artifact ID this finding came from, so the UI
	// can link to it (e.g. "registry", "amcache", "prefetch").
	SourceArtifact string `json:"sourceArtifact"`
	// RowKey is the source row's "__row" index, so the UI can deep-link
	// to the exact row in the full artifact view.
	RowKey string `json:"rowKey,omitempty"`
}

// Group is a category of findings (Run keys, services, etc.).
type Group struct {
	ID             string    `json:"id"`
	Title          string    `json:"title"`
	Icon           string    `json:"icon"`
	SourceArtifact string    `json:"sourceArtifact"`
	// Note is an optional caveat shown under the group title, e.g. to
	// explain that a group is filtered to suspicious entries only.
	Note     string    `json:"note,omitempty"`
	Findings []Finding `json:"findings"`
}

// Result is the full triage payload for a host.
type Result struct {
	Host   string  `json:"host"`
	Groups []Group `json:"groups"`
}

// suspiciousPathFragments are path substrings that indicate an
// executable living somewhere it usually shouldn't. Matched
// case-insensitively against registry ValueData and file paths. These
// are the canonical "executables don't normally live here" locations
// used across DFIR triage.
var suspiciousPathFragments = []string{
	`\temp\`,
	`\tmp\`,
	`\downloads\`,
	`\appdata\local\temp\`,
	`\appdata\roaming\`,
	`\programdata\`,
	`\$recycle.bin\`,
	`\users\public\`,
	`\windows\temp\`,
	`\perflogs\`,
}

// suspiciousInterpreters are process/command indicators that, when found
// in a service's ImagePath or a Run value, suggest a living-off-the-land
// launcher rather than a normal binary.
var suspiciousInterpreters = []string{
	`cmd.exe`,
	`cmd /c`,
	`powershell`,
	`pwsh`,
	`rundll32`,
	`regsvr32`,
	`mshta`,
	`wscript`,
	`cscript`,
	`.bat`,
	`.ps1`,
	`.vbs`,
	`.js`,
	`-enc`,
	`-encodedcommand`,
	`downloadstring`,
	`webclient`,
}

// looksSuspiciousPath reports whether s contains any suspicious path
// fragment. Case-insensitive.
func looksSuspiciousPath(s string) bool {
	low := strings.ToLower(s)
	for _, frag := range suspiciousPathFragments {
		if strings.Contains(low, frag) {
			return true
		}
	}
	return false
}

// looksSuspiciousLauncher reports whether s references a script
// interpreter or LOLBin launcher. Case-insensitive.
func looksSuspiciousLauncher(s string) bool {
	low := strings.ToLower(s)
	for _, ind := range suspiciousInterpreters {
		if strings.Contains(low, ind) {
			return true
		}
	}
	return false
}

// keyPathContains is a small helper: does the row's KeyPath contain the
// given (lowercased) fragment?
func keyPathContains(row model.Row, frag string) bool {
	return strings.Contains(strings.ToLower(row["KeyPath"]), frag)
}

// Artifacts is the set of parsed artifacts triage needs. The caller
// (server) supplies whichever are available; nil slices are fine and
// produce empty groups.
type Artifacts struct {
	Registry []model.Row // RECmd
	Amcache  []model.Row
	Prefetch []model.Row
}

// Analyze runs all enabled filters and returns the grouped findings.
// hostName is echoed back in the result for the UI header.
func Analyze(hostName string, arts Artifacts) Result {
	res := Result{Host: hostName}
	res.Groups = append(res.Groups,
		runKeysGroup(arts.Registry),
		winlogonGroup(arts.Registry),
		servicesGroup(arts.Registry),
		schedTasksGroup(arts.Registry),
		suspAmcacheGroup(arts.Amcache),
		suspPrefetchGroup(arts.Prefetch),
	)
	// Sort each group's findings newest-first so the most recent
	// persistence/execution evidence is at the top.
	for i := range res.Groups {
		sortFindingsByTime(res.Groups[i].Findings)
	}
	return res
}

// ---- Item 1: Run / RunOnce -------------------------------------------
//
// Shows ALL matches (low volume; even legitimate-looking Run entries
// deserve an eye during triage). Matches the common autostart key paths
// in both HKLM and HKCU.

func runKeysGroup(rows []model.Row) Group {
	g := Group{ID: "run-keys", Title: "Run / RunOnce", Icon: "\U0001F501",
		SourceArtifact: "registry"}
	runFrags := []string{
		`\currentversion\run`,
		`\currentversion\runonce`,
		`\currentversion\runonceex`,
		`\currentversion\runservices`,
		`\currentversion\runservicesonce`,
	}
	for _, row := range rows {
		kp := strings.ToLower(row["KeyPath"])
		matched := false
		for _, f := range runFrags {
			// Use HasSuffix-ish containment: the Run key path can have a
			// trailing component but the autostart key itself ends at
			// "\Run" / "\RunOnce". Containment is good enough and avoids
			// missing per-value rows where the value name is appended.
			if strings.Contains(kp, f) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		g.Findings = append(g.Findings, Finding{
			Primary:        valueOrDash(row["ValueData"]),
			Secondary:      row["KeyPath"] + nameSuffix(row["ValueName"]),
			Timestamp:      row["LastWriteTimestamp"],
			SourceArtifact: "registry",
			RowKey:         row["__row"],
		})
	}
	return g
}

// ---- Item 2: Winlogon autostart --------------------------------------
//
// Shows ALL matches. Shell/Userinit hijacking is a top persistence
// technique; the analyst wants to see these values even when they look
// default, because the whole point is spotting the non-default one.

func winlogonGroup(rows []model.Row) Group {
	g := Group{ID: "winlogon", Title: "Winlogon autostart", Icon: "\U0001F510",
		SourceArtifact: "registry",
		Note:           "Shell/Userinit should normally be explorer.exe / userinit.exe"}
	for _, row := range rows {
		if !keyPathContains(row, `\winlogon`) {
			continue
		}
		// Only surface the autostart-relevant values, not every Winlogon
		// value (there are many benign ones like Background, etc.).
		vn := strings.ToLower(row["ValueName"])
		relevant := vn == "shell" || vn == "userinit" || vn == "notify" ||
			vn == "taskman" || vn == "vmapplet" || vn == "appsetup"
		// Also catch Notify subkey paths.
		if !relevant && !keyPathContains(row, `\winlogon\notify`) {
			continue
		}
		g.Findings = append(g.Findings, Finding{
			Primary:        valueOrDash(row["ValueData"]),
			Secondary:      row["KeyPath"] + nameSuffix(row["ValueName"]),
			Timestamp:      row["LastWriteTimestamp"],
			SourceArtifact: "registry",
			RowKey:         row["__row"],
		})
	}
	return g
}

// ---- Item 3: Suspicious services (option B) --------------------------
//
// Filters to services whose ImagePath/ValueData points at a suspicious
// path OR references a script interpreter / LOLBin. Does NOT list every
// service (high volume, mostly benign). This is opinionated by design.

func servicesGroup(rows []model.Row) Group {
	g := Group{ID: "services", Title: "Suspicious services", Icon: "\U0001F6E0",
		SourceArtifact: "registry",
		Note:           "Filtered to services launching from unusual paths or via script interpreters"}
	for _, row := range rows {
		if !keyPathContains(row, `\services\`) {
			continue
		}
		data := row["ValueData"]
		// The ImagePath value is the interesting one, but batches vary in
		// whether they isolate it. Inspect ValueData regardless of which
		// value this row represents; the suspicious-path / launcher test
		// is specific enough to avoid most false positives.
		if !looksSuspiciousPath(data) && !looksSuspiciousLauncher(data) {
			continue
		}
		g.Findings = append(g.Findings, Finding{
			Primary:        valueOrDash(data),
			Secondary:      row["KeyPath"] + nameSuffix(row["ValueName"]),
			Timestamp:      row["LastWriteTimestamp"],
			SourceArtifact: "registry",
			RowKey:         row["__row"],
		})
	}
	return g
}

// ---- Item 4: Scheduled tasks -----------------------------------------
//
// Shows ALL matches in the TaskCache tree. Persistence via schtasks is
// common; the volume is usually manageable.

func schedTasksGroup(rows []model.Row) Group {
	g := Group{ID: "sched-tasks", Title: "Scheduled tasks", Icon: "\U0001F4C5",
		SourceArtifact: "registry"}
	for _, row := range rows {
		if !keyPathContains(row, `\schedule\taskcache\tree\`) &&
			!keyPathContains(row, `\schedule\taskcache\tasks\`) {
			continue
		}
		// Tree entries carry the task name in the key path; surface that
		// as the primary since the value data is often a GUID.
		primary := lastPathSegment(row["KeyPath"])
		if primary == "" {
			primary = valueOrDash(row["ValueData"])
		}
		g.Findings = append(g.Findings, Finding{
			Primary:        primary,
			Secondary:      row["KeyPath"],
			Timestamp:      row["LastWriteTimestamp"],
			SourceArtifact: "registry",
			RowKey:         row["__row"],
		})
	}
	return g
}

// ---- Item 9: Execution from suspicious paths (Amcache) ---------------

func suspAmcacheGroup(rows []model.Row) Group {
	g := Group{ID: "susp-amcache", Title: "Execution from suspicious paths (Amcache)",
		Icon: "\u2699", SourceArtifact: "amcache",
		Note: "Filtered to executables in temp / download / profile / public locations"}
	for _, row := range rows {
		path := row["FullPath"]
		if path == "" {
			continue
		}
		if !looksSuspiciousPath(path) {
			continue
		}
		secondary := row["Publisher"]
		if secondary == "" {
			secondary = "(no publisher)"
		}
		if sha := row["SHA1"]; sha != "" {
			secondary += " · SHA1 " + truncate(sha, 16)
		}
		g.Findings = append(g.Findings, Finding{
			Primary:        path,
			Secondary:      secondary,
			Timestamp:      row["FileKeyLastWriteTimestamp"],
			SourceArtifact: "amcache",
			RowKey:         row["__row"],
		})
	}
	return g
}

// ---- Item 10: Execution from suspicious paths (Prefetch) -------------

func suspPrefetchGroup(rows []model.Row) Group {
	g := Group{ID: "susp-prefetch", Title: "Execution from suspicious paths (Prefetch)",
		Icon: "\u26A1", SourceArtifact: "prefetch",
		Note: "Filtered to executables referenced from unusual locations"}
	for _, row := range rows {
		// Prefetch's SourceFilename / ExecutableName may hold the path.
		// VolumeNames sometimes carries the device path. Check the most
		// path-like fields.
		candidates := []string{row["SourceFilename"], row["ExecutableName"]}
		var hit string
		for _, c := range candidates {
			if c != "" && looksSuspiciousPath(c) {
				hit = c
				break
			}
		}
		if hit == "" {
			continue
		}
		secondary := ""
		if rc := row["RunCount"]; rc != "" {
			secondary = "run count " + rc
		}
		g.Findings = append(g.Findings, Finding{
			Primary:        hit,
			Secondary:      secondary,
			Timestamp:      row["LastRun"],
			SourceArtifact: "prefetch",
			RowKey:         row["__row"],
		})
	}
	return g
}

// ---- helpers ---------------------------------------------------------

func valueOrDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(empty)"
	}
	return s
}

func nameSuffix(valueName string) string {
	if strings.TrimSpace(valueName) == "" {
		return ""
	}
	return " → " + valueName
}

func lastPathSegment(keyPath string) string {
	keyPath = strings.TrimRight(keyPath, `\`)
	idx := strings.LastIndex(keyPath, `\`)
	if idx < 0 {
		return keyPath
	}
	return keyPath[idx+1:]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// TotalFindings returns the sum of findings across all groups. Handy for
// the UI's badge and for tests.
func (r Result) TotalFindings() int {
	n := 0
	for _, g := range r.Groups {
		n += len(g.Findings)
	}
	return n
}

// NonEmptyGroups returns only the groups that have at least one finding,
// preserving order. The UI uses this to avoid rendering empty sections.
func (r Result) NonEmptyGroups() []Group {
	out := make([]Group, 0, len(r.Groups))
	for _, g := range r.Groups {
		if len(g.Findings) > 0 {
			out = append(out, g)
		}
	}
	return out
}

// sortFindingsByTime sorts a group's findings newest-first by their raw
// timestamp string. ISO 8601 / RECmd timestamps sort correctly as
// strings, so we avoid parsing. Empty timestamps sort last.
func sortFindingsByTime(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		ti, tj := f[i].Timestamp, f[j].Timestamp
		if ti == "" {
			return false
		}
		if tj == "" {
			return true
		}
		return ti > tj
	})
}
