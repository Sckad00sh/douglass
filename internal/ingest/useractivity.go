package ingest

import (
	"strings"

	"github.com/example/artifact-review/internal/model"
)

// UserActivityArtifact defines a registry-derived "virtual" artifact: a
// browsable slice of the RECmd registry rows, selected by KeyPath. These
// have NO CSV of their own -- they are carved out of RECmd_Batch.csv at
// discovery time (for the row count) and again at load time (for the
// actual filtered rows). The whole set is grouped under a single
// "User Activity" sidebar header in the UI (registry-derived artifacts
// all carry Category "User Activity").
//
// Why derived rather than first-class artifact types: these keys are not
// separate tool outputs -- they all live in the one RECmd CSV. The
// existing artifact model maps one artifact to one source file via a
// filename pattern, which doesn't fit "many artifacts, one file, split
// by KeyPath." So they get their own small registry here and a dedicated
// path in discoverHost / LoadArtifact.
//
// Coverage caveat: a derived artifact only yields rows if the active
// RECmd batch (.reb) actually collected the underlying key. When it
// didn't, the artifact has zero rows and is hidden from the sidebar
// (same as any empty artifact) -- so a *missing* User Activity artifact
// means "no rows collected," NOT "confirmed no activity." This ambiguity
// is accepted: an empty browsable table is worse than absence.
type UserActivityArtifact struct {
	ID   string
	Name string
	Icon string
	// KeyPathMatch is a lowercase substring tested against each row's
	// KeyPath (case-insensitively). A row belongs to this artifact when
	// its KeyPath contains the substring.
	KeyPathMatch string
	// Columns is the table layout for this artifact's view. All rows are
	// registry rows, so columns are chosen from the RECmd CSV fields
	// (LastWriteTimestamp, KeyPath, ValueName, ValueData, ...).
	Columns []model.Column
}

// matches reports whether a registry row belongs to this artifact.
func (ua UserActivityArtifact) matches(row model.Row) bool {
	return strings.Contains(strings.ToLower(row["KeyPath"]), ua.KeyPathMatch)
}

// uaTimeCol / uaValueName / uaValueData / uaKeyPath are reused column
// definitions so the per-artifact layouts stay consistent.
var (
	uaTimeCol   = model.Column{Key: "LastWriteTimestamp", Label: "Last Write", Width: 170, Mono: true}
	uaKeyPath   = model.Column{Key: "KeyPath", Label: "Key Path", Width: 320, Mono: true}
	uaValueName = model.Column{Key: "ValueName", Label: "Value Name", Width: 200}
	uaValueData = model.Column{Key: "ValueData", Label: "Value Data", Width: 360}
)

// UserActivityArtifacts is the ordered set surfaced under "User Activity".
// Order here drives display order in the sidebar group.
//
// KeyPath substrings are lowercase (matches() lowercases the row's
// KeyPath before comparing). They're intentionally specific enough to
// avoid collateral matches -- e.g. `\explorer\runmru` won't match the
// autostart `\explorer\run` Run key.
//
// ShellBags / BagMRU / Bags are deliberately NOT here: the existing
// `shellbags` artifact (SBECmd over UsrClass.dat) already covers them,
// and re-surfacing the registry side would duplicate it.
var UserActivityArtifacts = []UserActivityArtifact{
	{
		ID: "ua-userassist", Name: "UserAssist", Icon: "\U0001F5B1",
		KeyPathMatch: `\explorer\userassist\`,
		// UserAssist ValueData carries decoded run count / focus time
		// when the batch's plugin decodes the ROT13 value name.
		Columns: []model.Column{uaTimeCol, {Key: "ValueName", Label: "Program", Width: 360}, {Key: "ValueData", Label: "Run Data", Width: 260}},
	},
	{
		ID: "ua-recentdocs", Name: "RecentDocs", Icon: "\U0001F4C4",
		KeyPathMatch: `\explorer\recentdocs`,
		Columns:      []model.Column{uaTimeCol, uaValueName, {Key: "ValueData", Label: "Document", Width: 420}},
	},
	{
		ID: "ua-typedpaths", Name: "TypedPaths", Icon: "\u2328",
		KeyPathMatch: `\explorer\typedpaths`,
		Columns:      []model.Column{uaTimeCol, uaValueName, {Key: "ValueData", Label: "Typed Path", Width: 420}},
	},
	{
		ID: "ua-runmru", Name: "RunMRU", Icon: "\u25B6",
		KeyPathMatch: `\explorer\runmru`,
		Columns:      []model.Column{uaTimeCol, uaValueName, {Key: "ValueData", Label: "Command", Width: 420}},
	},
	{
		ID: "ua-opensavemru", Name: "OpenSavePidlMRU", Icon: "\U0001F4C2",
		KeyPathMatch: `\comdlg32\opensavepidlmru`,
		Columns:      []model.Column{uaTimeCol, uaKeyPath, uaValueName, uaValueData},
	},
	{
		ID: "ua-lastvisitedmru", Name: "LastVisitedPidlMRU", Icon: "\U0001F4C1",
		KeyPathMatch: `\comdlg32\lastvisitedpidlmru`,
		Columns:      []model.Column{uaTimeCol, uaValueName, {Key: "ValueData", Label: "Application / Path", Width: 420}},
	},
	{
		ID: "ua-wordwheelquery", Name: "WordWheelQuery", Icon: "\U0001F50D",
		KeyPathMatch: `\explorer\wordwheelquery`,
		Columns:      []model.Column{uaTimeCol, uaValueName, {Key: "ValueData", Label: "Search Term", Width: 360}},
	},
	{
		ID: "ua-muicache", Name: "MuiCache", Icon: "\U0001F5BC",
		// MuiCache lives under UsrClass.dat:
		//   ...\Classes\Local Settings\...\Shell\MuiCache
		// No execution timestamp (the key write time is all we get).
		KeyPathMatch: `\muicache`,
		Columns:      []model.Column{uaTimeCol, {Key: "ValueName", Label: "Application Path", Width: 420}, {Key: "ValueData", Label: "Friendly Name", Width: 240}},
	},
	{
		ID: "ua-rdpdest", Name: "RDP Destinations", Icon: "\U0001F5A5",
		// HKCU\Software\Microsoft\Terminal Server Client\Servers\<server>
		// The server is the subkey, so it's in KeyPath, not a value.
		KeyPathMatch: `\terminal server client\servers`,
		Columns:      []model.Column{uaTimeCol, {Key: "KeyPath", Label: "Server (in key path)", Width: 360, Mono: true}, uaValueName, uaValueData},
	},
}

// findUserActivity returns the definition for the given artifact ID, or
// nil if the ID isn't a user-activity artifact.
func findUserActivity(id string) *UserActivityArtifact {
	for i := range UserActivityArtifacts {
		if UserActivityArtifacts[i].ID == id {
			return &UserActivityArtifacts[i]
		}
	}
	return nil
}

// UserActivityCategory is the Category string all derived user-activity
// artifacts carry. The frontend groups the sidebar by this value.
const UserActivityCategory = "User Activity"
