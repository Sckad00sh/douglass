package ingest

import (
	"regexp"

	"github.com/example/artifact-review/internal/model"
)

// ArtifactType bundles a type definition with its filename-recognition regex
// and column schema. The set below is ported from design/data.js (ARTIFACT_TYPES
// + COLS) and the README's recognition table.
type ArtifactType struct {
	model.ArtifactType
	// FilenamePattern is matched (case-insensitive, on basename) to claim
	// a CSV for this artifact. First match wins; see Recognize().
	FilenamePattern *regexp.Regexp
	Columns         []model.Column
}

// ArtifactTypes is the canonical registry. Order matters: more specific
// patterns must come before broader ones (e.g. Amcache "FileEntries" must
// not be claimed by a generic "Amcache" rule).
var ArtifactTypes = []ArtifactType{
	{
		ArtifactType: model.ArtifactType{
			ID: "mft", Name: "MFT", Icon: "🗂", Tool: "MFTECmd",
			Category: "Filesystem", File: "$MFT_Output.csv",
		},
		FilenamePattern: regexp.MustCompile(`(?i)MFT.*Output.*\.csv$`),
		Columns: []model.Column{
			{Key: "EntryNumber", Label: "Entry", Width: 70, Numeric: true, Mono: true},
			{Key: "InUse", Label: "In Use", Width: 60, Bool: true},
			{Key: "FileName", Label: "File Name", Width: 220},
			{Key: "Extension", Label: "Ext", Width: 60},
			{Key: "ParentPath", Label: "Parent Path", Width: 320, Mono: true},
			{Key: "FileSize", Label: "Size", Width: 90, Numeric: true, Format: "bytes"},
			{Key: "Created0x10", Label: "Created (SI)", Width: 170, Mono: true},
			{Key: "LastModified0x10", Label: "Modified (SI)", Width: 170, Mono: true},
			{Key: "LastAccess0x10", Label: "Accessed (SI)", Width: 170, Mono: true},
			{Key: "SiFlags", Label: "SI Flags", Width: 110},
			{Key: "Copied", Label: "Copied", Width: 60, Bool: true},
		},
	},
	{
		ArtifactType: model.ArtifactType{
			ID: "amcache", Name: "Amcache File Entries", Icon: "⚙", Tool: "AmcacheParser",
			Category: "Execution", File: "Amcache_UnassociatedFileEntries.csv",
		},
		// Match the UnassociatedFileEntries CSV — the main forensically
		// interesting Amcache output, listing executable history not tied
		// to a known program. Anchored to the suffix so we don't accidentally
		// claim other Amcache_*.csv siblings.
		FilenamePattern: regexp.MustCompile(`(?i)Amcache_UnassociatedFileEntries\.csv$`),
		// Columns reflect the actual EZ Tools AmcacheParser output for the
		// UnassociatedFileEntries CSV: no Publisher / FileVersionString
		// fields (those exist in some older builds but not the current
		// schema). Description and Version are the closest equivalents.
		Columns: []model.Column{
			{Key: "FileKeyLastWriteTimestamp", Label: "Last Write", Width: 170, Mono: true},
			{Key: "ApplicationName", Label: "Application", Width: 200},
			{Key: "FileExtension", Label: "Ext", Width: 60},
			{Key: "FullPath", Label: "Full Path", Width: 360, Mono: true},
			{Key: "Size", Label: "Size", Width: 90, Numeric: true, Format: "bytes"},
			{Key: "SHA1", Label: "SHA-1", Width: 180, Mono: true, TruncHash: true},
			{Key: "ProductName", Label: "Product", Width: 170},
			{Key: "Version", Label: "Version", Width: 110, Mono: true},
			{Key: "Description", Label: "Description", Width: 220},
			{Key: "BinaryType", Label: "Binary Type", Width: 90},
			{Key: "IsOsComponent", Label: "OS?", Width: 50, Bool: true},
		},
	},
	{
		ArtifactType: model.ArtifactType{
			ID: "amcache-associated", Name: "Amcache Associated", Icon: "⚙", Tool: "AmcacheParser",
			Category: "Execution", File: "Amcache_AssociatedFileEntries.csv",
		},
		FilenamePattern: regexp.MustCompile(`(?i)Amcache.*_AssociatedFileEntries\.csv$`),
		Columns: []model.Column{
			{Key: "FileKeyLastWriteTimestamp", Label: "Last Write", Width: 170, Mono: true},
			{Key: "ApplicationName", Label: "Application", Width: 200},
			{Key: "FullPath", Label: "Full Path", Width: 360, Mono: true},
			{Key: "Size", Label: "Size", Width: 90, Numeric: true, Format: "bytes"},
			{Key: "SHA1", Label: "SHA-1", Width: 180, Mono: true, TruncHash: true},
			{Key: "ProductName", Label: "Product", Width: 170},
			{Key: "Version", Label: "Version", Width: 110, Mono: true},
			{Key: "Description", Label: "Description", Width: 220},
		},
	},
	{
		ArtifactType: model.ArtifactType{
			ID: "amcache-programs", Name: "Amcache Programs", Icon: "⚙", Tool: "AmcacheParser",
			Category: "Execution", File: "Amcache_ProgramEntries.csv",
		},
		FilenamePattern: regexp.MustCompile(`(?i)Amcache.*_ProgramEntries\.csv$`),
		Columns: []model.Column{
			{Key: "KeyLastWriteTimestamp", Label: "Key Last Write", Width: 170, Mono: true},
			{Key: "Name", Label: "Program Name", Width: 280},
			{Key: "Version", Label: "Version", Width: 120, Mono: true},
			{Key: "Publisher", Label: "Publisher", Width: 200},
			{Key: "InstallDate", Label: "Installed", Width: 170, Mono: true},
			{Key: "UninstallString", Label: "Uninstall", Width: 280, Mono: true},
		},
	},
	{
		ArtifactType: model.ArtifactType{
			ID: "amcache-devices", Name: "Amcache Devices", Icon: "⚙", Tool: "AmcacheParser",
			Category: "Execution", File: "Amcache_DeviceContainers.csv",
		},
		FilenamePattern: regexp.MustCompile(`(?i)Amcache.*_Device(Containers|Pnps)\.csv$`),
		Columns: []model.Column{
			{Key: "KeyLastWriteTimestamp", Label: "Key Last Write", Width: 170, Mono: true},
			{Key: "Categories", Label: "Categories", Width: 200},
			{Key: "Manufacturer", Label: "Manufacturer", Width: 200},
			{Key: "ModelName", Label: "Model", Width: 220},
			{Key: "Description", Label: "Description", Width: 320},
		},
	},
	{
		ArtifactType: model.ArtifactType{
			ID: "amcache-drivers", Name: "Amcache Drivers", Icon: "⚙", Tool: "AmcacheParser",
			Category: "Execution", File: "Amcache_DriveBinaries.csv",
		},
		FilenamePattern: regexp.MustCompile(`(?i)Amcache.*_Drive(Binaries|Packages)\.csv$`),
		Columns: []model.Column{
			{Key: "DriverLastWriteTime", Label: "Driver Last Write", Width: 170, Mono: true},
			{Key: "DriverName", Label: "Driver", Width: 240, Mono: true},
			{Key: "Product", Label: "Product", Width: 200},
			{Key: "Service", Label: "Service", Width: 180},
			{Key: "DriverIsKernelMode", Label: "Kernel?", Width: 70, Bool: true},
			{Key: "DriverCompany", Label: "Company", Width: 200},
		},
	},
	{
		ArtifactType: model.ArtifactType{
			ID: "amcache-shortcuts", Name: "Amcache Shortcuts", Icon: "⚙", Tool: "AmcacheParser",
			Category: "Execution", File: "Amcache_ShortCuts.csv",
		},
		FilenamePattern: regexp.MustCompile(`(?i)Amcache.*_ShortCuts\.csv$`),
		Columns: []model.Column{
			{Key: "KeyLastWriteTimestamp", Label: "Key Last Write", Width: 170, Mono: true},
			{Key: "LnkName", Label: "LNK Name", Width: 280, Mono: true},
		},
	},
	{
		ArtifactType: model.ArtifactType{
			ID: "shimcache", Name: "Shimcache", Icon: "🧩", Tool: "AppCompatCacheParser",
			Category: "Execution", File: "SYSTEM_AppCompatCache.csv",
		},
		FilenamePattern: regexp.MustCompile(`(?i)AppCompatCache.*\.csv$`),
		// Match the actual EZ Tools AppCompatCacheParser output columns:
		// ControlSet, CacheEntryPosition, Path, LastModifiedTimeUTC,
		// Executed, Duplicate, SourceFile. (Older docs reference "Position"
		// and "RowType" -- those names aren't in the current schema.)
		Columns: []model.Column{
			{Key: "CacheEntryPosition", Label: "#", Width: 50, Numeric: true},
			{Key: "ControlSet", Label: "CS", Width: 50, Numeric: true},
			{Key: "LastModifiedTimeUTC", Label: "Last Modified (UTC)", Width: 170, Mono: true},
			{Key: "Path", Label: "Path", Width: 460, Mono: true},
			{Key: "Executed", Label: "Executed", Width: 90, Bool: true},
			{Key: "Duplicate", Label: "Dup", Width: 50, Bool: true},
		},
	},
	{
		ArtifactType: model.ArtifactType{
			ID: "prefetch-timeline", Name: "Prefetch Timeline", Icon: "⚡", Tool: "PECmd",
			Category: "Execution", File: "PECmd_Output_Timeline.csv",
		},
		// PECmd emits PECmd_Output_Timeline.csv with one row per recorded
		// execution time (flattened from the multi-time-per-file layout in
		// PECmd_Output.csv). This variant is more useful for incident
		// timing, so we expose it as its own artifact type. Order matters:
		// this pattern must come BEFORE the plain prefetch rule below,
		// because the prefetch rule's anchoring would not naturally
		// distinguish them.
		FilenamePattern: regexp.MustCompile(`(?i)PECmd_Output_Timeline\.csv$`),
		// The Timeline variant of PECmd output has exactly TWO columns:
		// RunTime + ExecutableName. (Confirmed against current EZ Tools
		// output. Older docs sometimes show more, but the canonical CSV
		// emits just these two.)
		Columns: []model.Column{
			{Key: "RunTime", Label: "Run Time", Width: 200, Mono: true},
			{Key: "ExecutableName", Label: "Executable", Width: 360, Mono: true},
		},
	},
	{
		ArtifactType: model.ArtifactType{
			ID: "prefetch", Name: "Prefetch", Icon: "⚡", Tool: "PECmd",
			Category: "Execution", File: "PECmd_Output.csv",
		},
		// Anchor on the literal suffix "PECmd_Output.csv" so we match
		// both the canonical name and any date-prefixed variant, but not
		// the Timeline sibling (handled by the rule above this one) nor
		// any other tool's *_Output.csv.
		FilenamePattern: regexp.MustCompile(`(?i)PECmd_Output\.csv$`),
		// Schema reflects the actual EZ Tools PECmd CSV columns. The
		// volume info is split across Volume0Name / Volume0Serial / etc.
		// (one set per volume), so we surface the primary volume only.
		Columns: []model.Column{
			{Key: "LastRun", Label: "Last Run", Width: 170, Mono: true},
			{Key: "ExecutableName", Label: "Executable", Width: 220, Mono: true},
			{Key: "RunCount", Label: "Runs", Width: 70, Numeric: true},
			{Key: "Hash", Label: "Hash", Width: 110, Mono: true},
			{Key: "SourceFilename", Label: "PF File", Width: 260, Mono: true},
			{Key: "Size", Label: "Size", Width: 90, Numeric: true, Format: "bytes"},
			{Key: "Volume0Name", Label: "Volume", Width: 170, Mono: true},
			{Key: "Volume0Serial", Label: "Vol Serial", Width: 110, Mono: true},
			{Key: "FilesLoaded", Label: "# Files Loaded", Width: 110, Numeric: true},
		},
	},
	{
		ArtifactType: model.ArtifactType{
			ID: "evtx", Name: "Event Logs", Icon: "📜", Tool: "EvtxECmd",
			Category: "Logs", File: "EvtxECmd_Output.csv",
		},
		FilenamePattern: regexp.MustCompile(`(?i)EvtxECmd_Output.*\.csv$`),
		Columns: []model.Column{
			{Key: "TimeCreated", Label: "TimeCreated", Width: 170, Mono: true},
			{Key: "EventId", Label: "EID", Width: 60, Numeric: true},
			{Key: "Level", Label: "Level", Width: 80},
			{Key: "Provider", Label: "Provider", Width: 200},
			{Key: "Channel", Label: "Channel", Width: 180},
			{Key: "MapDescription", Label: "Description", Width: 320},
			{Key: "UserName", Label: "User", Width: 140},
			{Key: "PayloadData1", Label: "Payload", Width: 280, Mono: true},
		},
	},
	{
		ArtifactType: model.ArtifactType{
			ID: "hayabusa", Name: "Hayabusa Detections", Icon: "🦅", Tool: "Hayabusa",
			Category: "Detections", File: "hayabusa_timeline.csv",
		},
		FilenamePattern: regexp.MustCompile(`(?i)hayabusa.*timeline.*\.csv$`),
		// Hayabusa's csv-timeline output has exactly these columns:
		// Timestamp, RuleTitle, Level, Computer, Channel, EventID,
		// RecordID, Details, ExtraFieldInfo, RuleID. MITRE attribution
		// is embedded inside Details/RuleTitle rather than its own column.
		Columns: []model.Column{
			{Key: "Timestamp", Label: "Timestamp", Width: 170, Mono: true},
			{Key: "Level", Label: "Level", Width: 80, Severity: true},
			{Key: "RuleTitle", Label: "Rule Title", Width: 320},
			{Key: "Computer", Label: "Computer", Width: 150},
			{Key: "Channel", Label: "Channel", Width: 150},
			{Key: "EventID", Label: "EID", Width: 60, Numeric: true},
			{Key: "Details", Label: "Details", Width: 360},
			{Key: "RuleID", Label: "Rule ID", Width: 240, Mono: true},
			{Key: "ExtraFieldInfo", Label: "Extra", Width: 280},
			{Key: "RecordID", Label: "Record", Width: 100, Numeric: true},
		},
	},
	{
		ArtifactType: model.ArtifactType{
			ID: "srum", Name: "SRUM Network", Icon: "🌐", Tool: "SrumECmd",
			Category: "System", File: "SrumECmd_NetworkUsage.csv",
		},
		FilenamePattern: regexp.MustCompile(`(?i)SrumECmd.*Network.*\.csv$`),
		Columns: []model.Column{
			{Key: "Timestamp", Label: "Timestamp", Width: 170, Mono: true},
			{Key: "AppId", Label: "App / Process", Width: 280, Mono: true},
			{Key: "UserName", Label: "User", Width: 140},
			{Key: "InterfaceLuid", Label: "Interface", Width: 110},
			{Key: "BytesSent", Label: "Bytes Sent", Width: 110, Numeric: true, Format: "bytes"},
			{Key: "BytesRecvd", Label: "Bytes Recvd", Width: 110, Numeric: true, Format: "bytes"},
			{Key: "L2ProfileId", Label: "Profile", Width: 180},
		},
	},
	{
		ArtifactType: model.ArtifactType{
			ID: "registry", Name: "Registry (RECmd)", Icon: "🔑", Tool: "RECmd",
			Category: "Registry", File: "RECmd_Batch.csv",
		},
		// Anchored to the suffix "RECmd_Batch*_Output.csv" (RECmd's default
		// pattern is `{timestamp}_RECmd_Batch_{batchname}_Output.csv`)
		// as well as the canonical name RECmd_Batch.csv our preprocessor
		// emits when given an explicit --csvf.
		FilenamePattern: regexp.MustCompile(`(?i)RECmd_Batch.*\.csv$`),
		Columns: []model.Column{
			{Key: "LastWriteTimestamp", Label: "Last Write", Width: 170, Mono: true},
			{Key: "HiveType", Label: "Hive", Width: 80},
			{Key: "Category", Label: "Category", Width: 140},
			{Key: "Description", Label: "Description", Width: 220},
			{Key: "KeyPath", Label: "Key Path", Width: 340, Mono: true},
			{Key: "ValueName", Label: "Value Name", Width: 160, Mono: true},
			{Key: "ValueType", Label: "Type", Width: 80},
			{Key: "ValueData", Label: "Data", Width: 280, Mono: true},
			{Key: "ValueData2", Label: "Data 2", Width: 200, Mono: true},
			{Key: "ValueData3", Label: "Data 3", Width: 200, Mono: true},
			{Key: "Comment", Label: "Comment", Width: 200},
			{Key: "Deleted", Label: "Del", Width: 50, Bool: true},
		},
	},
	{
		ArtifactType: model.ArtifactType{
			ID: "lnk", Name: "LNK Files", Icon: "🔗", Tool: "LECmd",
			Category: "Filesystem", File: "LECmd_Output.csv",
		},
		FilenamePattern: regexp.MustCompile(`(?i)\bLECmd_Output.*\.csv$`),
		Columns: []model.Column{
			{Key: "SourceCreated", Label: "LNK Created", Width: 170, Mono: true},
			{Key: "TargetCreated", Label: "Target Created", Width: 170, Mono: true},
			{Key: "TargetModified", Label: "Target Modified", Width: 170, Mono: true},
			{Key: "LocalPath", Label: "Local Path", Width: 360, Mono: true},
			{Key: "TargetSize", Label: "Size", Width: 90, Numeric: true, Format: "bytes"},
			{Key: "MachineId", Label: "Machine ID", Width: 170, Mono: true},
			{Key: "VolumeSerial", Label: "Vol Serial", Width: 110, Mono: true},
		},
	},
	{
		ArtifactType: model.ArtifactType{
			ID: "jumplist", Name: "Jump Lists", Icon: "↗", Tool: "JLECmd",
			Category: "Execution", File: "JLECmd_Output.csv",
		},
		FilenamePattern: regexp.MustCompile(`(?i)JLECmd_Output.*\.csv$`),
		Columns: []model.Column{
			{Key: "TargetCreated", Label: "Target Created", Width: 170, Mono: true},
			{Key: "LastModified", Label: "Last Modified", Width: 170, Mono: true},
			{Key: "SourceFile", Label: "Source File", Width: 280, Mono: true},
			{Key: "AppId", Label: "AppID", Width: 180, Mono: true},
			{Key: "TargetPath", Label: "Target Path", Width: 320, Mono: true},
			{Key: "EntryNumber", Label: "Entry #", Width: 70, Numeric: true},
		},
	},
}

// Recognize matches a basename against the registry. Returns nil if no
// pattern claims it.
func Recognize(basename string) *ArtifactType {
	for i := range ArtifactTypes {
		if ArtifactTypes[i].FilenamePattern.MatchString(basename) {
			return &ArtifactTypes[i]
		}
	}
	return nil
}

// AllTypes exposes the registry as a slice of plain model.ArtifactType
// for shipping to the front-end.
func AllTypes() []model.ArtifactType {
	out := make([]model.ArtifactType, 0, len(ArtifactTypes))
	for _, t := range ArtifactTypes {
		out = append(out, t.ArtifactType)
	}
	return out
}

// ColumnsFor returns the column schema for an artifact ID, or nil if unknown.
func ColumnsFor(id string) []model.Column {
	for _, t := range ArtifactTypes {
		if t.ID == id {
			return t.Columns
		}
	}
	return nil
}
