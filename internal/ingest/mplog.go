package ingest

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/example/artifact-review/internal/model"
)

// MPLog parsing.
//
// MPLog-YYYYMMDD-HHMMSS.log files are Microsoft Defender diagnostic logs
// emitted to C:\ProgramData\Microsoft\Windows Defender\Support\. They're
// UTF-16 LE (with BOM) and semi-structured: most lines are
// "ISO-TIMESTAMP <free-form message>" but some constructs span multiple
// lines (BM telemetry blocks, Dynamic Signature drops, RTP Perf Log
// banners).
//
// We classify each line into an EventType, collapse multi-line blocks
// into a single Row, and surface a Severity hint based on each event's
// content. Configuration is curated against a real 51k-line sample;
// EstimatedImpact lines (10k+ of pure process-scan noise) are dropped
// entirely at parse time. The DFIR-relevant subset retained is roughly
// 1.3% of the original line count.
//
// See the design discussion + sample-table preview that landed this
// schema before code was written.

// MPLog event types. These map 1:1 to the EventType column values in
// the parsed Row stream. Stable strings -- analysts will use them in
// per-column filters.
const (
	MPLogTypeBMTelemetry    = "BMTelemetry"
	MPLogTypeMiniFilterScan = "MiniFilterScan"
	MPLogTypeEMSScan        = "EMSScan"
	MPLogTypeASRRule        = "ASRRule"
	MPLogTypeAMSI           = "AMSI"
	MPLogTypeEngineEvent    = "EngineEvent"
	MPLogTypeDetection      = "Detection"
	MPLogTypeOther          = "Other"
)

// Pre-compiled regexes used by parseMPLog. Defined as package-level vars
// so they compile once. Each is keyed to the line shape it parses.
var (
	// ISO timestamp at line start: "2026-05-02T19:40:11.617 <message>"
	mplogTSRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3})\s+(.*)$`)

	// "ProcessImageName: foo.exe, Pid: 1234, TotalTime: N, Count: N,
	//  MaxTime: N, MaxTimeFile: ..., EstimatedImpact: P%"
	// Same shape covers both plain EstimatedImpact lines (dropped) and
	// AMSI subset (kept). Distinguished by the MaxTimeFile content.
	mplogEIRe = regexp.MustCompile(
		`ProcessImageName:\s*([^,]+),\s*Pid:\s*(\d+),\s*` +
			`TotalTime:\s*(\d+),\s*Count:\s*(\d+),\s*` +
			`MaxTime:\s*(\d+),\s*MaxTimeFile:\s*(.+?),\s*` +
			`EstimatedImpact:\s*(\d+)%`)

	// "Engine:EMS scan for process: svchost pid: 2040, ..."
	mplogEMSRe = regexp.MustCompile(
		`Engine:EMS scan for process:\s*(\S+)\s+pid:\s*(\d+)`)

	// "[RTP] [Mini-filter] Unsuccessful scan status(#N): <file>. Process: <proc>,
	//  Status: 0xC..., ..., Reason: <reason>, ..."
	mplogMFRe = regexp.MustCompile(
		`\[RTP\]\s*\[Mini-filter\]\s*Unsuccessful scan status\(#\d+\):\s*` +
			`(.+?)\.\s+Process:\s*([^,]+),\s*Status:\s*(0x[0-9a-fA-F]+).*?` +
			`Reason:\s*(\w+)`)

	// `Engine-HIPS:Loaded ASR vdm rule "Block ...", State=N, Action=N, ...`
	mplogASRRe = regexp.MustCompile(
		`Engine-HIPS:Loaded ASR vdm rule\s*"([^"]+)",\s*State=(\d+),\s*Action=(\d+)`)

	// "Engine:<msg>, hr=0x..." or "[Engine]:<msg>, hr=0x..."
	mplogEngRe = regexp.MustCompile(
		`(?:Engine|\[Engine\]):\s*(.+?),\s*hr=(0x[0-9a-fA-F]+)$`)

	// BM telemetry block CreationTime is "MM-DD-YYYY HH:MM:SS"; reformat
	// to ISO so it sorts/correlates alongside the timestamped events.
	mplogBMCTRe = regexp.MustCompile(
		`(\d{2})-(\d{2})-(\d{4})\s+(\d{2}:\d{2}:\d{2})`)

	// Taint Info: "...Reason: <reason>;..." and "...Parents: <path>:pid:N,..."
	mplogTaintReasonRe  = regexp.MustCompile(`Reason:\s*([^;]*)`)
	mplogTaintParentsRe = regexp.MustCompile(`Parents:\s*([^,]+)`)
)

// mplogMiniFilterBenignStatuses lists scan-status codes that fire so
// often they're effectively noise and shouldn't bump severity. 0xc0000001
// is "file disappeared between open and scan" which Defender hits
// constantly on busy systems.
var mplogMiniFilterBenignStatuses = map[string]bool{
	"0xc0000001": true,
}

// readMPLogFile decodes an MPLog file. MPLog is always UTF-16 LE with
// BOM on Windows -- we detect the BOM and translate to UTF-8 on the fly
// via bufio.Scanner. Files without BOM are read as UTF-8 (defensive --
// shouldn't happen in production but allows synthesized test data).
//
// Returns the decoded text as a single string. Callers split on \n.
func readMPLogFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// Peek the first two bytes to detect UTF-16 LE BOM (0xFF 0xFE).
	br := bufio.NewReader(f)
	bom, _ := br.Peek(2)
	if len(bom) >= 2 && bom[0] == 0xFF && bom[1] == 0xFE {
		// Consume the BOM, then read+decode rest as UTF-16 LE.
		_, _ = br.Discard(2)
		raw, err := io.ReadAll(br)
		if err != nil {
			return "", err
		}
		if len(raw)%2 != 0 {
			// Odd byte at end -- truncate. Defender shouldn't produce this
			// but we don't want to fail the whole parse over one byte.
			raw = raw[:len(raw)-1]
		}
		// Convert UTF-16 LE pairs to runes.
		u16 := make([]uint16, len(raw)/2)
		for i := 0; i < len(u16); i++ {
			u16[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
		}
		return string(utf16.Decode(u16)), nil
	}

	// No BOM: treat as UTF-8.
	b, err := io.ReadAll(br)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// parseMPLog reads an MPLog file and returns one Row per classified
// event. Multi-line BM telemetry blocks fold to a single row.
// EstimatedImpact lines (the dominant noise source) are skipped.
//
// The returned rows always carry every schema column as a key (with
// empty string when the event doesn't populate it) so the front-end
// doesn't see undefined fields.
func parseMPLog(path string) ([]model.Row, error) {
	text, err := readMPLogFile(path)
	if err != nil {
		return nil, err
	}
	// Normalize CRLF -> LF so the splitter doesn't leave \r on every line.
	text = strings.ReplaceAll(text, "\r\n", "\n")
	lines := strings.Split(text, "\n")

	out := make([]model.Row, 0, 4096)
	i := 0
	n := len(lines)
	for i < n {
		raw := lines[i]
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			i++
			continue
		}

		// BM telemetry block: BEGIN ... END span; fold into one row.
		if strings.TrimSpace(line) == "BEGIN BM telemetry" {
			ev, advance := parseBMBlock(lines, i)
			i += advance
			if ev != nil {
				out = append(out, ev)
			}
			continue
		}

		// All other event types are timestamped single lines.
		m := mplogTSRe.FindStringSubmatch(line)
		if m == nil {
			i++
			continue
		}
		ts, payload := m[1], m[2]

		if ev := classifyMPLogLine(ts, payload); ev != nil {
			out = append(out, ev)
		}
		i++
	}

	// Stamp row keys for mark-stability (matches the parseCSV contract).
	for idx, r := range out {
		r["__row"] = fmt.Sprintf("%d", idx)
	}
	return out, nil
}

// classifyMPLogLine matches a single timestamped line against the
// known event-type regexes, returning a model.Row populated for that
// event type or nil if the line is intentionally dropped (e.g. plain
// EstimatedImpact noise).
func classifyMPLogLine(ts, payload string) model.Row {
	// ProcessImageName-shaped: AMSI subset retained, plain EstimatedImpact
	// dropped per design. Distinguishing trait is the MaxTimeFile content.
	if m := mplogEIRe.FindStringSubmatch(payload); m != nil {
		// m[1]=proc m[2]=pid m[3]=totalTime m[4]=count m[5]=maxTime m[6]=file m[7]=impact
		file := strings.TrimSpace(m[6])
		isAMSI := strings.Contains(file, "->(UTF-16LE)") || strings.Contains(file, "AMSI")
		if !isAMSI {
			return nil // drop plain EstimatedImpact noise
		}
		impact, _ := strconv.Atoi(m[7])
		sev := "info"
		if impact >= 5 {
			sev = "warn"
		}
		return makeRow(ts, MPLogTypeAMSI, sev, mplogRowFields{
			ProcessName: strings.TrimSpace(m[1]),
			ProcessId:   m[2],
			FilePath:    file,
			Detail:      fmt.Sprintf("CPU %sms, %s scans, impact %d%%", m[3], m[4], impact),
		})
	}

	if m := mplogEMSRe.FindStringSubmatch(payload); m != nil {
		detail := payload
		if len(detail) > 120 {
			detail = detail[:120]
		}
		return makeRow(ts, MPLogTypeEMSScan, "info", mplogRowFields{
			ProcessName: m[1],
			ProcessId:   m[2],
			Detail:      detail,
		})
	}

	if m := mplogMFRe.FindStringSubmatch(payload); m != nil {
		// m[1]=file m[2]=procPath m[3]=status m[4]=reason
		status := m[3]
		sev := "warn"
		if mplogMiniFilterBenignStatuses[strings.ToLower(status)] {
			sev = "info"
		}
		return makeRow(ts, MPLogTypeMiniFilterScan, sev, mplogRowFields{
			ProcessName: basenameOf(m[2]),
			ImagePath:   strings.TrimSpace(m[2]),
			FilePath:    strings.TrimSpace(m[1]),
			Action:      fmt.Sprintf("Status=%s, Reason=%s", status, m[4]),
			Detail:      fmt.Sprintf("Scan status %s, reason %s", status, m[4]),
		})
	}

	if m := mplogASRRe.FindStringSubmatch(payload); m != nil {
		action := map[string]string{"0": "Audit", "1": "Block", "2": "AuditWithWarn"}[m[3]]
		if action == "" {
			action = m[3]
		}
		return makeRow(ts, MPLogTypeASRRule, "info", mplogRowFields{
			RuleOrThreat: m[1],
			Action:       action,
			Detail:       fmt.Sprintf("ASR rule loaded, State=%s", m[2]),
		})
	}

	if m := mplogEngRe.FindStringSubmatch(payload); m != nil {
		hr := m[2]
		// 0x800710da = "no version info" -- super common, not interesting
		sev := "warn"
		if hr == "0x0" || strings.EqualFold(hr, "0x800710da") {
			sev = "low"
		}
		msg := m[1]
		if len(msg) > 120 {
			msg = msg[:120]
		}
		return makeRow(ts, MPLogTypeEngineEvent, sev, mplogRowFields{
			Action: hr,
			Detail: msg,
		})
	}

	// Anything else timestamped lands here for "all" mode visibility.
	detail := payload
	if len(detail) > 120 {
		detail = detail[:120]
	}
	return makeRow(ts, MPLogTypeOther, "low", mplogRowFields{
		Detail: detail,
	})
}

// parseBMBlock reads a "BEGIN BM telemetry"/"END BM telemetry" block
// starting at lines[start] and returns the collapsed event plus the
// number of lines consumed (including BEGIN and END markers).
// Robust to a missing END marker: stops at EOF or at the next BEGIN.
func parseBMBlock(lines []string, start int) (model.Row, int) {
	block := map[string]string{}
	i := start + 1 // skip BEGIN
	for i < len(lines) {
		l := strings.TrimRight(lines[i], "\r")
		ls := strings.TrimSpace(l)
		if ls == "END BM telemetry" {
			i++
			break
		}
		if ls == "BEGIN BM telemetry" {
			// Malformed -- previous block didn't get its END. Stop here
			// without consuming this new BEGIN; the outer loop will pick
			// it up next iteration.
			break
		}
		// key:value parse, splitting on the FIRST colon. Values can
		// contain colons (e.g. Taint Info), so don't split on every one.
		if idx := strings.Index(l, ":"); idx > 0 {
			k := strings.TrimSpace(l[:idx])
			v := strings.TrimSpace(l[idx+1:])
			block[k] = v
		}
		i++
	}
	return bmBlockToRow(block), i - start
}

// bmBlockToRow converts the accumulated key:value map from a BM telemetry
// block into one model.Row. Missing fields produce empty-string columns.
func bmBlockToRow(block map[string]string) model.Row {
	// CreationTime arrives as "MM-DD-YYYY HH:MM:SS"; reformat to ISO so
	// it correlates with other timestamps.
	ct := block["CreationTime"]
	ts := ct
	if m := mplogBMCTRe.FindStringSubmatch(ct); m != nil {
		ts = fmt.Sprintf("%s-%s-%sT%s.000", m[3], m[1], m[2], m[4])
	}

	// Pull parent process + reason out of the embedded Taint Info string.
	// Both regexes return empty match on miss; we substring-strip the
	// result.
	taint := block["Taint Info"]
	parent := ""
	if m := mplogTaintParentsRe.FindStringSubmatch(taint); m != nil {
		parent = strings.TrimSpace(m[1])
	}
	reason := ""
	if m := mplogTaintReasonRe.FindStringSubmatch(taint); m != nil {
		reason = strings.TrimSpace(m[1])
	}
	reasonForDetail := reason
	if reasonForDetail == "" {
		reasonForDetail = "(none)"
	}

	threat, _ := strconv.Atoi(block["ThreatLevel"])
	sev := "info"
	switch {
	case threat >= 5:
		sev = "high"
	case threat >= 1:
		sev = "warn"
	}

	ip := block["ImagePath"]
	return makeRow(ts, MPLogTypeBMTelemetry, sev, mplogRowFields{
		ProcessName:   basenameOf(ip),
		ProcessId:     block["ProcessID"],
		ImagePath:     ip,
		Action:        block["Operations"],
		ParentProcess: parent,
		Detail: fmt.Sprintf("Reason: %s. SigID %s. ThreatLevel %d.",
			reasonForDetail, block["SignatureID"], threat),
	})
}

// mplogRowFields is a shorthand for "the optional columns I want to set"
// when building a row. Anything not specified ends up as "" in the Row.
// Keeps classifyMPLogLine readable instead of carrying 11 args.
type mplogRowFields struct {
	ProcessName   string
	ProcessId     string
	ImagePath     string
	FilePath      string
	RuleOrThreat  string
	Action        string
	ParentProcess string
	Detail        string
}

// makeRow assembles a single model.Row with every MPLog schema column
// present (empty string when not set). __row gets stamped later by
// parseMPLog so it reflects the row's position in the output stream.
func makeRow(ts, eventType, severity string, f mplogRowFields) model.Row {
	return model.Row{
		"Timestamp":     ts,
		"EventType":     eventType,
		"Severity":      severity,
		"ProcessName":   f.ProcessName,
		"ProcessId":     f.ProcessId,
		"ImagePath":     f.ImagePath,
		"FilePath":      f.FilePath,
		"RuleOrThreat":  f.RuleOrThreat,
		"Action":        f.Action,
		"ParentProcess": f.ParentProcess,
		"Detail":        f.Detail,
	}
}

// basenameOf returns the trailing filename portion of a path, handling
// both forward and back slashes. Returns the input unchanged if it
// contains no separator.
func basenameOf(p string) string {
	if p == "" {
		return ""
	}
	if idx := strings.LastIndexAny(p, `/\`); idx >= 0 {
		return p[idx+1:]
	}
	return p
}

// mplogFilterRelevant is the default front-end filter: rows whose
// EventType is BMTelemetry or Detection, OR whose Severity is warn or
// worse. Other rows are present in the full row set but hidden by the
// UI's default toggle. Server-side filtering would change the row count
// the client sees and break the "show all" toggle; we keep filtering
// client-side and just expose the predicate here for tests.
func mplogFilterRelevant(r model.Row) bool {
	t := r["EventType"]
	if t == MPLogTypeBMTelemetry || t == MPLogTypeDetection {
		return true
	}
	switch r["Severity"] {
	case "warn", "high", "crit":
		return true
	}
	return false
}
