package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestHostOverviewSchema_RoundTrip pins the phase-1 host overview schema:
// every nested block (identity/hardware/network/triage) must marshal
// through JSON, deserialize back, and produce the same values. Catches
// regressions where someone removes a field or changes a json tag.
func TestHostOverviewSchema_RoundTrip(t *testing.T) {
	original := Host{
		ID:   "WS-FIN-014",
		Name: "WS-FIN-014",
		Role: "Workstation",
		Tag:  "WS",
		Identity: &HostIdentity{
			Hostname:  "WS-FIN-014",
			FQDN:      "ws-fin-014.corp.local",
			Domain:    "CORP",
			OS:        "Windows 11 Pro",
			OSVersion: "22H2",
			Build:     "10.0.22621.4317",
			Arch:      "x64",
			TimeZone:  "UTC-05:00 (EST)",
		},
		Hardware: &HostHardware{
			CPUModel:    "Intel Core i7-12700 @ 2.10GHz",
			CPUCores:    12,
			CPUThreads:  20,
			RAMBytes:    34359738368,
			DiskKind:    "NVMe",
			DiskBytes:   549755813888,
			DiskUsedPct: 71,
			LastBoot:    "2025-11-07T08:42:00Z",
		},
		Network: &HostNetwork{
			IPv4:    []string{"10.40.2.18"},
			MAC:     []string{"00:1A:2B:5C:7E:9F"},
			Gateway: "10.40.2.1",
			DNS:     []string{"10.40.0.10", "10.40.0.11"},
		},
		Triage: &HostTriage{
			Method:      "KAPE -> EZ Tools",
			Operator:    "j.kowalski@corp",
			Targets:     []string{"!SANS_Triage", "EventLogs", "RegistryHives"},
			StartedAt:   "2025-11-08T06:00:00Z",
			CompletedAt: "2025-11-08T06:11:00Z",
			SizeBytes:   4080218931,
		},
	}

	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Host
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Spot-check every nested field. A blanket reflect.DeepEqual would
	// trip on the nil ArtifactSummaries slice differing between original
	// and decoded (one is nil, one is empty after unmarshaling the
	// json:"artifacts" array). Comparing the nested blocks individually
	// avoids that distraction.
	if got.Identity == nil || *got.Identity != *original.Identity {
		t.Errorf("Identity round-trip mismatch: %+v vs %+v", got.Identity, original.Identity)
	}
	if got.Hardware == nil || *got.Hardware != *original.Hardware {
		t.Errorf("Hardware round-trip mismatch: %+v vs %+v", got.Hardware, original.Hardware)
	}
	if got.Network == nil ||
		!equalStringSlice(got.Network.IPv4, original.Network.IPv4) ||
		!equalStringSlice(got.Network.MAC, original.Network.MAC) ||
		got.Network.Gateway != original.Network.Gateway ||
		!equalStringSlice(got.Network.DNS, original.Network.DNS) {
		t.Errorf("Network round-trip mismatch: %+v vs %+v", got.Network, original.Network)
	}
	if got.Triage == nil ||
		got.Triage.Method != original.Triage.Method ||
		got.Triage.Operator != original.Triage.Operator ||
		!equalStringSlice(got.Triage.Targets, original.Triage.Targets) ||
		got.Triage.StartedAt != original.Triage.StartedAt ||
		got.Triage.CompletedAt != original.Triage.CompletedAt ||
		got.Triage.SizeBytes != original.Triage.SizeBytes {
		t.Errorf("Triage round-trip mismatch: %+v vs %+v", got.Triage, original.Triage)
	}
}

// TestHostOverviewSchema_LegacyCompat verifies that an old-format
// host.json (with only the flat fields, no nested blocks) deserializes
// without setting any of the nested pointers. This is the path existing
// cases follow when upgraded -- the renderer must show "Not collected"
// placeholders for the missing blocks rather than crashing.
func TestHostOverviewSchema_LegacyCompat(t *testing.T) {
	legacy := `{
		"id": "WS-OLD-001",
		"name": "WS-OLD-001",
		"os": "Windows 10 Pro",
		"role": "Workstation",
		"tag": "WS",
		"triageStart": "2024-01-15T12:00:00Z"
	}`
	var got Host
	if err := json.Unmarshal([]byte(legacy), &got); err != nil {
		t.Fatalf("legacy unmarshal: %v", err)
	}
	if got.Identity != nil {
		t.Errorf("legacy host: Identity = %+v, want nil", got.Identity)
	}
	if got.Hardware != nil {
		t.Errorf("legacy host: Hardware = %+v, want nil", got.Hardware)
	}
	if got.Network != nil {
		t.Errorf("legacy host: Network = %+v, want nil", got.Network)
	}
	if got.Triage != nil {
		t.Errorf("legacy host: Triage = %+v, want nil", got.Triage)
	}
	// Legacy flat fields should still populate.
	if got.OS != "Windows 10 Pro" {
		t.Errorf("legacy OS = %q, want %q", got.OS, "Windows 10 Pro")
	}
	if got.TriageStart != "2024-01-15T12:00:00Z" {
		t.Errorf("legacy TriageStart = %q", got.TriageStart)
	}
}

// TestHostOverviewSchema_OmitEmpty pins that the json:"...,omitempty"
// tags on the nested pointers actually take effect -- a Host with no
// nested blocks must produce JSON that doesn't include identity/
// hardware/network/triage keys at all. This matters for the renderer:
// `host.identity` in JS should be undefined (not present) on legacy
// hosts, not an empty object.
func TestHostOverviewSchema_OmitEmpty(t *testing.T) {
	h := Host{ID: "x", Name: "x"}
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, k := range []string{`"identity"`, `"hardware"`, `"network"`, `"triage"`} {
		if strings.Contains(s, k) {
			t.Errorf("empty Host JSON contains %s; want omitted: %s", k, s)
		}
	}
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
