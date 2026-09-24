package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

const storeRuntimeComponentID = "melusina-store-sidecar"

const (
	// storeEnrollmentRuntimeSchema names the enrolled Store's /release-info
	// self-report. It is deliberately not componentrelease.
	// RuntimeReleaseInfoSchema, and the report has none of the controller
	// tuple's component, generation, version or artifact fields: the update
	// controller's strict decoder refuses it, so it can never be read as a
	// controller apply (testdata/store-enrollment-runtime-v1-vector.json).
	storeEnrollmentRuntimeSchema = "melusina-store-enrollment-runtime-v1"
	storeEnrollmentRuntimeSource = "enrollment"

	// refusalReleaseInfoMarkerOnEnrolledStore: on an enrolled Store nothing
	// legitimate writes the controller runtime marker. The controller never
	// applies the Store binary (its renderer refuses the Store as a component)
	// and the enrollment binds that binary, so a marker there is either a
	// hand-composed tuple or a stale one, and /release-info reports neither.
	refusalReleaseInfoMarkerOnEnrolledStore = "release-info-marker-on-enrolled-store"
	// refusalReleaseInfoEnrollmentBinaryMismatch: the measured executable is
	// not the one the current enrollment binds. Startup has already refused
	// this as store-enrollment-facts-mismatch:binarySha256; the self-report
	// checks it again rather than trusting that it ran.
	refusalReleaseInfoEnrollmentBinaryMismatch = "release-info-enrollment-binary-mismatch"
	refusalReleaseInfoEnrollmentIncomplete     = "release-info-enrollment-incomplete"

	// runtimeMarkerEnvPrefix is the prefix of every key the controller's
	// marker writer emits (internal/hostupdate/runtime_marker.go).
	runtimeMarkerEnvPrefix = "RRS_"
)

// storeEnrollmentRuntimeReport is gate 2's runtime identity for an enrolled
// Store (DEPLOYMENT-CONTRACT.md "Start and acceptance"). Every value comes
// from the enrollment startup has just verified or from this process:
//   - storeId, enrollmentSequence and enrollmentSha256 name the owner-signed
//     enrollment, or its latest accepted successor, that the Store runs under;
//     enrollmentSha256 is the digest estate-enroll or estate-enroll-successor
//     printed;
//   - binarySha256 is the hash of /proc/self/exe that the boot-identity
//     ceremony measured, equal to that enrollment's binarySha256;
//   - pid lets the reader bind the answer to the unit's MainPID.
//
// The deployer's storehost verify compares binarySha256 with the
// install-bootstrap journal's installed tuple and with the enrollment it
// assembled; this report is one of the three, never the whole proof.
type storeEnrollmentRuntimeReport struct {
	Schema             string `json:"schema"`
	Source             string `json:"source"`
	StoreID            string `json:"storeId"`
	EnrollmentSequence uint64 `json:"enrollmentSequence"`
	EnrollmentSHA256   string `json:"enrollmentSha256"`
	BinarySHA256       string `json:"binarySha256"`
	PID                int    `json:"pid"`
}

// enrolledRuntimeReleaseInfo is the self-report fixed at startup: an enrolled
// Store's binding changes only through a successor, which requires the Store
// stopped, so the report cannot go stale while this process runs.
type enrolledRuntimeReleaseInfo struct {
	report storeEnrollmentRuntimeReport
	body   []byte
}

// enrolledRuntimeReleaseInfoFor builds the self-report from the result of
// deriveEnrolledBootIdentity. A nil state is an unenrolled Store: it returns
// nil, and /release-info keeps the retiring estate's controller-marker path
// unchanged. Only the standard build starts unenrolled; the estate-bootstrap
// build refuses that at startup (unenrolledStoreRefusal).
func enrolledRuntimeReleaseInfoFor(state *storeEnrollmentState, identity *verifiedBootIdentity, pid int) (*enrolledRuntimeReleaseInfo, error) {
	if state == nil {
		return nil, nil
	}
	if identity == nil {
		return nil, fmt.Errorf("%s: boot identity is absent", refusalReleaseInfoEnrollmentIncomplete)
	}
	if pid <= 0 {
		return nil, fmt.Errorf("%s: invalid runtime pid", refusalReleaseInfoEnrollmentIncomplete)
	}
	storeID, enrolledBinary := state.Enrollment.StoreID, state.Enrollment.BinarySHA256
	if state.Successor != nil {
		storeID, enrolledBinary = state.Successor.StoreID, state.Successor.BinarySHA256
	}
	enrollmentSHA256 := state.currentSHA256()
	if strings.TrimSpace(storeID) == "" || len(enrollmentSHA256) != 64 {
		return nil, fmt.Errorf("%s: the enrollment names no Store ID or digest", refusalReleaseInfoEnrollmentIncomplete)
	}
	measured := hex.EncodeToString(identity.facts.binaryHash[:])
	if measured != enrolledBinary {
		return nil, fmt.Errorf("%s: measured %s, enrollment sequence %d binds %s", refusalReleaseInfoEnrollmentBinaryMismatch, measured, state.sequence(), enrolledBinary)
	}
	report := storeEnrollmentRuntimeReport{
		Schema:             storeEnrollmentRuntimeSchema,
		Source:             storeEnrollmentRuntimeSource,
		StoreID:            storeID,
		EnrollmentSequence: state.sequence(),
		EnrollmentSHA256:   enrollmentSHA256,
		BinarySHA256:       measured,
		PID:                pid,
	}
	body, err := encodeStoreEnrollmentRuntimeReport(report)
	if err != nil {
		return nil, err
	}
	return &enrolledRuntimeReleaseInfo{report: report, body: body}, nil
}

// encodeStoreEnrollmentRuntimeReport is the exact response body, one JSON
// object and a newline, as json.Encoder writes the controller tuple.
func encodeStoreEnrollmentRuntimeReport(report storeEnrollmentRuntimeReport) ([]byte, error) {
	body, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

// runtimeMarkerKeys names the controller-marker keys present in environ, by
// key only: a marker's values are never reflected.
func runtimeMarkerKeys(environ []string) []string {
	var keys []string
	for _, entry := range environ {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, runtimeMarkerEnvPrefix) {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	return keys
}

// newRuntimeReleaseInfoHandler serves /release-info. Unenrolled, it is the
// retiring estate's controller-marker handler, unchanged. Enrolled, it serves
// the enrollment self-report, and refuses by name instead when any
// controller-marker key reached the process environment.
func newRuntimeReleaseInfoHandler(enrolled *enrolledRuntimeReleaseInfo, environ func() []string) http.HandlerFunc {
	if enrolled == nil {
		return handleRuntimeReleaseInfo
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if keys := runtimeMarkerKeys(environ()); len(keys) != 0 {
			http.Error(w, "runtime release identity unavailable: "+refusalReleaseInfoMarkerOnEnrolledStore+": "+strings.Join(keys, ","), http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(enrolled.body)
	}
}

// runtimeReleaseInfo is the exact six-field runtime contract consumed by the
// external controller.  It is deliberately sourced from systemd's local
// EnvironmentFile, not reconstructed from an unsigned config, the catalog, or
// the binary version: the controller writes the signed tuple before restart and
// rolls it back from its WAL before a rollback restart.
type runtimeReleaseInfo struct {
	Schema         string `json:"schema"`
	ComponentID    string `json:"componentId"`
	GenerationID   uint64 `json:"generationId"`
	Version        string `json:"version"`
	PID            int    `json:"pid"`
	ArtifactSHA256 string `json:"artifactSha256"`
}

func handleRuntimeReleaseInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	info, err := currentRuntimeReleaseInfo(os.Getenv, os.Getpid())
	if err != nil {
		// The absence of a marker is expected before the first controller-driven
		// update.  It must never be reported as a valid running release.
		http.Error(w, "runtime release identity unavailable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return
	}
	if err := json.NewEncoder(w).Encode(info); err != nil {
		return
	}
}

func currentRuntimeReleaseInfo(getenv func(string) string, pid int) (runtimeReleaseInfo, error) {
	if pid <= 0 {
		return runtimeReleaseInfo{}, errors.New("invalid runtime pid")
	}
	info := runtimeReleaseInfo{
		Schema:         strings.TrimSpace(getenv("RRS_RUNTIME_SCHEMA")),
		ComponentID:    strings.TrimSpace(getenv("RRS_COMPONENT_ID")),
		Version:        strings.TrimSpace(getenv("RRS_SIDECAR_VERSION")),
		ArtifactSHA256: strings.ToLower(strings.TrimSpace(getenv("RRS_ARTIFACT_SHA256"))),
		PID:            pid,
	}
	if info.Schema != componentrelease.RuntimeReleaseInfoSchema {
		return runtimeReleaseInfo{}, fmt.Errorf("schema %q is not %q", info.Schema, componentrelease.RuntimeReleaseInfoSchema)
	}
	if info.ComponentID != storeRuntimeComponentID {
		return runtimeReleaseInfo{}, fmt.Errorf("component id %q is not %q", info.ComponentID, storeRuntimeComponentID)
	}
	if !safeRuntimeToken(info.Version) {
		return runtimeReleaseInfo{}, errors.New("version is missing or unsafe")
	}
	if len(info.ArtifactSHA256) != 64 {
		return runtimeReleaseInfo{}, errors.New("artifact sha256 is not 64 hex characters")
	}
	if _, err := hex.DecodeString(info.ArtifactSHA256); err != nil {
		return runtimeReleaseInfo{}, errors.New("artifact sha256 is not hexadecimal")
	}
	generation, err := strconv.ParseUint(strings.TrimSpace(getenv("RRS_GENERATION_ID")), 10, 64)
	if err != nil || generation == 0 {
		return runtimeReleaseInfo{}, errors.New("generation id is not a positive integer")
	}
	info.GenerationID = generation
	return info, nil
}

// EnvironmentFile values are data, never shell syntax.  Keep the accepted
// alphabet aligned with the controller's marker writer and reject whitespace,
// quotes, assignment, and newlines before reflecting anything in JSON.
func safeRuntimeToken(v string) bool {
	if v == "" || len(v) > 512 {
		return false
	}
	for _, r := range v {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		switch r {
		case '.', '-', '_', '+', ':', '@', '%', '/':
			continue
		default:
			return false
		}
	}
	return true
}
