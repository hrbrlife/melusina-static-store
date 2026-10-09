package appscan

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ScanFiles runs the installed ClamAV engine against private copies of the
// exact bytes that will be hashed into the report. A missing database or
// scanner, a detection, or an incomplete scan refuses the report.
func ScanFiles(content [4][]byte, database, workDir string) (string, string, error) {
	stage, err := os.MkdirTemp(workDir, "scan-app-")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0o700); err != nil {
		return "", "", err
	}
	names := []string{"app.spk", "metadata.json", "RELEASE.json", "RUNTIME-CONTRACT.json"}
	staged := make([]string, 4)
	for i, name := range names {
		staged[i] = filepath.Join(stage, name)
		if err := os.WriteFile(staged[i], content[i], 0o600); err != nil {
			return "", "", err
		}
	}
	cmd := exec.Command("clamscan", append([]string{"--database=" + database, "--"}, staged...)...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("scan-app-clamav-refused: %w: %s", err, strings.TrimSpace(string(output)))
	}
	known := summaryNumber(string(output), "Known viruses")
	files := summaryNumber(string(output), "Scanned files")
	infections := summaryNumber(string(output), "Infected files")
	expectedFiles := 0
	for _, raw := range content {
		if len(raw) != 0 {
			expectedFiles++
		}
	}
	if known < 1 || files != expectedFiles || infections != 0 {
		return "", "", errors.New("scan-app-clamav-summary-invalid")
	}
	versionOutput, err := exec.Command("clamscan", "--version").Output()
	if err != nil || !strings.HasPrefix(string(versionOutput), "ClamAV ") {
		return "", "", errors.New("scan-app-clamav-version-unavailable")
	}
	return strings.TrimSpace(string(versionOutput)), strconv.Itoa(known) + "-signatures", nil
}

func summaryNumber(output, name string) int {
	match := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + `: ([0-9]+)$`).FindStringSubmatch(output)
	if len(match) != 2 {
		return -1
	}
	value, err := strconv.Atoi(match[1])
	if err != nil {
		return -1
	}
	return value
}
