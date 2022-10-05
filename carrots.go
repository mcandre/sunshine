package carrots

import (
	"io"
	"fmt"
	"log"
	"path/filepath"
	"os"
)

// Scanner collects warnings.
type Scanner struct {
	// Warnings denote an actionable permission discrepancy.
	Warnings []string
}

// ScanSSH analyzes .ssh directories.
func ScanSSH(pth string, info os.FileInfo) []string {
	if info.Name() == ".ssh" {
		mode := info.Mode() % 01000

		if mode != 0700 {
			return []string{fmt.Sprintf("%s: expected chmod 0700, got %04o", pth, mode)}
		}
	}

	return []string{}
}

// ScanAuthorizedKeys analyzes authorized_keys files.
func ScanAuthorizedKeys(pth string, info os.FileInfo) []string {
	if info.Name() == "authorized_keys" {
		mode := info.Mode() % 01000

		if mode != 0600 {
			return []string{fmt.Sprintf("%s: expected chmod 0600, got %04o", pth, mode)}
		}
	}

	return []string{}
}

// ScanKnownHosts analyzes known_hosts files.
func ScanKnownHosts(pth string, info os.FileInfo) []string {
	if info.Name() == "known_hosts" {
		mode := info.Mode() % 01000

		if mode != 0644 {
			return []string{fmt.Sprintf("%s: expected chmod 0644, got %04o", pth, mode)}
		}
	}

	return []string{}
}

// Walk traverses a file path recursively,
// collecting known permission discrepancies.
func (o *Scanner) Walk(pth string, info os.FileInfo, err error) error {
	o.Warnings = append(o.Warnings, ScanSSH(pth, info)...)
	o.Warnings = append(o.Warnings, ScanAuthorizedKeys(pth, info)...)
	o.Warnings = append(o.Warnings, ScanKnownHosts(pth, info)...)

	return nil
}

// Scan checks the given root file path recursively
// for known permission discrepancies.
func Scan(root string) []string {
	var scanner Scanner

	err := filepath.Walk(root, scanner.Walk)

	if err != nil && err != io.EOF {
		log.Print(err)
	}

	return scanner.Warnings
}

// Report emits any warnings the console.
// If warnings are present, returns 1.
// Else, returns 0.
func Report(root string) int {
	warnings := Scan(root)

	for _, warning := range warnings {
		fmt.Println(warning)
	}

	if len(warnings) != 0 {
		return 1
	}

	return 0
}
