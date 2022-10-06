package sunshine

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
)

// SSHKeyPattern matches SSH key filenames.
var SSHKeyPattern = regexp.MustCompile("^id_.+$")

// SSHPublicKeyPattern matches SSH public key filenames.
var SSHPublicKeyPattern = regexp.MustCompile("^id_.+\\.pub$")

// Scanner collects warnings.
type Scanner struct {
	// Warnings denote an actionable permission discrepancy.
	Warnings []string

	// Home denotes the current user's home directory.
	Home string
}

// NewScanner constructs a scanner.
func NewScanner() (*Scanner, error) {
	home, err := os.UserHomeDir()

	if err != nil {
		return nil, err
	}

	return &Scanner{Home: home}, nil
}

// ScanFileExists checks paths for existence.
func (o Scanner) ScanFileExists(pth string, info os.FileInfo) error {
	_, err := os.Stat(pth)

	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s: not found", pth)
	}

	return nil
}

// ScanSSH analyzes .ssh directories.
func (o Scanner) ScanSSH(pth string, info os.FileInfo) []string {
	if info.Name() == ".ssh" {
		mode := info.Mode() % 01000

		if mode != 0700 {
			return []string{fmt.Sprintf("%s: expected chmod 0700, got %04o", pth, mode)}
		}
	}

	return []string{}
}

// ScanSSHConfig analyzes .ssh/config files.
func (o Scanner) ScanSSHConfig(pth string, info os.FileInfo) []string {
	if info.Name() == "config" {
		parent := path.Base(filepath.Dir(pth))

		if parent == ".ssh" {
			mode := info.Mode() % 01000

			if mode != 0400 {
				return []string{fmt.Sprintf("%s: expected chmod 0400, got %04o", pth, mode)}
			}
		}
	}

	return []string{}
}

// ScanSSHKeys analyzes .ssh/id_.+(\.pub)? files.
func (o Scanner) ScanSSHKeys(pth string, info os.FileInfo) []string {
	name := info.Name()

	if SSHKeyPattern.MatchString(name) {
		parent := path.Base(filepath.Dir(pth))

		if parent == ".ssh" {
			mode := info.Mode() % 01000

			if SSHPublicKeyPattern.MatchString(name) {
				if mode != 0644 {
					return []string{fmt.Sprintf("%s: expected chmod 0644, got %04o", pth, mode)}
				}
			} else {
				if mode != 0600 {
					return []string{fmt.Sprintf("%s: expected chmod 0600, got %04o", pth, mode)}
				}
			}
		}
	}

	return []string{}
}

// ScanSSHAuthorizedKeys analyzes authorized_keys files.
func (o Scanner) ScanSSHAuthorizedKeys(pth string, info os.FileInfo) []string {
	if info.Name() == "authorized_keys" {
		mode := info.Mode() % 01000

		if mode != 0600 {
			return []string{fmt.Sprintf("%s: expected chmod 0600, got %04o", pth, mode)}
		}
	}

	return []string{}
}

// ScanSSHKnownHosts analyzes known_hosts files.
func (o Scanner) ScanSSHKnownHosts(pth string, info os.FileInfo) []string {
	if info.Name() == "known_hosts" {
		mode := info.Mode() % 01000

		if mode != 0644 {
			return []string{fmt.Sprintf("%s: expected chmod 0644, got %04o", pth, mode)}
		}
	}

	return []string{}
}

// ScanHome analyzes home directories.
func (o Scanner) ScanHome(pth string, info os.FileInfo) []string {
	if info.Name() == o.Home {
		mode := info.Mode() % 01000

		if mode != 0755 {
			return []string{fmt.Sprintf("%s: expected chmod 0755, got %04o", pth, mode)}
		}
	}

	return []string{}
}

// Walk traverses a file path recursively,
// collecting known permission discrepancies.
func (o *Scanner) Walk(pth string, info os.FileInfo, err error) error {
	if err2 := o.ScanFileExists(pth, info); err2 != nil {
		return err2
	}

	o.Warnings = append(o.Warnings, o.ScanSSH(pth, info)...)
	o.Warnings = append(o.Warnings, o.ScanSSHConfig(pth, info)...)
	o.Warnings = append(o.Warnings, o.ScanSSHKeys(pth, info)...)
	o.Warnings = append(o.Warnings, o.ScanSSHAuthorizedKeys(pth, info)...)
	o.Warnings = append(o.Warnings, o.ScanSSHKnownHosts(pth, info)...)

	o.Warnings = append(o.Warnings, o.ScanHome(pth, info)...)
	return nil
}

// Scan checks the given root file path recursively
// for known permission discrepancies.
func Scan(roots []string) ([]string, []error) {
	scanner, err := NewScanner()

	if err != nil {
		return []string{}, []error{err}
	}

	var errs []error

	for _, root := range roots {
		if err2 := filepath.Walk(root, scanner.Walk); err2 != nil && err2 != io.EOF {
			errs = append(errs, err2)
		}
	}

	return scanner.Warnings, errs
}

// Report emits any warnings the console.
// If warnings are present, returns 1.
// Else, returns 0.
func Report(roots []string) int {
	warnings, errs := Scan(roots)

	for _, warning := range warnings {
		fmt.Println(warning)
	}

	if len(errs) != 0 {
		for _, err := range errs {
			fmt.Println(err)
		}

		return 1
	}

	if len(warnings) != 0 {
		return 1
	}

	return 0
}
