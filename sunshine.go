package sunshine

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sync"
)

// SSHKeyPattern matches SSH key filenames.
var SSHKeyPattern = regexp.MustCompile("^id_.+$")

// SSHPublicKeyPattern matches SSH public key filenames.
var SSHPublicKeyPattern = regexp.MustCompile("^id_.+\\.pub$")

// Scanner collects warnings.
type Scanner struct {
	// Debug enables additional messages.
	Debug bool

	// DebugCh signals low level events.
	DebugCh chan string

	// WarnCh signals permission discrepancies.
	WarnCh chan string

	// ErrCh signals errors experienced during scan attempts.
	ErrCh chan error

	// DoneChn signals the end of a bulk scan.
	DoneCh chan struct{}

	// Home denotes the current user's home directory.
	Home string
}

// NewScanner constructs a scanner.
func NewScanner(debug bool) (*Scanner, error) {
	home, err := os.UserHomeDir()

	if err != nil {
		return nil, err
	}

	debugCh := make(chan string)
	warnCh := make(chan string)
	errCh := make(chan error)
	doneCh := make(chan struct{})
	scanner := Scanner{
		Debug: debug,
		DebugCh: debugCh,
		WarnCh: warnCh,
		ErrCh: errCh,
		DoneCh: doneCh,
		Home: home,
	}
	return &scanner, nil
}

// ChecknFileExists checks paths for existence.
func (o Scanner) CheckFileExists(pth string, info os.FileInfo) error {
	_, err := os.Stat(pth)

	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s: not found", pth)
	}

	return nil
}

// ValidateDirectory enforces the given directory policy.
func (o *Scanner) ValidateDirectory(pth string, info os.FileInfo) {
	if !info.IsDir() {
		o.WarnCh <- fmt.Sprintf("%s: expected directory, got file", pth)
	}
}

// ValidateFile enforces the given file policy.
func (o *Scanner) ValidateFile(pth string, info os.FileInfo) {
	if info.IsDir() {
		o.WarnCh <- fmt.Sprintf("%s: expected file, got directory", pth)
	}
}

// ValidateChmod enforces the given chmod policy.
func (o *Scanner) ValidateChmod(pth string, info os.FileInfo, expectedMode os.FileMode) {
	observedMode := info.Mode() % 01000

	if expectedMode != observedMode {
		o.WarnCh <- fmt.Sprintf("%s: expected chmod %04o, got %04o", pth, expectedMode, observedMode)
	}
}

// ValidateChmodMask enforces the given chmod mask policy.
func (o *Scanner) ValidateChmodMask(pth string, info os.FileInfo, expectedMask os.FileMode) {
	observedMode := info.Mode() % 01000

	if expectedMask & observedMode == 0 {
		o.WarnCh <- fmt.Sprintf("%s: expected chmod mask to union with %04o, got %04o", pth, expectedMask, observedMode)
	}
}

// ScanInsible analyzes paths for missing u+x (directories) or u+r (files) bits.
func (o Scanner) ScanInvisible(pth string, info os.FileInfo) {
	if info.IsDir() {
		o.ValidateChmodMask(pth, info, 0500)
	} else {
		o.ValidateChmodMask(pth, info, 0400)
	}
}

// ScanEtcSSH analyzes /etc or /etc/ssh.
func (o Scanner) ScanEtcSSH(pth string, info os.FileInfo) {
	if pth == "/etc" || pth == "/etc/ssh" {
		o.ValidateDirectory(pth, info)
		o.ValidateChmod(pth, info, 0755)
	}
}

// ScanSSH analyzes .ssh directories.
func (o Scanner) ScanUserSSH(pth string, info os.FileInfo) {
	if info.Name() == ".ssh" {
		o.ValidateDirectory(pth, info)
		o.ValidateChmod(pth, info, 0700)
	}
}

// ScanSSHConfig analyzes .ssh/config files.
func (o Scanner) ScanSSHConfig(pth string, info os.FileInfo) {
	if info.Name() == "config" {
		parent := path.Base(filepath.Dir(pth))

		if parent == ".ssh" {
			o.ValidateFile(pth, info)
			o.ValidateChmod(pth, info, 0400)
		}
	}
}

// ScanSSHKeys analyzes .ssh/id_.+(\.pub)? files.
func (o Scanner) ScanSSHKeys(pth string, info os.FileInfo) {
	name := info.Name()

	if SSHKeyPattern.MatchString(name) {
		parent := path.Base(filepath.Dir(pth))

		if parent == ".ssh" {
			o.ValidateFile(pth, info)

			if SSHPublicKeyPattern.MatchString(name) {
				o.ValidateChmod(pth, info, 0644)
			} else {
				o.ValidateChmod(pth, info, 0600)
			}
		}
	}
}

// ScanSSHAuthorizedKeys analyzes authorized_keys files.
func (o Scanner) ScanSSHAuthorizedKeys(pth string, info os.FileInfo) {
	if info.Name() == "authorized_keys" {
		o.ValidateFile(pth, info)
		o.ValidateChmod(pth, info, 0600)
	}
}

// ScanSSHKnownHosts analyzes known_hosts files.
func (o Scanner) ScanSSHKnownHosts(pth string, info os.FileInfo) {
	if info.Name() == "known_hosts" {
		o.ValidateFile(pth, info)
		o.ValidateChmod(pth, info, 0644)
	}
}

// ScanHome analyzes home directories.
func (o Scanner) ScanHome(pth string, info os.FileInfo) {
	if info.Name() == o.Home {
		o.ValidateDirectory(pth, info)
		o.ValidateChmod(pth, info, 0755)
	}
}

// Walk traverses a file path recursively,
// collecting known permission discrepancies.
func (o *Scanner) Walk(pth string, info os.FileInfo, err error) error {
	if o.Debug {
		o.DebugCh <- fmt.Sprintf("scanning: %s", pth)
	}

	if info == nil {
		return fmt.Errorf("%s: access denied", pth)
	}

	if err2 := o.CheckFileExists(pth, info); err2 != nil {
		return err2
	}

	if info.Mode() & os.ModeSymlink != 0 {
		p, err3 := os.Readlink(pth)

		if err3 != nil {
			return err3
		}

		pth = p
	}

	o.ScanInvisible(pth, info)
	o.ScanHome(pth, info)
	o.ScanEtcSSH(pth, info)
	o.ScanUserSSH(pth, info)
	o.ScanSSHConfig(pth, info)
	o.ScanSSHKeys(pth, info)
	o.ScanSSHAuthorizedKeys(pth, info)
	o.ScanSSHKnownHosts(pth, info)
	return nil
}

// Illuminate pours through the given file paths recursively
// for known permission discrepancies.
func Illuminate(roots []string, debug bool) (*Scanner, error) {
	scanner, err := NewScanner(debug)

	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	wg.Add(len(roots))

	for _, root := range roots {
		go func(r string, w *sync.WaitGroup) {
			defer w.Done()

			if err2 := filepath.Walk(r, scanner.Walk); err2 != nil && err2 != io.EOF {
				scanner.ErrCh <- err2
			}
		}(root, &wg)
	}

	go func() {
		wg.Wait()
		scanner.DoneCh<-struct{}{}
	}()

	return scanner, nil
}
