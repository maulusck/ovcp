// Package backup: encrypted export/import of ovcp state. Excludes the reissuable openvpn server cert/key; always includes tls-crypt.key (not reissuable).
package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ovcp/ovcp/internal/pki"
	"github.com/ovcp/ovcp/internal/store"
)

type file struct{ src, name string }

// required files (relative to dataDir) -> name inside the archive. Missing
// any of these means dataDir isn't a real ovcp install; Create errors out.
var requiredFiles = []file{
	{filepath.Join("pki", "ca.crt"), "pki/ca.crt"},
	{filepath.Join("pki", "ca.key.enc"), "pki/ca.key.enc"},
	{filepath.Join("pki", "crl.pem"), "pki/crl.pem"},
	{filepath.Join("pki", "tls-crypt.key"), "pki/tls-crypt.key"},
	{"server.conf", "server.conf"},
}

// optional files: included if present, silently skipped otherwise.
var optionalFiles = []file{
	{"openvpn.log", "openvpn.log"},
}

// ErrAlreadyInitialized guards Restore against clobbering a live install.
var ErrAlreadyInitialized = errors.New("backup: data directory already has a CA; use -force to overwrite")

// Create writes an encrypted tar.gz backup (CA, CRL, tls-crypt key, server.conf, database) to w.
func Create(dataDir string, s *store.Store, w io.Writer, passphrase []byte) error {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	for _, f := range requiredFiles {
		data, err := os.ReadFile(filepath.Join(dataDir, f.src))
		if err != nil {
			return fmt.Errorf("backup: %s: %w", f.src, err)
		}
		if err := tarWrite(tw, f.name, data); err != nil {
			return err
		}
	}
	for _, f := range optionalFiles {
		data, err := os.ReadFile(filepath.Join(dataDir, f.src))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("backup: %s: %w", f.src, err)
		}
		if err := tarWrite(tw, f.name, data); err != nil {
			return err
		}
	}

	dbSnapshot, err := snapshotDB(s)
	if err != nil {
		return fmt.Errorf("backup: database snapshot: %w", err)
	}
	if err := tarWrite(tw, "ovcp.db", dbSnapshot); err != nil {
		return err
	}

	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	sealed, err := pki.Seal(buf.Bytes(), passphrase)
	if err != nil {
		return err
	}
	_, err = w.Write(sealed)
	return err
}

// Restore extracts an archive created by Create into dataDir. It writes no
// server cert/key (the archive never has one) — run `ovcp renew-server`
// right after to issue one from the restored CA.
func Restore(dataDir string, r io.Reader, passphrase []byte, force bool) error {
	if !force {
		if _, err := os.Stat(filepath.Join(dataDir, "pki", "ca.crt")); err == nil {
			return ErrAlreadyInitialized
		}
	}
	sealed, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	plain, err := pki.Open(sealed, passphrase)
	if err != nil {
		return err
	}
	gz, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return fmt.Errorf("backup: corrupt archive: %w", err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("backup: corrupt archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return fmt.Errorf("backup: unsafe path in archive: %q", hdr.Name)
		}
		dst := filepath.Join(dataDir, clean)
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			return err
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return err
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			return err
		}
	}
}

func tarWrite(tw *tar.Writer, name string, data []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(data)), Mode: 0o600}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

// snapshotDB copies the live database via VACUUM INTO (a torn raw file copy
// under concurrent writes would make for a very bad day on restore).
func snapshotDB(s *store.Store) ([]byte, error) {
	tmp, err := os.CreateTemp("", "ovcp-backup-*.db")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	tmp.Close()
	os.Remove(tmpPath) // VACUUM INTO requires the destination not exist
	defer os.Remove(tmpPath)
	if err := s.BackupTo(tmpPath); err != nil {
		return nil, err
	}
	return os.ReadFile(tmpPath)
}
