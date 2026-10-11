// Package backup makes an encrypted, portable snapshot of a SopsHQ install so a
// lost machine does not lose its private keys, store, and configuration.
//
// The snapshot is a ZIP archive holding three things:
//
//   - data/...            the whole data directory (vault-sealed private keys,
//     the JSON store, the replication oplog, the audit log, and vault.json);
//   - config.jsonc        the SopsHQ configuration at backup time;
//   - RESTORE_README.txt  plain-language restore instructions (see restoreReadme).
//
// The ZIP is then sealed AS A WHOLE with AES-256-GCM, under a key derived from a
// backup key via PBKDF2-HMAC-SHA384. The on-disk and off-machine artifact
// is therefore an opaque encrypted blob (framing: magic, salt, iter, nonce,
// ciphertext), never a readable ZIP. Contents are encrypted twice: each private
// key by the vault, and the whole archive by the backup key.
//
// SECURITY: the backup key is never stored here; restoring requires it.
// No third-party dependencies.
package backup

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var magic = []byte("SOPSHQBK1")

const (
	saltLen = 16
	keyLen  = 32 // AES-256
	iter    = 600000
)

// Build zips the data dir + config + RESTORE_README and seals the ZIP as a whole
// with AES-256-GCM. It returns the sealed blob so callers (export to disk and the
// destination senders) can reuse the same bytes.
func Build(dataDir, configPath, key string) ([]byte, error) {
	if key == "" {
		return nil, errors.New("backup: empty key")
	}
	z, err := zipSet(dataDir, configPath)
	if err != nil {
		return nil, err
	}
	return seal(key, z)
}

// Export builds the sealed archive and writes it atomically to outPath (0600).
func Export(dataDir, configPath, outPath, key string) error {
	blob, err := Build(dataDir, configPath, key)
	if err != nil {
		return err
	}
	tmp := outPath + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return fmt.Errorf("backup: write: %w", err)
	}
	return os.Rename(tmp, outPath)
}

// Restore decrypts the archive at inPath with key and extracts the full
// set into destDir, which then contains data/, config.jsonc, and
// RESTORE_README.txt. destDir must not exist yet or must be empty; a
// non-empty destDir is refused before anything is read or written, so a
// caller can never overwrite existing files by mistake.
func Restore(inPath, destDir, key string) error {
	notEmpty, err := DestDirNotEmpty(destDir)
	if err != nil {
		return err
	}
	if notEmpty {
		return fmt.Errorf("backup: destination directory %q is not empty - refusing to restore into it (see -dir help)", destDir)
	}
	raw, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("backup: read: %w", err)
	}
	z, err := unseal(key, raw)
	if err != nil {
		return err
	}
	return unzip(z, destDir)
}

// DestDirNotEmpty reports whether destDir already exists and contains at
// least one entry - the condition Restore refuses to write into. A
// nonexistent directory, or one that exists but is empty, reports false.
// Callers that want to warn an operator before Restore runs (the menu's
// extra overwrite confirmation) share this same check rather than
// duplicating it.
func DestDirNotEmpty(destDir string) (bool, error) {
	entries, err := os.ReadDir(destDir)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("backup: check destination %q: %w", destDir, err)
	}
	return len(entries) > 0, nil
}

// zipSet builds the in-memory ZIP: dataDir contents under "data/", the config
// file as "config.jsonc", and the generated "RESTORE_README.txt".
func zipSet(dataDir, configPath string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	err := filepath.WalkDir(dataDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dataDir, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return writeZipEntry(zw, "data/"+filepath.ToSlash(rel), data)
	})
	if err != nil {
		return nil, fmt.Errorf("backup: zip data: %w", err)
	}

	cfg, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("backup: read config: %w", err)
	}
	if err := writeZipEntry(zw, "config.jsonc", cfg); err != nil {
		return nil, err
	}
	if err := writeZipEntry(zw, "RESTORE_README.txt", []byte(restoreReadme())); err != nil {
		return nil, err
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("backup: zip close: %w", err)
	}
	return buf.Bytes(), nil
}

// writeZipEntry adds one deflate-compressed file to the ZIP.
func writeZipEntry(zw *zip.Writer, name string, data []byte) error {
	w, err := zw.Create(name)
	if err != nil {
		return fmt.Errorf("backup: zip entry %q: %w", name, err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("backup: zip write %q: %w", name, err)
	}
	return nil
}

// unzip extracts a ZIP into destDir, rejecting any path-traversal entry.
func unzip(data []byte, destDir string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("backup: open zip: %w", err)
	}
	for _, f := range zr.File {
		clean := filepath.Clean(f.Name)
		if filepath.IsAbs(clean) || clean == ".." || hasDotDot(clean) {
			return fmt.Errorf("backup: unsafe path in archive: %q", f.Name)
		}
		target := filepath.Join(destDir, clean)
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("backup: open entry %q: %w", f.Name, err)
		}
		contents, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return fmt.Errorf("backup: read entry %q: %w", f.Name, err)
		}
		if err := os.WriteFile(target, contents, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func hasDotDot(p string) bool {
	for _, part := range bytes.Split([]byte(filepath.ToSlash(p)), []byte("/")) {
		if string(part) == ".." {
			return true
		}
	}
	return false
}

// seal wraps plain with the SOPSHQBK1 framing: magic, salt, iter, nonce, and the
// AES-256-GCM ciphertext.
func seal(key string, plain []byte) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("backup: salt: %w", err)
	}
	gcm, err := newGCM(key, salt)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("backup: nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plain, nil)

	var buf bytes.Buffer
	buf.Write(magic)
	buf.Write(salt)
	var iterBuf [4]byte
	binary.BigEndian.PutUint32(iterBuf[:], iter)
	buf.Write(iterBuf[:])
	buf.Write(nonce)
	buf.Write(ct)
	return buf.Bytes(), nil
}

// unseal reverses seal: it checks the framing and authenticates + decrypts.
func unseal(key string, raw []byte) ([]byte, error) {
	if len(raw) < len(magic)+saltLen+4+12 || !bytes.Equal(raw[:len(magic)], magic) {
		return nil, errors.New("backup: not a SopsHQ backup file")
	}
	off := len(magic)
	salt := raw[off : off+saltLen]
	off += saltLen
	off += 4 // iter (fixed; reserved for future use)
	gcm, err := newGCM(key, salt)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(raw) < off+ns {
		return nil, errors.New("backup: truncated archive")
	}
	nonce := raw[off : off+ns]
	ct := raw[off+ns:]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("backup: decrypt failed (wrong key?): %w", err)
	}
	return plain, nil
}

// newGCM derives the AES-256 key from the backup key + salt and returns a GCM AEAD.
func newGCM(key string, salt []byte) (cipher.AEAD, error) {
	dek, err := pbkdf2.Key(sha512.New384, key, salt, iter, keyLen)
	if err != nil {
		return nil, fmt.Errorf("backup: kdf: %w", err)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("backup: aes: %w", err)
	}
	return cipher.NewGCM(block)
}

// restoreReadme is the plain-language guide embedded in every archive as
// RESTORE_README.txt. ASCII-only so it is safe on any console.
func restoreReadme() string {
	return `SopsHQ encrypted backup - how to restore
========================================

WHAT THIS IS
------------
This file came from inside a SopsHQ backup archive. The archive is a single
encrypted blob: a ZIP of the items below, sealed as a whole with AES-256-GCM
(key derived with PBKDF2-HMAC-SHA384) under a backup password you chose.

WHAT IS INSIDE
--------------
  data/               The SopsHQ data directory. It holds the vault-sealed age
                      private keys, the JSON store, the replication oplog, the
                      audit log, and the vault metadata (vault.json).
  config.jsonc        The SopsHQ configuration at the time of the backup.
  RESTORE_README.txt  This file.

HOW TO RESTORE
--------------
1. Install the same SopsHQ build on the target machine.
2. Decrypt and unpack the archive into an empty directory:

     sopshq restore -in <archive-file> -dir <empty-destination-dir>

   You will be asked for the BACKUP PASSWORD (see below).
3. The destination directory then contains data/, config.jsonc, and this file.
   Put data/ where SopsHQ expects its data directory and use config.jsonc,
   then start SopsHQ and unlock the vault with the vault key as usual.

ABOUT THE BACKUP PASSWORD
-------------------------
The plaintext backup password is NEVER stored anywhere by SopsHQ. The running
config keeps only a vault-sealed (encrypted) copy, which cannot be opened
without the vault - and the vault is not available on a fresh machine. So the
backup password is NOT recoverable from this archive or from the config inside
it. You MUST supply it yourself from your own password manager, where you saved
it when you set it. Without it, this archive cannot be decrypted.

ABOUT THE PRIVATE KEYS
----------------------
Even after you restore, the age private keys inside data/ stay vault-sealed.
Using them in normal operation still requires the vault key, exactly as
on the original machine. The backup password protects the archive as a whole;
the vault key protects each key inside it.
`
}
