package keysvc

import (
	"strings"

	"sopshq/internal/keys"
	"sopshq/internal/place"
)

// ImportableKeystore reports one LOCAL OS user whose on-disk keystore holds age
// key material that SopsHQ does not yet track. It is produced by a READ-ONLY scan
// (DiscoverImportableKeys) and carries only NON-secret facts (username, keystore
// path, public keys), so it is safe to render in the panel and keep in memory. The
// panel turns it into a one-click Import that runs the dedup-safe adopt path.
type ImportableKeystore struct {
	OSUserID string
	Username string
	KeyBase  string
	// Importable lists the PUBLIC keys (age1...) of on-disk PRIVATE keys (keys.txt)
	// whose public key is not yet a Key in the database. Importing seals each private
	// key into the vault (adopt). Public, safe to display.
	Importable []string
	// PubOnly lists PUBLIC keys present on disk (keys.pub) that have NO matching
	// private key in keys.txt to import. A public-only file cannot be adopted (there
	// is no private half to seal into the vault), so it is shown for awareness only.
	PubOnly []string
}

// DiscoverImportableKeys scans every LOCAL OS user's keystore for age key material
// that is not yet in the database and returns the importable findings. It is
// READ-ONLY: it only reads each keystore's keys.txt / keys.pub and the database, and
// never places, writes, or repoints anything. The operator triggers the actual
// import explicitly (AdoptExistingKeyForOSUser via the panel's Import button).
//
// A user that already has a key in custody is skipped: AdoptExistingKeyForOSUser
// only imports for a user with none yet, so the surfaced set matches exactly what
// clicking Import would bring in. Within a scanned user, an on-disk key whose public
// key is already a Key in the database (deduped by keyByRecipient) is not surfaced,
// so a key SopsHQ already tracks never shows up as "importable".
//
// SECURITY: private keys are read only to derive their PUBLIC recipient (via
// age-keygen -y, which never emits the private half); no private key is stored in the
// result or logged.
func (s *Service) DiscoverImportableKeys() []ImportableKeystore {
	if s.localMachineID == "" {
		return nil
	}
	var out []ImportableKeystore
	for _, u := range s.store.OSUsers.List() {
		base := s.userKeyBase(u)
		if u.MachineID != s.localMachineID || base == "" {
			continue
		}
		if s.userGeneratedKey(u.M.UUID) != nil {
			continue // already tracked; Import would be a no-op for this user
		}
		item := ImportableKeystore{OSUserID: u.M.UUID, Username: u.Username, KeyBase: base}
		privRecips := map[string]bool{}
		// Derive every on-disk private key's public key in ONE age-keygen exec (the
		// whole capped keys.txt on stdin), rather than one exec per key, to bound the
		// render-path cost.
		if privs, err := place.ReadPrivateKeys(base); err == nil {
			if recs, derr := keys.RecipientsFor(strings.Join(privs, "\n")); derr == nil {
				for _, rec := range recs {
					if rec == "" || privRecips[rec] {
						continue
					}
					privRecips[rec] = true
					if _, inDB := s.keyByRecipient(rec); !inDB {
						item.Importable = append(item.Importable, rec)
					}
				}
			}
		}
		for _, rec := range readPubRecipients(base) {
			if privRecips[rec] {
				continue // its private half is on disk (handled above)
			}
			if _, inDB := s.keyByRecipient(rec); inDB {
				continue
			}
			item.PubOnly = append(item.PubOnly, rec)
		}
		if len(item.Importable) > 0 || len(item.PubOnly) > 0 {
			out = append(out, item)
		}
	}
	return out
}

// readPubRecipients reads the age public keys (age1...) from a keystore's keys.pub,
// or nil when the file is absent or holds none. Public keys are safe to read and
// display; nothing is written.
func readPubRecipients(base string) []string {
	data, err := place.ReadCappedFile(place.PubFile(base))
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if strings.HasPrefix(line, "age1") {
			out = append(out, line)
		}
	}
	return out
}
