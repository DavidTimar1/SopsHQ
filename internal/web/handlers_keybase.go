package web

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"sopshq/internal/audit"
	"sopshq/internal/auth"
)

// keybaseRootView is the Settings page "Keys root folder" panel data: this
// machine's current shared keybase root (config keybase_root), read from the
// live key service. A path is not a secret.
type keybaseRootView struct {
	Root string // "" means keys stay under each user's home
}

// keybaseRootViewData reads this machine's configured keybase root from the
// live key service, so the page reflects the value the running process is
// actually using, not just what is on disk.
func (s *Server) keybaseRootViewData() keybaseRootView {
	return keybaseRootView{Root: s.keys.KeybaseRoot()}
}

// saveKeybaseRoot changes this machine's shared keybase root (config
// keybase_root). Admin-only and CSRF-checked. An empty value is accepted and
// means "no root" (keys stay under each user's home); a non-empty value must be
// an absolute path, distinct from data_dir, and an existing folder - the config
// validator checks the first two but not existence, and placement cannot work
// against a root that is not there.
//
// The new value is written to config.jsonc FIRST; only once that succeeds is
// the running service updated, so the file and the live process never
// disagree. Changing the root moves no key: it only changes where a
// root-derived user's key is placed from now on.
func (s *Server) saveKeybaseRoot(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/settings") {
		return
	}
	root := strings.TrimSpace(r.FormValue("keybase_root"))
	if root != "" {
		if !filepath.IsAbs(root) {
			redirect(w, r, "/settings", "Keys root folder must be an absolute path.", true)
			return
		}
		if root == s.cfg.DataDir {
			redirect(w, r, "/settings", "Keys root folder must be different from the data directory.", true)
			return
		}
		info, err := os.Stat(root)
		if err != nil {
			redirect(w, r, "/settings", "Keys root folder does not exist; create it first.", true)
			return
		}
		if !info.IsDir() {
			redirect(w, r, "/settings", "Keys root folder exists but is not a folder.", true)
			return
		}
	}

	old := s.cfg.KeybaseRoot
	s.cfg.KeybaseRoot = root
	if err := s.cfg.Save(); err != nil {
		s.cfg.KeybaseRoot = old
		redirect(w, r, "/settings", "Could not save the keys root folder; the previous value is still in effect.", true)
		return
	}
	s.keys.SetKeybaseRoot(root)
	s.audit.Record(sess.Username, "keybase_root_set", "config", audit.OK, root)
	redirect(w, r, "/settings",
		"Keys root folder saved. This applies to keys placed from now on; keys already placed stay where they are.", false)
}
