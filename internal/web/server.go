// Package web is SopsHQ's admin panel: a server-rendered HTML UI built on
// net/http and html/template with a little vanilla JavaScript. The layout is
// responsive (usable from phone to desktop) and themable (light/dark).
//
// Security posture: the panel is served over plain HTTP and reached only on a
// trusted network boundary - loopback (via an SSH tunnel) or a Tailscale address
// (WireGuard-encrypted, tailnet-only). Do not bind 0.0.0.0 on a host with a public
// IP. Session cookies are HttpOnly and SameSite=Strict (the Secure flag is off over
// HTTP, which is fine on loopback/Tailscale); state-changing POSTs carry a CSRF
// token bound to the session; routes are gated by login and, where noted, by the
// admin role. Login requires a password AND a TOTP code, and repeated failures lock
// a username out briefly.
package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"sync"
	"time"

	"sopshq/internal/audit"
	"sopshq/internal/auth"
	"sopshq/internal/config"
	"sopshq/internal/keysvc"
	"sopshq/internal/model"
	"sopshq/internal/notify"
	"sopshq/internal/permmap"
	"sopshq/internal/store"
	"sopshq/internal/vault"
)

const sessionCookie = "sopshq_session"

// Server holds the panel's dependencies and compiled templates.
type Server struct {
	store    *store.Store
	vault    *vault.Vault
	audit    *audit.Log
	keys     *keysvc.Service
	cfg      *config.Config
	sessions *auth.Manager
	nodeName string
	version  string

	secret []byte // server-side key for deriving CSRF tokens
	tmpl   map[string]*template.Template
	mux    *http.ServeMux

	// syncFn triggers one replication pull from all peers, returning
	// (peers, applied, conflicts). nil until SetSync is called.
	syncFn func() (int, int, int)

	// peerStatusFn reports each peer's live reachability and last pull outcome for
	// the Machines page. nil until SetPeerStatus is called (the page then omits the
	// status column, e.g. in tests).
	peerStatusFn func() []PeerStatus

	// ingestToken gates the best-effort usage ingestion endpoint. Empty disables
	// it (returns 404).
	ingestToken string

	// backupRun triggers one self-backup run, returning an ASCII status summary.
	// nil until SetBackupRunner is called (the dashboard then hides "Back up now").
	backupRun func() (string, error)

	// notifier fans chosen events out to the operator's Telegram/Slack channels.
	// nil until SetNotifier is called; its methods are nil-safe, so call sites need
	// no guard. It never blocks or fails the action that triggers it.
	notifier *notify.Notifier

	// permmap stores the machine-local, vault-sealed filesystem permission scans
	// (latest + baseline). nil until SetPermmap is called (e.g. in tests, or when
	// the vault-derived crypter is unavailable); the page then shows an empty state.
	permmap *permmap.Store

	// logins throttles repeated failed logins: after too many consecutive failures
	// for a username it locks that username out for a short window. In-memory only.
	logins *loginLimiter

	// lastBackup records the most recent run for the dashboard. Guarded by its
	// mutex because the panel handler and (in serve) the daily ticker both write it.
	lastBackupMu sync.Mutex
	lastBackup   lastBackupState

	// lastAction records the most recent apply/sync result for the dashboard's
	// detailed results panel. Guarded by its mutex because any apply/sync handler
	// may write it concurrently with a dashboard read.
	lastActionMu sync.Mutex
	lastAction   lastActionState

	// pending caches the cross-machine "needs applying" state so the header alert
	// and dashboard read it cheaply. Computing it can block on peer network I/O, so
	// a background refresher (StartPendingRefresher) and post-mutation async passes
	// keep it current; the request path never recomputes it. pendingSet is false
	// until the first computation completes (e.g. in tests that never start it).
	pendingMu   sync.RWMutex
	pending     keysvc.PendingState
	pendingSet  bool
	pendingBusy bool
}

// SetSync wires the manual "Sync now" action to the server's replication runner.
func (s *Server) SetSync(f func() (int, int, int)) { s.syncFn = f }

// SetPeerStatus wires the Machines page's live per-peer status (reachability +
// last pull outcome).
func (s *Server) SetPeerStatus(f func() []PeerStatus) { s.peerStatusFn = f }

// SetIngestToken enables the usage ingestion endpoint, requiring this token.
func (s *Server) SetIngestToken(tok string) { s.ingestToken = tok }

// SetBackupRunner wires the "Back up now" button (and reports backups as available)
// to the server's self-backup runner.
func (s *Server) SetBackupRunner(f func() (string, error)) { s.backupRun = f }

// SetNotifier wires the event notifier so chosen panel events alert the operator's
// configured channels. Until called, event notifications are no-ops.
func (s *Server) SetNotifier(n *notify.Notifier) { s.notifier = n }

// SetPermmap wires the machine-local permission-scan storage so the auditor page
// can read scans and store new ones. Until called, the page renders an empty
// state (no scan data) but still shows the setup instructions.
func (s *Server) SetPermmap(p *permmap.Store) { s.permmap = p }

// NewServer wires the panel. It compiles templates from the embedded FS and
// registers routes. ttl is the session lifetime.
func NewServer(st *store.Store, v *vault.Vault, a *audit.Log, ks *keysvc.Service, cfg *config.Config, version string, ttl time.Duration) (*Server, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("web: secret: %w", err)
	}
	s := &Server{
		store:    st,
		vault:    v,
		audit:    a,
		keys:     ks,
		cfg:      cfg,
		sessions: auth.NewManager(ttl),
		nodeName: cfg.NodeName,
		version:  version,
		secret:   secret,
		logins:   newLoginLimiter(),
	}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	s.routes()
	return s, nil
}

// Handler returns the root http.Handler for the panel.
func (s *Server) Handler() http.Handler { return s.mux }

// parseTemplates builds one template set per page, each cloned from the shared
// layout so pages can define their own "content" and "title" blocks.
func (s *Server) parseTemplates() error {
	base, err := template.New("layout").Funcs(funcs).ParseFS(tmplFS, "templates/layout.html")
	if err != nil {
		return fmt.Errorf("web: parse layout: %w", err)
	}
	pages, err := fs.Glob(tmplFS, "templates/pages/*.html")
	if err != nil {
		return err
	}
	s.tmpl = make(map[string]*template.Template, len(pages))
	for _, p := range pages {
		name := pageName(p)
		clone, err := base.Clone()
		if err != nil {
			return err
		}
		if _, err := clone.ParseFS(tmplFS, p); err != nil {
			return fmt.Errorf("web: parse %s: %w", p, err)
		}
		s.tmpl[name] = clone
	}
	return nil
}

// routes registers all handlers.
func (s *Server) routes() {
	m := http.NewServeMux()

	static, _ := fs.Sub(staticFS, "static")
	m.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))

	// Best-effort usage ingestion (token-gated, no session: called by a shim, not
	// a logged-in user).
	m.HandleFunc("POST /ingest/keyused", s.ingestKeyUsed)

	// First-run setup (only usable while there are no panel users).
	m.HandleFunc("GET /setup", s.getSetup)
	m.HandleFunc("POST /setup", s.postSetup)
	m.HandleFunc("GET /setup/totp", s.getSetupTOTP)
	m.HandleFunc("POST /setup/totp", s.postSetupTOTP)

	// Auth.
	m.HandleFunc("GET /login", s.getLogin)
	m.HandleFunc("POST /login", s.postLogin)
	m.HandleFunc("POST /logout", s.protect(s.postLogout))

	// Dashboard.
	m.HandleFunc("GET /{$}", s.protect(s.getDashboard))

	// Settings: this machine's paths + self-backup controls.
	m.HandleFunc("GET /settings", s.protect(s.getSettings))

	// DB: a read-only browse view with one filterable table per record type.
	// Login-gated; the Users and Secrets tabs are gathered only for admins.
	m.HandleFunc("GET /db", s.protect(s.getDB))

	// Permissions: the read-only Linux filesystem permission/ACL auditor. Admin-only
	// throughout - the map reveals the whole filesystem layout and who can access
	// what. The page and its JSON feeds read scans; the POSTs scan, set a baseline,
	// and enable/disable/configure the feature.
	m.HandleFunc("GET /permmap", s.protectAdmin(s.getPermmap))
	m.HandleFunc("GET /permmap/data", s.protectAdmin(s.getPermmapData))
	m.HandleFunc("GET /permmap/tree", s.protectAdmin(s.getPermmapTree))
	m.HandleFunc("GET /permmap/diff", s.protectAdmin(s.getPermmapDiff))
	m.HandleFunc("POST /permmap/scan", s.protectAdmin(s.scanPermmap))
	m.HandleFunc("POST /permmap/baseline", s.protectAdmin(s.baselinePermmap))
	m.HandleFunc("POST /permmap/enable", s.protectAdmin(s.enablePermmap))
	m.HandleFunc("POST /permmap/disable", s.protectAdmin(s.disablePermmap))
	m.HandleFunc("POST /permmap/config", s.protectAdmin(s.configPermmap))

	// Map: a custom nested-tree explorer of how the records relate. The page and
	// its tree JSON are login-gated; editing the stored custom views is admin-only.
	m.HandleFunc("GET /map", s.protect(s.getMap))
	m.HandleFunc("GET /map/tree", s.protect(s.getMapTree))
	m.HandleFunc("POST /map/views", s.protectAdmin(s.createMapView))
	m.HandleFunc("POST /map/views/{id}", s.protectAdmin(s.updateMapView))
	m.HandleFunc("POST /map/views/{id}/delete", s.protectAdmin(s.deleteMapView))

	// Conflicts: resolve the duplicate records the lossless reconcile pass left intact.
	// The read-only list is login-gated; the destructive resolutions (they delete records
	// and pick which sealed credential survives) are admin-only, matching the backup /
	// notification settings surfaces they can act on. Merge is a two-step, double-confirmed
	// flow: the list posts picks to /merge/confirm (step 2 render), and only that page can
	// reach /merge/execute (which refuses without the confirm token).
	m.HandleFunc("GET /conflicts", s.protect(s.listConflicts))
	m.HandleFunc("POST /conflicts/merge/confirm", s.protectAdmin(s.confirmConflictMerge))
	m.HandleFunc("POST /conflicts/merge/execute", s.protectAdmin(s.executeConflictMerge))
	m.HandleFunc("POST /conflicts/keep-both", s.protectAdmin(s.keepBothConflict))
	// Same-field divergences (two machines changed the SAME field of one record):
	// also a two-step, double-confirmed pick (choosing one value discards the other),
	// admin-only like the record merges.
	m.HandleFunc("POST /conflicts/field/confirm", s.protectAdmin(s.confirmFieldConflict))
	m.HandleFunc("POST /conflicts/field/execute", s.protectAdmin(s.executeFieldConflict))

	// Quick add: guided one-shot to add a secret (project- or global-scoped).
	m.HandleFunc("GET /quick-add", s.protect(s.getQuickAdd))
	m.HandleFunc("POST /quick-add", s.protect(s.postQuickAdd))

	// Help: in-panel terminology + how-it-works (glossary, two gates, diagram).
	m.HandleFunc("GET /help", s.protect(s.getHelp))

	// Account security (self-service 2FA re-enrollment for the logged-in user).
	m.HandleFunc("GET /account", s.protect(s.getAccount))
	m.HandleFunc("POST /account/reenroll", s.protect(s.reenrollTOTP))

	// Resource CRUD (any logged-in user may view/manage operational records).
	m.HandleFunc("GET /machines", s.protect(s.listMachines))
	m.HandleFunc("POST /machines", s.protect(s.createMachine))
	m.HandleFunc("POST /machines/{id}/delete", s.protect(s.deleteMachine))
	m.HandleFunc("POST /machines/{id}/local", s.protect(s.setLocalMachine))
	// New-peer confirmation: a peer whose identity is new (via Add peer or sync) is
	// held Pending until the operator says it is a distinct new peer or a reinstall.
	m.HandleFunc("POST /machines/{id}/confirm-new", s.protect(s.confirmNewPeer))
	m.HandleFunc("POST /machines/{id}/confirm-reinstall", s.protect(s.confirmReinstallPeer))

	// Cluster sync: set the shared transfer key (admin-only, CSRF-checked).
	m.HandleFunc("POST /machines/transfer-key", s.protectAdmin(s.setTransferKey))

	m.HandleFunc("GET /osusers", s.protect(s.listOSUsers))
	m.HandleFunc("POST /osusers", s.protect(s.createOSUser))
	m.HandleFunc("POST /osusers/{id}/delete", s.protect(s.deleteOSUser))
	m.HandleFunc("POST /osusers/{id}/fix-discovery", s.protect(s.fixDiscovery))
	m.HandleFunc("POST /osusers/{id}/import-keys", s.protect(s.importKeys))

	m.HandleFunc("GET /projects", s.protect(s.listProjects))
	m.HandleFunc("POST /projects", s.protect(s.createProject))
	m.HandleFunc("POST /projects/{id}/delete", s.protect(s.deleteProject))
	m.HandleFunc("GET /projects/{id}", s.protect(s.projectDetail))
	m.HandleFunc("POST /projects/{id}/paths", s.protect(s.addProjectPath))
	m.HandleFunc("POST /projects/{id}/paths/delete", s.protect(s.deleteProjectPath))
	m.HandleFunc("POST /projects/{id}/wire", s.protect(s.wireProject))
	m.HandleFunc("POST /projects/{id}/wire/resolve", s.protect(s.resolveWiring))
	m.HandleFunc("POST /projects/{id}/secrets", s.protect(s.addSecret))
	m.HandleFunc("POST /projects/{id}/secrets/edit", s.protect(s.editSecret))
	m.HandleFunc("POST /projects/{id}/secrets/reveal", s.protect(s.revealSecret))
	m.HandleFunc("POST /projects/{id}/secrets/bulk-add", s.protect(s.bulkAddSecrets))
	m.HandleFunc("POST /projects/{id}/secrets/delete", s.protect(s.deleteSecret))

	// Folder browser for path fields (lists directories on THIS machine only).
	m.HandleFunc("GET /fs/list", s.protect(s.browseFolder))

	m.HandleFunc("GET /keys", s.protect(s.listKeys))
	m.HandleFunc("POST /keys", s.protect(s.createKey))
	m.HandleFunc("POST /keys/{id}/delete", s.protect(s.deleteKey))
	m.HandleFunc("POST /keys/{id}/rename", s.protect(s.renameKey))
	m.HandleFunc("POST /keys/{id}/generate", s.protect(s.generateKey))
	m.HandleFunc("POST /keys/{id}/rotate", s.protect(s.rotateKey))

	m.HandleFunc("POST /assignments", s.protect(s.createAssignment))
	m.HandleFunc("POST /assignments/{id}/delete", s.protect(s.deleteAssignment))

	m.HandleFunc("POST /apply", s.protect(s.applyLocal))
	m.HandleFunc("POST /apply-all", s.protect(s.applyAll))
	m.HandleFunc("POST /sync", s.protect(s.syncNow))

	// Self-backup controls are admin-only (they unseal the backup password and can
	// push the whole sealed archive off-machine).
	m.HandleFunc("POST /backup/now", s.protectAdmin(s.backupNow))
	m.HandleFunc("POST /backup/password", s.protectAdmin(s.setBackupPassword))
	m.HandleFunc("POST /backup/config", s.protectAdmin(s.saveBackupConfig))
	m.HandleFunc("POST /backup/destinations/add", s.protectAdmin(s.addBackupDestination))
	m.HandleFunc("POST /backup/destinations/remove", s.protectAdmin(s.removeBackupDestination))

	// Notification controls are admin-only (they seal channel credentials and can
	// send a message off-machine).
	m.HandleFunc("POST /notifications/config", s.protectAdmin(s.saveNotificationConfig))
	m.HandleFunc("POST /notifications/telegram", s.protectAdmin(s.setNotificationTelegram))
	m.HandleFunc("POST /notifications/slack", s.protectAdmin(s.setNotificationSlack))
	m.HandleFunc("POST /notifications/test", s.protectAdmin(s.testNotification))

	// Audit-retention policy lives in config.jsonc; saving it is admin-only.
	m.HandleFunc("POST /settings/retention", s.protectAdmin(s.saveRetention))

	// Keys root folder (keybase_root) lives in config.jsonc; saving it is
	// admin-only, matching the other config-writing settings above.
	m.HandleFunc("POST /settings/keybase-root", s.protectAdmin(s.saveKeybaseRoot))

	// Reconcile an external change to a managed file (keys.txt/.sops.yaml/secrets.yaml).
	// Admin-only: adopting imports a manually-added key into the vault, and overwriting
	// re-asserts SopsHQ's state - both privileged.
	m.HandleFunc("POST /reconcile", s.protectAdmin(s.postReconcile))

	m.HandleFunc("GET /drift", s.protect(s.getDrift))
	m.HandleFunc("POST /drift/resolve", s.protect(s.resolveDrift))
	m.HandleFunc("GET /usage", s.protect(s.getUsage))
	m.HandleFunc("POST /usage/shim/install", s.protect(s.installShim))
	m.HandleFunc("POST /usage/shim/uninstall", s.protect(s.uninstallShim))

	m.HandleFunc("GET /audit", s.protect(s.getAudit))
	// Audit-log purges are destructive, so admin-only.
	m.HandleFunc("POST /audit/purge-all", s.protectAdmin(s.purgeAllAudit))
	m.HandleFunc("POST /audit/purge-before", s.protectAdmin(s.purgeAuditBefore))

	// Cross-project secrets catalog is admin-only (a mass-decrypt surface). The
	// JSON feed backs the reuse picker on the project page.
	m.HandleFunc("GET /secrets", s.protectAdmin(s.getSecretsCatalog))
	m.HandleFunc("GET /secrets/catalog.json", s.protectAdmin(s.getSecretsCatalogJSON))
	m.HandleFunc("GET /secrets/edit", s.protectAdmin(s.getSecretEdit))
	m.HandleFunc("POST /secrets/edit", s.protectAdmin(s.postSecretEdit))

	// Global (shared) secrets: named sets encrypted to one or more OS users, each
	// decrypting with their own key. Login-gated like project secrets.
	m.HandleFunc("GET /global", s.protect(s.getGlobal))
	m.HandleFunc("POST /global", s.protect(s.createGlobalSet))
	m.HandleFunc("POST /global/{id}/delete", s.protect(s.deleteGlobalSet))
	m.HandleFunc("POST /global/{id}/secrets", s.protect(s.addGlobalSecret))
	m.HandleFunc("POST /global/{id}/secrets/reveal", s.protect(s.revealGlobalSecret))
	m.HandleFunc("POST /global/{id}/secrets/delete", s.protect(s.deleteGlobalSecret))

	// Panel-user management is admin-only.
	m.HandleFunc("GET /users", s.protectAdmin(s.listUsers))
	m.HandleFunc("POST /users", s.protectAdmin(s.createUser))
	m.HandleFunc("POST /users/{id}/delete", s.protectAdmin(s.deleteUser))
	m.HandleFunc("POST /users/{id}/reset-2fa", s.protectAdmin(s.resetUserTOTP))

	s.mux = m
}

// ---- middleware -----------------------------------------------------------

// protect wraps a handler so only logged-in users reach it, passing the session to
// the handler.
func (s *Server) protect(h func(http.ResponseWriter, *http.Request, auth.Session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.session(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// Install a per-request memo so the handler and the renderer share one
		// computation of the live pending state (DriftLocal runs at most once).
		h(w, withReqScope(r), sess)
	}
}

// protectAdmin is protect plus an admin-role check.
func (s *Server) protectAdmin(h func(http.ResponseWriter, *http.Request, auth.Session)) http.HandlerFunc {
	return s.protect(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		if sess.Role != model.RoleAdmin {
			s.audit.Record(sess.Username, "access_denied", r.URL.Path, audit.Denied, "admin only")
			s.renderError(w, r, sess, "Admins only.", http.StatusForbidden)
			return
		}
		h(w, r, sess)
	})
}

// session returns the current session for a request, if any.
func (s *Server) session(r *http.Request) (auth.Session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return auth.Session{}, false
	}
	return s.sessions.Get(c.Value)
}

// setSessionCookie writes the session cookie with safe attributes.
func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
}

// ---- CSRF -----------------------------------------------------------------

// csrfToken derives a per-session CSRF token: HMAC(secret, sessionToken). It is
// embedded in forms and re-checked on POST.
func (s *Server) csrfToken(sessionToken string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(sessionToken))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// checkCSRF validates the "csrf" form field against the session.
func (s *Server) checkCSRF(r *http.Request, sess auth.Session) bool {
	got := r.FormValue("csrf")
	want := s.csrfToken(sess.Token)
	return got != "" && hmac.Equal([]byte(got), []byte(want))
}

// pageName turns "templates/pages/keys.html" into "keys".
func pageName(p string) string {
	base := p[len("templates/pages/"):]
	return base[:len(base)-len(".html")]
}
