package web

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"sopshq/internal/audit"
	"sopshq/internal/keysvc"
	"sopshq/internal/model"
)

// ctxKey is the type of the context key reqScopeKey, under which a per-request memo
// lives. A single page render can ask for the live pending state more than once (the
// header alert and the dashboard body), and computing it runs DriftLocal (file stats +
// vault opens); the memo makes it run at most once per request.
type ctxKey int

const reqScopeKey ctxKey = iota

type reqScope struct {
	pending    keysvc.PendingState
	pendingSet bool
}

// withReqScope returns r carrying a fresh per-request memo. The protect middleware
// installs it so a handler and the renderer share one computation.
func withReqScope(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), reqScopeKey, &reqScope{}))
}

func reqScopeFrom(r *http.Request) *reqScope {
	rs, _ := r.Context().Value(reqScopeKey).(*reqScope)
	return rs
}

// pendingState returns the cached cross-machine pending state and whether it has
// been computed at least once. The request path uses this for the PEER portion; it
// never recomputes it (which could block on a slow or offline peer).
func (s *Server) pendingState() (keysvc.PendingState, bool) {
	s.pendingMu.RLock()
	defer s.pendingMu.RUnlock()
	return s.pending, s.pendingSet
}

// livePending is the pending state used for DISPLAY. The LOCAL drift is recomputed
// fresh from disk + database on this call, so a change the operator just made (a
// deleted project, a removed assignment) is reflected on the very next page without
// a manual "Sync now". The PEER portion (Remote drift + Unreachable peers) needs
// network I/O per peer, so it is taken from the background-refreshed cache. It is
// read-only: DriftLocal only stats files and reads the database. It memoizes into the
// per-request scope so a page that asks twice (header + body) computes it once.
func (s *Server) livePending(r *http.Request) keysvc.PendingState {
	if rs := reqScopeFrom(r); rs != nil && rs.pendingSet {
		return rs.pending
	}
	cached, _ := s.pendingState()
	ps := keysvc.PendingState{Remote: cached.Remote, Unreachable: cached.Unreachable}
	if s.keys.LocalMachine() != "" {
		if items, err := s.keys.DriftLocal(); err == nil {
			ps.Local = items
		}
	}
	if rs := reqScopeFrom(r); rs != nil {
		rs.pending = ps
		rs.pendingSet = true
	}
	return ps
}

// missingFolder names a project whose configured folder for THIS machine is absent
// on disk (the folder was moved or deleted). It drives a proactive alert telling the
// operator to update the project's path; nothing is changed automatically.
type missingFolder struct {
	ProjectID   string
	ProjectName string
	Path        string
}

// missingLocalFolders scans every project's configured path for the local machine
// and returns the ones whose folder does not exist (or is no longer a directory) on
// disk. Read-only: it only os.Stat's the paths and changes nothing. It returns nil
// when no local machine is designated, since there is nothing to check against. A
// path that stats with an unrelated error (e.g. permission denied) is left alone to
// avoid a false "missing" alert; only a truly absent path or a path that now points
// at a non-directory is flagged.
func (s *Server) missingLocalFolders() []missingFolder {
	localID := s.keys.LocalMachine()
	if localID == "" {
		return nil
	}
	var out []missingFolder
	for _, p := range s.store.Projects.List() {
		for _, pp := range p.Paths {
			if pp.MachineID != localID {
				continue
			}
			path := strings.TrimSpace(pp.Path)
			if path == "" {
				break
			}
			fi, err := os.Stat(path)
			if (err != nil && os.IsNotExist(err)) || (err == nil && !fi.IsDir()) {
				out = append(out, missingFolder{ProjectID: p.M.UUID, ProjectName: p.Name, Path: path})
			}
			break
		}
	}
	return out
}

// importAlert is the panel's "keys found on disk" summary: the per-keystore
// importable findings plus the totals that drive the headline badge. It is built
// by importAlertState from a read-only discovery scan.
type importAlert struct {
	Keystores []keysvc.ImportableKeystore
	Count     int // total importable (private) keys across keystores - the Import count
	PubOnly   int // total public-only keys (present on disk, no private to import)
}

// importAlertState runs the read-only on-disk key discovery scan and folds it into
// the alert totals. It changes nothing; the operator imports explicitly.
func (s *Server) importAlertState() importAlert {
	a := importAlert{Keystores: s.keys.DiscoverImportableKeys()}
	for _, k := range a.Keystores {
		a.Count += len(k.Importable)
		a.PubOnly += len(k.PubOnly)
	}
	return a
}

// refreshPending recomputes the pending state and stores it. It may block on peer
// network I/O, so it only ever runs on a background goroutine. When the state
// transitions from "no drift" to "drift present", it fires a drift notification
// once (not on every refresh while drift persists, and not at first computation,
// so a restart with pre-existing drift does not re-alert).
func (s *Server) refreshPending() {
	// Self-heal before computing drift: run the convergent cluster reconcile
	// (machine identity dedup + new-peer flagging + non-machine silent dedup +
	// orphaned-assignment pruning). It is idempotent and runs off the request path
	// (at startup, after each mutation, and on the minute tick), so pre-existing
	// duplicates and orphans clear on the next run without a manual step. Every
	// change is a store tombstone/write that replicates like any other mutation.
	s.reconcileCluster()
	st := s.keys.Pending()
	s.pendingMu.Lock()
	hadState := s.pendingSet
	prevCount := s.pending.Count()
	s.pending = st
	s.pendingSet = true
	s.pendingMu.Unlock()
	if hadState && prevCount == 0 && st.Count() > 0 {
		s.notifier.Notify(model.EventDrift, "drift detected - "+pendingSummary(st))
	}
}

// reconcileCluster runs one convergent reconcile pass and, when this node's own
// machine record was merged away (a reinstall the operator confirmed), persists the
// followed local machine id back to the config so the identity change survives a
// restart. It touches no network, so machine handlers call it synchronously for
// immediate feedback; refreshPending calls it before computing peer drift.
func (s *Server) reconcileCluster() {
	res := s.keys.ReconcileCluster("system")
	if res.LocalChanged {
		s.cfg.LocalMachineID = res.LocalMachineID
		if err := s.cfg.Save(); err != nil {
			s.audit.Record("system", "local_machine_follow_merge", res.LocalMachineID, audit.Failed, err.Error())
		} else {
			s.audit.Record("system", "local_machine_follow_merge", res.LocalMachineID, audit.OK, "reinstall adopted existing peer identity")
		}
	}
}

// refreshPendingAsync recomputes in the background unless a pass is already
// running, so a burst of mutations coalesces into at most one extra refresh.
func (s *Server) refreshPendingAsync() {
	s.pendingMu.Lock()
	if s.pendingBusy {
		s.pendingMu.Unlock()
		return
	}
	s.pendingBusy = true
	s.pendingMu.Unlock()
	go func() {
		s.refreshPending()
		s.pendingMu.Lock()
		s.pendingBusy = false
		s.pendingMu.Unlock()
	}()
}

// StartPendingRefresher computes the pending state once and then every minute until
// stop is closed. cmd/serve wires this; tests that never call it simply see an
// uncomputed state, so no peer probing happens during tests.
func (s *Server) StartPendingRefresher(stop <-chan struct{}) {
	go func() {
		s.refreshPending()
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				s.refreshPending()
			}
		}
	}()
}

// pendingSummary is the one-line title for the header alert (a tooltip).
func pendingSummary(st keysvc.PendingState) string {
	msg := strconv.Itoa(st.Count()) + " change(s) need applying"
	if n := len(st.Unreachable); n > 0 {
		msg += "; " + strconv.Itoa(n) + " machine(s) could not be checked"
	}
	return msg
}
