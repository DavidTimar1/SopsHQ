package keysvc

import (
	"path/filepath"
	"strings"

	"sopshq/internal/model"
	"sopshq/internal/usage"
)

// SetUsage enables best-effort key-usage tracking with the given log.
func (s *Service) SetUsage(l *usage.Log) { s.usage = l }

// RecordUse records a best-effort key-usage (decrypt) event. It is a no-op if
// usage tracking is not enabled. Reporters give at least a path; key_id is
// optional (attribution falls back to the project the path lives in).
func (s *Service) RecordUse(user, path, keyID, source string) error {
	if s.usage == nil {
		return nil
	}
	return s.usage.Record(usage.Event{User: user, Path: path, KeyID: keyID, Source: source})
}

// KeyUsage is a best-effort usage summary for one key.
type KeyUsage struct {
	Count int
	Last  int64 // Unix seconds of the most recent attributed event, 0 if none
}

// UsageForKey returns the best-effort decrypt count and last-used time attributed
// to a key. Returns the zero value when usage tracking is off.
func (s *Service) UsageForKey(keyID string) KeyUsage {
	var u KeyUsage
	if s.usage == nil {
		return u
	}
	events, err := s.usage.All()
	if err != nil {
		return u
	}
	for _, ev := range events {
		if !s.eventHitsKey(ev, keyID) {
			continue
		}
		u.Count++
		if ev.Time > u.Last {
			u.Last = ev.Time
		}
	}
	return u
}

// RecentUsage returns the most recent usage events (newest first).
func (s *Service) RecentUsage(limit int) ([]usage.Event, error) {
	if s.usage == nil {
		return nil, nil
	}
	return s.usage.Recent(limit)
}

// KeysForEvent resolves the key ids a usage event is attributed to: an explicit
// key_id if present, plus the keys assigned (on the local machine) to the local
// project whose folder contains the event's path.
func (s *Service) KeysForEvent(ev usage.Event) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	add(ev.KeyID)
	if p := s.localProjectForPath(ev.Path); p != nil {
		for _, a := range s.store.Assignments.List() {
			if a.ProjectID == p.M.UUID && a.MachineID == s.localMachineID {
				add(a.KeyID)
			}
		}
	}
	return out
}

// eventHitsKey reports whether a usage event is attributed to keyID.
func (s *Service) eventHitsKey(ev usage.Event, keyID string) bool {
	for _, id := range s.KeysForEvent(ev) {
		if id == keyID {
			return true
		}
	}
	return false
}

// localProjectForPath finds the local project whose folder is the longest prefix
// of path (so a secrets file inside the project attributes to it).
func (s *Service) localProjectForPath(path string) *model.Project {
	want := normPath(path)
	var best *model.Project
	bestLen := -1
	for _, p := range s.store.Projects.List() {
		dir := s.localProjectPath(p)
		if dir == "" {
			continue
		}
		nd := normPath(dir)
		if pathWithin(want, nd) && len(nd) > bestLen {
			best = p
			bestLen = len(nd)
		}
	}
	return best
}

// normPath normalizes a path for prefix comparison (clean + forward slashes).
// Case is preserved; on Windows callers report real paths so this is adequate.
func normPath(p string) string {
	return filepath.ToSlash(filepath.Clean(p))
}

// pathWithin reports whether child is equal to or inside dir (both normalized).
func pathWithin(child, dir string) bool {
	if child == dir {
		return true
	}
	return strings.HasPrefix(child, dir+"/")
}
