package permmap

import "strings"

// Filter names one of the four ACL-aware queries (plus a couple of close
// relatives) the operator can run over a scan. The empty filter ("" / FilterAll)
// matches every entry.
type Filter string

const (
	FilterAll           Filter = ""               // every entry
	FilterWorldWritable Filter = "world_writable" // "other" has write
	FilterDangerous     Filter = "dangerous"      // world-writable (non-sticky-dir) or suid/sgid
	FilterHasACL        Filter = "has_acl"        // any named ACL principal
	FilterACLOverride   Filter = "acl_override"   // a named principal beyond owner/owning-group
	FilterSuidSgid      Filter = "suid_sgid"      // setuid or setgid
)

// match reports whether one entry passes the named flag filter.
func (f Filter) match(e Entry) bool {
	switch f {
	case FilterWorldWritable:
		return e.WorldWritable
	case FilterDangerous:
		return e.Dangerous
	case FilterHasACL:
		return e.HasACL
	case FilterACLOverride:
		return e.ACLOverride
	case FilterSuidSgid:
		return e.SuidSgid
	default:
		return true
	}
}

// searchMatch reports whether an entry matches the free-text query. The query is
// matched case-insensitively against the path, owner, group, and ACL entries, so
// the operator can find a path, a named user/group, or a specific ACL grant.
func searchMatch(e Entry, q string) bool {
	if q == "" {
		return true
	}
	q = strings.ToLower(q)
	if strings.Contains(strings.ToLower(e.Path), q) ||
		strings.Contains(strings.ToLower(e.Owner), q) ||
		strings.Contains(strings.ToLower(e.Group), q) {
		return true
	}
	for _, a := range e.ACL {
		if strings.Contains(strings.ToLower(a), q) {
			return true
		}
	}
	for _, a := range e.DefaultACL {
		if strings.Contains(strings.ToLower(a), q) {
			return true
		}
	}
	return false
}

// Query applies a flag filter and a free-text search to a scan and returns up to
// limit matching entries together with the total number that matched. A limit of
// 0 or less returns all matches. Returning total separately lets the caller tell
// the operator "showing N of M" instead of silently truncating.
func Query(entries []Entry, f Filter, search string, limit int) (matches []Entry, total int) {
	for _, e := range entries {
		if !f.match(e) || !searchMatch(e, search) {
			continue
		}
		total++
		if limit <= 0 || len(matches) < limit {
			matches = append(matches, e)
		}
	}
	return matches, total
}

// Counts summarizes a scan: the totals behind the quick-filter buttons so the
// page can show how many entries each query would return without running them.
type Counts struct {
	Total         int `json:"total"`
	WorldWritable int `json:"world_writable"`
	Dangerous     int `json:"dangerous"`
	HasACL        int `json:"has_acl"`
	ACLOverride   int `json:"acl_override"`
	SuidSgid      int `json:"suid_sgid"`
}

// Summarize counts the entries matching each flag filter in a single pass.
func Summarize(entries []Entry) Counts {
	var c Counts
	c.Total = len(entries)
	for _, e := range entries {
		if e.WorldWritable {
			c.WorldWritable++
		}
		if e.Dangerous {
			c.Dangerous++
		}
		if e.HasACL {
			c.HasACL++
		}
		if e.ACLOverride {
			c.ACLOverride++
		}
		if e.SuidSgid {
			c.SuidSgid++
		}
	}
	return c
}
