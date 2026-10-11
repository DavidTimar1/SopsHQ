package permmap

import (
	"sort"
	"strings"
)

// AttrChange is one attribute of one path that differs between the baseline and
// the latest scan: the field name and its before/after values, both as display
// strings.
type AttrChange struct {
	Field  string `json:"field"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// PathChange is a path present in both scans whose attributes changed.
type PathChange struct {
	Path  string       `json:"path"`
	Attrs []AttrChange `json:"attrs"`
}

// Diff is the result of comparing a baseline scan to a later one: paths that
// appeared, paths that disappeared, and paths whose attributes changed.
type Diff struct {
	Added   []Entry      `json:"added"`
	Removed []Entry      `json:"removed"`
	Changed []PathChange `json:"changed"`
}

// Empty reports whether the diff found no changes at all.
func (d Diff) Empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}

// Total is the number of changed paths across all three categories.
func (d Diff) Total() int { return len(d.Added) + len(d.Removed) + len(d.Changed) }

// Compare diffs a baseline scan against a later scan, both keyed by path. A path
// only in the later scan is Added; only in the baseline is Removed; in both with
// any differing security-relevant attribute is Changed (with the specific
// before->after of each attribute that moved). Results are sorted by path for a
// stable digest.
func Compare(baseline, latest []Entry) Diff {
	base := index(baseline)
	cur := index(latest)
	var d Diff
	for path, after := range cur {
		before, ok := base[path]
		if !ok {
			d.Added = append(d.Added, after)
			continue
		}
		if attrs := attrChanges(before, after); len(attrs) > 0 {
			d.Changed = append(d.Changed, PathChange{Path: path, Attrs: attrs})
		}
	}
	for path, before := range base {
		if _, ok := cur[path]; !ok {
			d.Removed = append(d.Removed, before)
		}
	}
	sort.Slice(d.Added, func(i, j int) bool { return d.Added[i].Path < d.Added[j].Path })
	sort.Slice(d.Removed, func(i, j int) bool { return d.Removed[i].Path < d.Removed[j].Path })
	sort.Slice(d.Changed, func(i, j int) bool { return d.Changed[i].Path < d.Changed[j].Path })
	return d
}

// index builds a path->Entry map from a slice of entries.
func index(entries []Entry) map[string]Entry {
	m := make(map[string]Entry, len(entries))
	for _, e := range entries {
		m[e.Path] = e
	}
	return m
}

// attrChanges returns the security-relevant attributes that differ between two
// entries for the same path, each as a before->after pair. ACL lists are joined
// for a compact, comparable display string.
func attrChanges(before, after Entry) []AttrChange {
	var out []AttrChange
	add := func(field, b, a string) {
		if b != a {
			out = append(out, AttrChange{Field: field, Before: b, After: a})
		}
	}
	add("owner", before.Owner, after.Owner)
	add("group", before.Group, after.Group)
	add("mode", before.Mode, after.Mode)
	add("acl", strings.Join(before.ACL, ","), strings.Join(after.ACL, ","))
	add("default_acl", strings.Join(before.DefaultACL, ","), strings.Join(after.DefaultACL, ","))
	add("caps", before.Caps, after.Caps)
	add("world_writable", yesno(before.WorldWritable), yesno(after.WorldWritable))
	add("dangerous", yesno(before.Dangerous), yesno(after.Dangerous))
	return out
}

// yesno renders a bool as a short, stable display token for the diff.
func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
