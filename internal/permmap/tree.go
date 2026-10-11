package permmap

import (
	"path"
	"sort"
)

// Node is one entry in the lazy folder tree: a path with its display name, its
// type, whether it can be expanded (a directory with at least one child), and the
// security flags so the tree can mark dangerous or ACL'd paths inline.
type Node struct {
	Path          string `json:"path"`
	Name          string `json:"name"` // last path element, for display
	Type          string `json:"type"`
	IsDir         bool   `json:"is_dir"`
	HasChildren   bool   `json:"has_children"`
	Owner         string `json:"owner"`
	Group         string `json:"group"`
	Mode          string `json:"mode"`
	WorldWritable bool   `json:"world_writable"`
	HasACL        bool   `json:"has_acl"`
	ACLOverride   bool   `json:"acl_override"`
	Dangerous     bool   `json:"dangerous"`
}

// Children returns the immediate children of parent within the scan, as tree
// nodes sorted directories-first then by name. A path P is an immediate child of
// parent when path.Dir(P) == parent. This backs lazy tree expansion: the page
// asks for one directory's children at a time, so the payload stays bounded even
// for a whole-server scan. HasChildren is set when a directory itself has at
// least one immediate child, so the UI can show an expand affordance only where
// expanding will yield something.
func Children(entries []Entry, parent string) []Node {
	parent = path.Clean(parent)
	// Index direct-child counts so HasChildren is correct without an O(n^2) rescan.
	childCount := make(map[string]int, len(entries))
	for _, e := range entries {
		childCount[path.Dir(e.Path)]++
	}
	var out []Node
	for _, e := range entries {
		if path.Dir(e.Path) != parent {
			continue
		}
		isDir := e.Type == "d"
		out = append(out, Node{
			Path:          e.Path,
			Name:          path.Base(e.Path),
			Type:          e.Type,
			IsDir:         isDir,
			HasChildren:   isDir && childCount[e.Path] > 0,
			Owner:         e.Owner,
			Group:         e.Group,
			Mode:          e.Mode,
			WorldWritable: e.WorldWritable,
			HasACL:        e.HasACL,
			ACLOverride:   e.ACLOverride,
			Dangerous:     e.Dangerous,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir // directories first
		}
		return out[i].Name < out[j].Name
	})
	return out
}
