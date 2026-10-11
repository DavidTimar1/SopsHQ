package web

import (
	"embed"
	"html/template"
	"strings"
	"time"
)

//go:embed templates/layout.html templates/pages/*.html
var tmplFS embed.FS

//go:embed static
var staticFS embed.FS

// funcs are template helpers available in every page.
var funcs = template.FuncMap{
	// fmtTime renders a Unix-seconds timestamp in a readable local form, or a
	// dash for the zero value.
	"fmtTime": func(sec int64) string {
		if sec == 0 {
			return "-"
		}
		return time.Unix(sec, 0).Format("2006-01-02 15:04")
	},
	// join concatenates a string slice with sep (used to emit a view's ordered
	// group-by keys as a data attribute).
	"join": strings.Join,
}
