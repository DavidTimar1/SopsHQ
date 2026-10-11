package backup

import (
	"strconv"
	"time"
)

// fileExt is the extension every backup archive carries.
const fileExt = ".bk"

// DateFormats lists the datetime presets a backup filename may use, in UI order.
// Each entry is a Go reference layout that time.Format understands, except the
// special value "unix", which means epoch seconds.
var DateFormats = []string{
	"20060102-150405",
	"2006-01-02_15-04-05",
	"20060102",
	"2006-01-02",
	"unix",
}

// BuildFilename composes a backup archive name from base, a datetime stamp
// formatted per format at time t, placed as position ("prefix" or "suffix") of
// base, joined with "-", plus the ".bk" extension. format is one of DateFormats
// ("unix" yields epoch seconds); an empty or unknown format falls back to the
// first preset, and an empty base falls back to "sopshq-backup". t is taken as a
// parameter (callers pass time.Now()) so the result is deterministic.
func BuildFilename(base, format, position string, t time.Time) string {
	if base == "" {
		base = "sopshq-backup"
	}
	stamp := formatStamp(format, t)
	name := base + "-" + stamp
	if position == "prefix" {
		name = stamp + "-" + base
	}
	return name + fileExt
}

// formatStamp renders t per format, treating "unix" specially and falling back to
// the first preset for an empty or unknown layout.
func formatStamp(format string, t time.Time) string {
	if format == "unix" {
		return strconv.FormatInt(t.Unix(), 10)
	}
	if !knownLayout(format) {
		format = DateFormats[0]
	}
	return t.Format(format)
}

// knownLayout reports whether format is one of the supported presets.
func knownLayout(format string) bool {
	for _, f := range DateFormats {
		if f == format {
			return true
		}
	}
	return false
}
