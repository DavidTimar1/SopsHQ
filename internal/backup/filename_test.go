package backup

import (
	"strconv"
	"testing"
	"time"
)

func TestBuildFilename(t *testing.T) {
	// A fixed instant keeps the expected names deterministic.
	when := time.Date(2026, 6, 28, 23, 15, 9, 0, time.UTC)
	unix := strconv.FormatInt(when.Unix(), 10)

	tests := []struct {
		name     string
		base     string
		format   string
		position string
		want     string
	}{
		{"suffix datetime", "sopshq-backup", "20060102-150405", "suffix", "sopshq-backup-20260628-231509.bk"},
		{"prefix datetime", "sopshq-backup", "20060102-150405", "prefix", "20260628-231509-sopshq-backup.bk"},
		{"underscore layout", "db", "2006-01-02_15-04-05", "suffix", "db-2026-06-28_23-15-09.bk"},
		{"date only", "db", "20060102", "suffix", "db-20260628.bk"},
		{"dashed date only", "db", "2006-01-02", "prefix", "2026-06-28-db.bk"},
		{"unix epoch", "db", "unix", "suffix", "db-" + unix + ".bk"},
		{"unknown format falls back to first preset", "db", "bogus", "suffix", "db-20260628-231509.bk"},
		{"empty format falls back to first preset", "db", "", "suffix", "db-20260628-231509.bk"},
		{"empty base falls back to default", "", "20060102", "suffix", "sopshq-backup-20260628.bk"},
		{"unknown position is treated as suffix", "db", "20060102", "elsewhere", "db-20260628.bk"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildFilename(tt.base, tt.format, tt.position, when)
			if got != tt.want {
				t.Fatalf("BuildFilename(%q,%q,%q) = %q, want %q", tt.base, tt.format, tt.position, got, tt.want)
			}
		})
	}
}
