package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sopshq/internal/audit"
	"sopshq/internal/auth"
	"sopshq/internal/backup"
	"sopshq/internal/model"
)

// lastBackupState is the most recent self-backup run, shown on the dashboard. It
// holds only non-secret status: when it ran, a destination-by-name summary, and
// whether it succeeded. It never holds the password, a credential, or archive bytes.
type lastBackupState struct {
	When    int64 // Unix seconds; 0 means "no run this session"
	Summary string
	OK      bool
}

// backupView is the Settings page "Backups" panel data. It exposes the editable
// configuration by NAME only (no credential, no password) and the last run's
// status, so the template can render the schedule, filename, and destination
// controls with the stored values pre-selected.
type backupView struct {
	Available    bool   // a backup runner is wired (serve, not a bare test server)
	Enabled      bool   // the daily schedule is on
	DailyAt      string // local "HH:MM"
	BaseName     string // archive filename stem
	DateFormat   string // the selected datetime preset (a Go layout, or "unix")
	DatePosition string // "prefix" or "suffix"
	PasswordSet  bool   // a backup password has been sealed into the record (never the value)

	// DateFormats are the preset options for the filename dropdown, each marked
	// Selected if it is the stored choice.
	DateFormats  []dateFormatOption
	Destinations []backupDestRow

	LastWhen    int64
	LastSummary string
	LastOK      bool
	HasLast     bool
}

// dateFormatOption is one entry of the datetime-format dropdown: the Go layout
// (or "unix"), a rendered example, and whether it is the current selection.
type dateFormatOption struct {
	Layout   string
	Example  string
	Selected bool
}

// backupDestRow is one destination as shown in the UI: its slice Index (for
// removal), its Type, and a credential-free Label. It never carries a credential.
type backupDestRow struct {
	Index int
	Type  string
	Label string
}

// backupViewData assembles the backup panel from this machine's stored backup
// settings plus the last-run state. It exposes only non-secret fields; the backup
// password and every destination credential stay sealed and are never copied here.
func (s *Server) backupViewData() backupView {
	b := s.store.BackupSettingsFor(s.keys.LocalMachine())
	now := time.Now()
	v := backupView{
		Available:    s.backupRun != nil,
		Enabled:      b.Enabled,
		DailyAt:      b.DailyAt,
		BaseName:     b.BaseName,
		DateFormat:   b.DateFormat,
		DatePosition: b.DatePosition,
		PasswordSet:  b.PasswordSealed != "",
		Destinations: backupDestRows(b.Destinations, s.cfg.DataDir),
	}
	for _, f := range backup.DateFormats {
		v.DateFormats = append(v.DateFormats, dateFormatOption{
			Layout:   f,
			Example:  dateFormatExample(f, now),
			Selected: f == b.DateFormat,
		})
	}
	s.lastBackupMu.Lock()
	last := s.lastBackup
	s.lastBackupMu.Unlock()
	if last.When != 0 {
		v.HasLast = true
		v.LastWhen = last.When
		v.LastSummary = last.Summary
		v.LastOK = last.OK
	}
	return v
}

// backupDestRows pairs each destination with its slice index and a credential-free
// label so the template can list them and offer a remove button by index.
func backupDestRows(dests []model.BackupDest, dataDir string) []backupDestRow {
	labels := backupDestNames(dests, dataDir)
	rows := make([]backupDestRow, len(dests))
	for i, d := range dests {
		rows[i] = backupDestRow{Index: i, Type: d.Type, Label: labels[i]}
	}
	return rows
}

// dateFormatExample renders one preset at time t for display next to its layout.
// "unix" yields epoch seconds; any other value is a Go reference layout.
func dateFormatExample(format string, t time.Time) string {
	if format == "unix" {
		return strconv.FormatInt(t.Unix(), 10)
	}
	return t.Format(format)
}

// backupDestNames lists each destination by a human, credential-free label.
func backupDestNames(dests []model.BackupDest, dataDir string) []string {
	var out []string
	for _, d := range dests {
		switch d.Type {
		case "local":
			folder := d.Folder
			if folder == "" {
				folder = dataDir
			}
			out = append(out, "local: "+folder)
		case "ftp":
			scheme := "ftp"
			if d.FTPS {
				scheme = "ftps"
			}
			out = append(out, scheme+": "+d.Host)
		case "telegram":
			out = append(out, "telegram: chat "+d.ChatID)
		default:
			out = append(out, d.Type)
		}
	}
	return out
}

// backupNow runs one self-backup on demand and stores the outcome for the
// dashboard. Admin-only and CSRF-checked. The runner unseals the backup password
// internally; nothing secret is logged, returned to the page, or stored here.
func (s *Server) backupNow(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/settings") {
		return
	}
	if s.backupRun == nil {
		redirect(w, r, "/settings", "Backups are not available in this process.", true)
		return
	}
	summary, err := s.backupRun()
	now := time.Now().Unix()
	if err != nil {
		s.lastBackupMu.Lock()
		s.lastBackup = lastBackupState{When: now, Summary: err.Error(), OK: false}
		s.lastBackupMu.Unlock()
		s.audit.Record(sess.Username, "backup_now", "panel", audit.Failed, "")
		redirect(w, r, "/settings", "Backup failed: "+err.Error(), true)
		return
	}
	s.lastBackupMu.Lock()
	s.lastBackup = lastBackupState{When: now, Summary: summary, OK: true}
	s.lastBackupMu.Unlock()
	s.audit.Record(sess.Username, "backup_now", "panel", audit.OK, "")
	redirect(w, r, "/settings", "Backup complete: "+summary, false)
}

// setBackupPassword seals the operator-chosen backup password into this machine's
// backup-settings record. Admin-only and CSRF-checked. The plaintext is sealed
// with the vault and the sealed (ciphertext) blob is persisted; the plaintext is
// never logged, echoed, returned, or stored. The flash reminds the operator to
// ALSO save the password in their password manager, because restore needs it and
// it is not recoverable from the backup itself.
func (s *Server) setBackupPassword(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/settings") {
		return
	}
	password := r.FormValue("backup_secret")
	if len(password) < 8 {
		redirect(w, r, "/settings", "The backup password must be at least 8 characters.", true)
		return
	}
	sealed, err := s.vault.Seal([]byte(password))
	if err != nil {
		s.renderError(w, r, sess, "Vault is locked; cannot seal the backup password.", http.StatusInternalServerError)
		return
	}
	b := s.store.BackupSettingsFor(s.keys.LocalMachine())
	b.PasswordSealed = sealed
	if err := s.store.BackupSettingsColl.Put(b); err != nil {
		s.renderError(w, r, sess, "Could not save the backup settings.", http.StatusInternalServerError)
		return
	}
	s.audit.Record(sess.Username, "backup_password_set", "backup_settings", audit.OK, "")
	redirect(w, r, "/settings", "Backup password set. Also save it in your password manager - "+
		"it is required to restore and is never recoverable from the backup itself.", false)
}

// saveBackupConfig stores this machine's schedule and filename pattern (Enabled,
// DailyAt, BaseName, DateFormat, DatePosition). Admin-only and CSRF-checked. A bad
// DailyAt is rejected with a flash; BaseName, DateFormat, and DatePosition fall
// back to their defaults when blank or out of range. The audit row records a
// non-secret change summary only.
func (s *Server) saveBackupConfig(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/settings") {
		return
	}
	dailyAt := strings.TrimSpace(r.FormValue("daily_at"))
	if !validDailyAt(dailyAt) {
		redirect(w, r, "/settings", "Daily time must be HH:MM, 24-hour (for example 03:30).", true)
		return
	}
	baseName := strings.TrimSpace(r.FormValue("base_name"))
	if baseName == "" {
		baseName = model.DefaultBackupBaseName
	}
	format := r.FormValue("date_format")
	if !knownDateFormat(format) {
		format = model.DefaultBackupDateFormat
	}
	position := r.FormValue("date_position")
	if position != "prefix" && position != "suffix" {
		position = model.DefaultBackupDatePosition
	}

	b := s.store.BackupSettingsFor(s.keys.LocalMachine())
	b.Enabled = r.FormValue("enabled") != ""
	b.DailyAt = dailyAt
	b.BaseName = baseName
	b.DateFormat = format
	b.DatePosition = position
	if err := s.store.BackupSettingsColl.Put(b); err != nil {
		s.renderError(w, r, sess, "Could not save the backup settings.", http.StatusInternalServerError)
		return
	}
	summary := fmt.Sprintf("enabled=%t at=%s name=%s format=%s pos=%s",
		b.Enabled, b.DailyAt, b.BaseName, b.DateFormat, b.DatePosition)
	s.audit.Record(sess.Username, "backup_config", "backup_settings", audit.OK, summary)
	redirect(w, r, "/settings", "Backup schedule and filename saved.", false)
}

// addBackupDestination appends a destination (local/ftp/telegram) to this
// machine's backup settings. Admin-only and CSRF-checked. The FTP password and the
// Telegram bot token are vault-SEALED before storage and never logged, echoed, or
// rendered; the audit row records the destination type only.
func (s *Server) addBackupDestination(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/settings") {
		return
	}
	typ := r.FormValue("type")
	dest := model.BackupDest{Type: typ}
	switch typ {
	case "local":
		dest.Folder = strings.TrimSpace(r.FormValue("folder"))
	case "ftp":
		host := strings.TrimSpace(r.FormValue("host"))
		user := strings.TrimSpace(r.FormValue("ftp_user"))
		if host == "" || user == "" {
			redirect(w, r, "/settings", "An FTP destination needs a host and a user.", true)
			return
		}
		dest.Host = host
		dest.User = user
		dest.Port, _ = strconv.Atoi(strings.TrimSpace(r.FormValue("port")))
		dest.Path = strings.TrimSpace(r.FormValue("path"))
		dest.FTPS = r.FormValue("ftps") != ""
		if pw := r.FormValue("ftp_secret"); pw != "" {
			sealed, err := s.vault.Seal([]byte(pw))
			if err != nil {
				s.renderError(w, r, sess, "Vault is locked; cannot seal the FTP password.", http.StatusInternalServerError)
				return
			}
			dest.PasswordSealed = sealed
		}
	case "telegram":
		chatID := strings.TrimSpace(r.FormValue("chat_id"))
		token := strings.TrimSpace(r.FormValue("bot_token"))
		if chatID == "" || token == "" {
			redirect(w, r, "/settings", "A Telegram destination needs a chat id and a bot token.", true)
			return
		}
		sealed, err := s.vault.Seal([]byte(token))
		if err != nil {
			s.renderError(w, r, sess, "Vault is locked; cannot seal the bot token.", http.StatusInternalServerError)
			return
		}
		dest.ChatID = chatID
		dest.BotTokenSealed = sealed
	default:
		redirect(w, r, "/settings", "Choose a destination type.", true)
		return
	}

	b := s.store.BackupSettingsFor(s.keys.LocalMachine())
	b.Destinations = append(b.Destinations, dest)
	if err := s.store.BackupSettingsColl.Put(b); err != nil {
		s.renderError(w, r, sess, "Could not save the backup settings.", http.StatusInternalServerError)
		return
	}
	s.audit.Record(sess.Username, "backup_dest_add", typ, audit.OK, "")
	redirect(w, r, "/settings", "Destination added.", false)
}

// removeBackupDestination drops the destination at the given slice index from this
// machine's backup settings. Admin-only and CSRF-checked. The audit row records the
// index only (never a credential).
func (s *Server) removeBackupDestination(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/settings") {
		return
	}
	idx, err := strconv.Atoi(r.FormValue("index"))
	b := s.store.BackupSettingsFor(s.keys.LocalMachine())
	if err != nil || idx < 0 || idx >= len(b.Destinations) {
		redirect(w, r, "/settings", "No such destination.", true)
		return
	}
	b.Destinations = append(b.Destinations[:idx], b.Destinations[idx+1:]...)
	if err := s.store.BackupSettingsColl.Put(b); err != nil {
		s.renderError(w, r, sess, "Could not save the backup settings.", http.StatusInternalServerError)
		return
	}
	s.audit.Record(sess.Username, "backup_dest_remove", strconv.Itoa(idx), audit.OK, "")
	redirect(w, r, "/settings", "Destination removed.", false)
}

// validDailyAt reports whether s is a valid 24-hour "HH:MM" time of day.
func validDailyAt(s string) bool {
	_, err := time.Parse("15:04", s)
	return err == nil
}

// knownDateFormat reports whether format is one of the supported filename presets.
func knownDateFormat(format string) bool {
	for _, f := range backup.DateFormats {
		if f == format {
			return true
		}
	}
	return false
}
