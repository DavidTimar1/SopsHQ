package web

import (
	"net/url"
	"strings"
	"testing"
)

// TestSaveBackupConfigPersists confirms /backup/config writes the schedule and
// filename fields onto this machine's record, and that a malformed DailyAt is
// rejected without disturbing the stored values.
func TestSaveBackupConfigPersists(t *testing.T) {
	ts, srv, _ := backupTestServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")
	csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/settings"), "csrf")

	resp, err := c.PostForm(ts.URL+"/backup/config", url.Values{
		"csrf": {csrf}, "enabled": {"1"}, "daily_at": {"04:15"},
		"base_name": {"my-backup"}, "date_format": {"2006-01-02"}, "date_position": {"prefix"},
	})
	if err != nil {
		t.Fatalf("post config: %v", err)
	}
	resp.Body.Close()

	b := srv.store.BackupSettingsFor(srv.keys.LocalMachine())
	if !b.Enabled || b.DailyAt != "04:15" || b.BaseName != "my-backup" ||
		b.DateFormat != "2006-01-02" || b.DatePosition != "prefix" {
		t.Fatalf("backup config not persisted: %+v", b)
	}

	// A bad DailyAt is rejected before anything is written; the prior values stay.
	resp, err = c.PostForm(ts.URL+"/backup/config", url.Values{
		"csrf": {csrf}, "daily_at": {"99:99"}, "base_name": {"changed"},
	})
	if err != nil {
		t.Fatalf("post bad daily_at: %v", err)
	}
	resp.Body.Close()
	b = srv.store.BackupSettingsFor(srv.keys.LocalMachine())
	if b.DailyAt != "04:15" || b.BaseName != "my-backup" || !b.Enabled {
		t.Fatalf("a bad daily_at should have been rejected, got %+v", b)
	}
}

// TestAddBackupDestinationSealsCredential confirms adding an FTP or Telegram
// destination seals the credential into the record (never the plaintext) and that
// the plaintext never reaches the rendered Settings page.
func TestAddBackupDestinationSealsCredential(t *testing.T) {
	ts, srv, _ := backupTestServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")
	csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/settings"), "csrf")

	const ftpPass = "ftp-secret-xyz"
	resp, err := c.PostForm(ts.URL+"/backup/destinations/add", url.Values{
		"csrf": {csrf}, "type": {"ftp"}, "host": {"ftp.example.com"},
		"ftp_user": {"alice"}, "ftp_secret": {ftpPass}, "path": {"/backups"}, "ftps": {"1"},
	})
	if err != nil {
		t.Fatalf("add ftp: %v", err)
	}
	resp.Body.Close()

	const botToken = "telegram-token-abc"
	resp, err = c.PostForm(ts.URL+"/backup/destinations/add", url.Values{
		"csrf": {csrf}, "type": {"telegram"}, "chat_id": {"12345"}, "bot_token": {botToken},
	})
	if err != nil {
		t.Fatalf("add telegram: %v", err)
	}
	resp.Body.Close()

	b := srv.store.BackupSettingsFor(srv.keys.LocalMachine())
	if len(b.Destinations) != 2 {
		t.Fatalf("expected 2 destinations, got %d", len(b.Destinations))
	}

	ftp := b.Destinations[0]
	if ftp.Type != "ftp" || ftp.Host != "ftp.example.com" || ftp.User != "alice" || !ftp.FTPS {
		t.Fatalf("ftp destination fields wrong: %+v", ftp)
	}
	if ftp.PasswordSealed == "" || ftp.PasswordSealed == ftpPass {
		t.Fatal("ftp password was not sealed")
	}
	if got, err := srv.vault.Open(ftp.PasswordSealed); err != nil || string(got) != ftpPass {
		t.Fatalf("sealed ftp password did not round-trip: %v", err)
	}

	tg := b.Destinations[1]
	if tg.Type != "telegram" || tg.ChatID != "12345" {
		t.Fatalf("telegram destination fields wrong: %+v", tg)
	}
	if tg.BotTokenSealed == "" || tg.BotTokenSealed == botToken {
		t.Fatal("telegram bot token was not sealed")
	}
	if got, err := srv.vault.Open(tg.BotTokenSealed); err != nil || string(got) != botToken {
		t.Fatalf("sealed bot token did not round-trip: %v", err)
	}

	// Neither plaintext credential appears on the rendered Settings page.
	body := getBody(t, c, ts.URL+"/settings")
	if strings.Contains(body, ftpPass) || strings.Contains(body, botToken) {
		t.Fatal("the Settings page leaked a destination credential")
	}
}

// TestRemoveBackupDestination confirms removing by slice index drops exactly that
// destination and keeps the rest.
func TestRemoveBackupDestination(t *testing.T) {
	ts, srv, _ := backupTestServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")
	csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/settings"), "csrf")

	for _, folder := range []string{"/data/a", "/data/b"} {
		resp, err := c.PostForm(ts.URL+"/backup/destinations/add", url.Values{
			"csrf": {csrf}, "type": {"local"}, "folder": {folder},
		})
		if err != nil {
			t.Fatalf("add local %s: %v", folder, err)
		}
		resp.Body.Close()
	}
	if n := len(srv.store.BackupSettingsFor(srv.keys.LocalMachine()).Destinations); n != 2 {
		t.Fatalf("expected 2 destinations, got %d", n)
	}

	resp, err := c.PostForm(ts.URL+"/backup/destinations/remove", url.Values{
		"csrf": {csrf}, "index": {"0"},
	})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	resp.Body.Close()

	dests := srv.store.BackupSettingsFor(srv.keys.LocalMachine()).Destinations
	if len(dests) != 1 || dests[0].Folder != "/data/b" {
		t.Fatalf("remove by index failed: %+v", dests)
	}
}

// TestBackupConfigRoutesRequireCSRF confirms a missing or forged CSRF token leaves
// the mutating backup-config routes inert.
func TestBackupConfigRoutesRequireCSRF(t *testing.T) {
	ts, srv, _ := backupTestServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	cases := []struct {
		path string
		form url.Values
	}{
		{"/backup/config", url.Values{"enabled": {"1"}, "daily_at": {"05:00"}}},
		{"/backup/destinations/add", url.Values{"type": {"local"}, "folder": {"/x"}}},
		{"/backup/destinations/remove", url.Values{"index": {"0"}}},
	}
	for _, tc := range cases {
		// Missing token.
		resp, err := c.PostForm(ts.URL+tc.path, tc.form)
		if err != nil {
			t.Fatalf("post %s (no csrf): %v", tc.path, err)
		}
		resp.Body.Close()
		forged := url.Values{}
		for k, v := range tc.form {
			forged[k] = v
		}
		forged.Set("csrf", "bogus")
		resp, err = c.PostForm(ts.URL+tc.path, forged)
		if err != nil {
			t.Fatalf("post %s (forged csrf): %v", tc.path, err)
		}
		resp.Body.Close()
	}

	b := srv.store.BackupSettingsFor(srv.keys.LocalMachine())
	if b.Enabled || len(b.Destinations) != 0 {
		t.Fatalf("a CSRF-less or forged POST mutated the backup settings: %+v", b)
	}
}
