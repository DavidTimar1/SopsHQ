//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// startupDir returns the current user's Startup folder
// (%AppData%\Microsoft\Windows\Start Menu\Programs\Startup): anything placed here runs
// automatically at every logon for this Windows account, with no admin/UAC needed - it
// lives entirely inside the user's own profile. os.UserConfigDir() resolves %AppData%.
func startupDir() (string, error) {
	appData, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve %%AppData%%: %w", err)
	}
	return filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"), nil
}

// installLauncherScript writes the Startup-folder launcher script (buildLauncherScript)
// for bin/configPath, creating the Startup folder if needed, and returns the path it
// wrote. Re-running it overwrites the same file (a fixed name), so it converges instead
// of accumulating stale copies.
func installLauncherScript(bin, configPath string) (string, error) {
	dir, err := startupDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create Startup folder %s: %w", dir, err)
	}
	scriptPath := filepath.Join(dir, launcherScriptName)
	content := buildLauncherScript(bin, configPath)
	tmp := scriptPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, scriptPath); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("place %s: %w", scriptPath, err)
	}
	return scriptPath, nil
}

// uninstallLauncherScript removes the Startup-folder launcher script, if present. It
// reports the path it checked and whether a file was actually removed there - a missing
// file is not an error (nothing to do).
func uninstallLauncherScript() (scriptPath string, removed bool, err error) {
	dir, err := startupDir()
	if err != nil {
		return "", false, err
	}
	scriptPath = filepath.Join(dir, launcherScriptName)
	if _, statErr := os.Stat(scriptPath); statErr != nil {
		if os.IsNotExist(statErr) {
			return scriptPath, false, nil
		}
		return scriptPath, false, fmt.Errorf("stat %s: %w", scriptPath, statErr)
	}
	if err := os.Remove(scriptPath); err != nil {
		return scriptPath, false, fmt.Errorf("remove %s: %w", scriptPath, err)
	}
	return scriptPath, true, nil
}
