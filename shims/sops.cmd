@echo off
REM SopsHQ usage-shim launcher (Windows). Lets a bare "sops" command resolve to the
REM PowerShell wrapper: place this on PATH EARLIER than the real sops.exe. It runs
REM sops-wrapper.ps1 (sitting next to it) with all arguments and returns its exit
REM code. SopsHQ's panel can install/remove this for you (Usage page).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sops-wrapper.ps1" %*
exit /b %ERRORLEVEL%
