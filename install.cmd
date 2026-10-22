@echo off
rem Orvpass Windows Command Prompt Installer
echo =======================================================================
echo  ⚡ Installing Orvpass CLI for Windows Command Prompt & PowerShell
echo =======================================================================
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/krtvysinghhhh/Orvpass/main/install.ps1 | iex"
if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✨ Installation completed successfully.
    echo Please restart your Command Prompt or run 'refreshenv' to use orvpass.
) else (
    echo.
    echo ❌ Installation encountered an issue.
)
pause
