@echo off
setlocal
set "REPO=ihtishamshahzad7/dadadevourer"
set "TMP=%TEMP%\DadaDevourer"
if not exist "%TMP%" mkdir "%TMP%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$r=Invoke-RestMethod 'https://api.github.com/repos/%REPO%/releases/latest'; $a=$r.assets | Where-Object { $_.name -match '\\.exe$' -and $_.name -match 'setup|nsis|x64' } | Select-Object -First 1; if(-not $a){throw 'No Windows installer was found in the latest release.'}; Write-Host ('Downloading '+$a.name); Invoke-WebRequest -Uri $a.browser_download_url -OutFile '%TMP%\DadaDevourer-Setup.exe'"
if errorlevel 1 (echo Download failed.& exit /b 1)
echo Starting DadaDevourer installer...
start /wait "" "%TMP%\DadaDevourer-Setup.exe"
if errorlevel 1 (echo Installer failed.& exit /b 1)
echo DadaDevourer installation/update completed.
endlocal
