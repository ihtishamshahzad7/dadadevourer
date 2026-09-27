@echo off
setlocal
cd /d "%~dp0..\.."
echo Checking DadaDevourer frontend build...
cd desktop
call npm run build
if errorlevel 1 (echo Build failed. Nothing was pushed.& exit /b 1)
cd ..
git add .
git status
set "MSG=%~1"
if "%MSG%"=="" set "MSG=chore: update DadaDevourer"
git commit -m "%MSG%"
if errorlevel 1 (echo Commit failed. Nothing was pushed.& exit /b 1)
git push origin main
if errorlevel 1 (echo Push failed.& exit /b 1)
echo Latest tested changes pushed to origin/main.
endlocal
