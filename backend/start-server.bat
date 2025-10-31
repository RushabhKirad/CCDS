@echo off
echo Starting Cyber Defense Backend Server...
echo.
set PATH=%PATH%;C:\Program Files\nodejs;C:\Users\rusha\AppData\Roaming\npm
cd /d "%~dp0"
echo Installing dependencies...
npm install
echo.
echo Starting server...
node server.js
pause