@echo off
cd /d "%~dp0"
where node >nul 2>nul || (echo Node.js is not installed. Install it from https://nodejs.org and run this again. & pause & exit /b 1)
if exist .env goto run
echo First-time setup: create your admin login.
set /p AU=Admin username: 
set /p AP=Admin password: 
> .env echo PORT=3000
>> .env echo ADMIN_USERNAME=%AU%
>> .env echo ADMIN_PASSWORD=%AP%
>> .env echo COOKIE_SECURE=false
>> .env echo TRUST_PROXY=false
:run
start "" http://localhost:3000
node --env-file-if-exists=.env server.js
pause
