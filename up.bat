@echo off
REM One command for Windows: build (if Go), run proxy, open a playit.gg TCP tunnel.
REM make up is for Linux; on Windows run this: up.bat
REM playit.gg: free, no credit card, stable address. First run needs a one-time
REM web setup (claim account + create a TCP tunnel to 127.0.0.1:PORT).
setlocal enabledelayedexpansion
cd /d "%~dp0"

REM --- .env ---
if not exist ".env" (
  copy ".env.example" ".env" >nul
  echo Da tao .env tu .env.example. Mo dien PROXY_AUTH roi chay lai.
  notepad .env
  exit /b 1
)

REM --- port tu .env ---
set "HTTP_ADDR=:8080"
for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
  set "k=%%A"
  if not "!k:~0,1!"=="#" if /i "%%A"=="HTTP_ADDR" set "HTTP_ADDR=%%B"
)
for /f "tokens=2 delims=:" %%P in ("!HTTP_ADDR!") do set "PORT=%%P"
if "!PORT!"=="" set "PORT=8080"

REM --- build + chay proxy ---
where go >nul 2>nul && ( echo Building proxy.exe... & go build -o proxy.exe . )
if not exist "proxy.exe" (
  echo Khong co proxy.exe va may khong co Go. Dua proxy.exe build san vao thu muc nay.
  exit /b 1
)
echo Starting proxy on port !PORT!...
start "vps-proxy" /min proxy.exe

REM --- playit: tu tai neu chua co ---
if not exist "playit.exe" (
  echo Tai playit...
  curl -sL -o playit.exe https://github.com/playit-cloud/playit-agent/releases/latest/download/playit-windows-x86_64-signed.exe
)
if not exist "playit.exe" (
  echo Tai playit that bai, tai tay o https://playit.gg/download
  exit /b 1
)

echo.
echo === LAN DAU DUNG PLAYIT ===
echo 1. playit se in mot link - mo bang trinh duyet, dang nhap/tao tai khoan free.
echo 2. Trong trang playit, tao 1 tunnel loai TCP tro toi  127.0.0.1:!PORT!
echo 3. playit cho dia chi co dinh:  ^<ten^>.gl.at.ply.gg:^<PORT^>
echo 4. AutoPro proxy:  http:^<dia-chi-playit^>:^<PORT^>:user:pass
echo.
playit.exe
