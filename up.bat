@echo off
REM One command for Windows: build (if Go), run proxy, open a free TCP tunnel.
REM make up is for Linux; on Windows run this: up.bat
REM Tunnel is bore.pub: free, no account, no credit card, no setup.
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

REM --- bore: tu tai neu chua co (khong can the, khong can tai khoan, khong setup) ---
set "BORE="
where bore >nul 2>nul && set "BORE=bore"
if exist "bore.exe" set "BORE=bore.exe"
if "!BORE!"=="" (
  echo Tai bore...
  curl -sL -o bore.zip https://github.com/ekzhang/bore/releases/download/v0.6.0/bore-v0.6.0-x86_64-pc-windows-msvc.zip
  tar -xf bore.zip bore.exe
  del bore.zip >nul 2>nul
  if exist "bore.exe" ( set "BORE=bore.exe" ) else ( echo Tai bore that bai. & exit /b 1 )
)

echo.
echo => Proxy chay cong !PORT!. Dia chi cong khai o dong "listening at bore.pub:XXXXX" ben duoi.
echo => AutoPro proxy:  http:bore.pub:^<XXXXX^>:user:pass   (lay dung port o dong duoi)
echo.
%BORE% local !PORT! --to bore.pub
