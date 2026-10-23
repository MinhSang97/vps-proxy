@echo off
REM One command for Windows: build (if Go), run proxy, open ngrok tunnel.
REM make up is for Linux; on Windows run this: up.bat
setlocal enabledelayedexpansion
cd /d "%~dp0"

REM --- .env ---
if not exist ".env" (
  copy ".env.example" ".env" >nul
  echo Da tao .env tu .env.example. Mo dien PROXY_AUTH va NGROK_TOKEN roi chay lai.
  notepad .env
  exit /b 1
)

REM --- doc NGROK_TOKEN va HTTP_ADDR tu .env ---
set "NGROK_TOKEN="
set "HTTP_ADDR=:8080"
for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
  set "k=%%A"
  if not "!k:~0,1!"=="#" (
    if /i "%%A"=="NGROK_TOKEN" set "NGROK_TOKEN=%%B"
    if /i "%%A"=="HTTP_ADDR" set "HTTP_ADDR=%%B"
  )
)
for /f "tokens=2 delims=:" %%P in ("!HTTP_ADDR!") do set "PORT=%%P"
if "!PORT!"=="" set "PORT=8080"

REM --- build proxy.exe neu co Go ---
where go >nul 2>nul && ( echo Building proxy.exe... & go build -o proxy.exe . )
if not exist "proxy.exe" (
  echo Khong co proxy.exe va may khong co Go. Dua proxy.exe build san vao thu muc nay.
  exit /b 1
)

REM --- chay proxy nen ---
echo Starting proxy on port !PORT!...
start "vps-proxy" /min proxy.exe

REM --- ngrok: tu tai neu chua co ---
set "NGROK="
where ngrok >nul 2>nul && set "NGROK=ngrok"
if exist "ngrok.exe" set "NGROK=ngrok.exe"
if "!NGROK!"=="" (
  echo Tai ngrok...
  curl -sL -o ngrok.zip https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-windows-amd64.zip
  tar -xf ngrok.zip ngrok.exe
  del ngrok.zip >nul 2>nul
  if exist "ngrok.exe" ( set "NGROK=ngrok.exe" ) else ( echo Tai ngrok that bai, tai tay o https://ngrok.com/download & exit /b 1 )
)
if not "!NGROK_TOKEN!"=="" %NGROK% config add-authtoken !NGROK_TOKEN! >nul 2>nul
echo.
echo => Proxy chay cong !PORT!. Dia chi ngrok o dong Forwarding ben duoi.
echo => May khac nhap proxy:  http:^<host^>:^<port^>:user:pass  (lay host:port o dong tcp://...)
echo.
%NGROK% tcp !PORT!
