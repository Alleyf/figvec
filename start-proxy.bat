@echo off
rem ================================================================
rem  PDF Figure to SVG - Windows launcher for proxy.py
rem
rem  IMPORTANT: this batch file is intentionally pure ASCII, saved
rem  as UTF-8 without BOM with CRLF line endings. cmd.exe parses
rem  batch files using the OEM code page (936 on zh-CN systems), so
rem  a non-ASCII byte here would be decoded wrongly and split into
rem  bogus commands. All Chinese messages are printed by proxy.py
rem  AFTER chcp 65001, which avoids that whole class of problems.
rem ================================================================
chcp 65001 >nul
setlocal EnableExtensions
cd /d "%~dp0"
title PDF Figure to SVG - local CORS proxy

rem First argument (optional) overrides the upstream base URL.
rem Example: start-proxy.bat http://192.168.1.10:8000
set "UPSTREAM=%~1"
if not defined UPSTREAM set "UPSTREAM=http://10.17.121.224:3425"

rem ---- find a usable Python 3 interpreter (python / py -3 / python3) ----
python -c "import sys" >nul 2>nul
if errorlevel 1 goto :TRY_PY
set "PYEXE=python"
goto :RUN

:TRY_PY
py -3 -c "import sys" >nul 2>nul
if errorlevel 1 goto :TRY_PY3
set "PYEXE=py"
set "PYARG=-3"
goto :RUN

:TRY_PY3
python3 -c "import sys" >nul 2>nul
if errorlevel 1 goto :NO_PYTHON
set "PYEXE=python3"
goto :RUN

:NO_PYTHON
echo.
echo [ERROR] Python 3 not found.
echo Install Python 3.8 or newer from https://www.python.org/downloads/windows/
echo and tick "Add python.exe to PATH", then run this file again.
echo Manual start: py -3 proxy.py --upstream http://10.17.121.224:3425
echo.
rem Optional one-line Chinese hint. The text is carried as base64 so
rem that this batch file stays pure ASCII. Any failure is ignored.
powershell -NoProfile -Command "try{$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('5pyq5om+5YiwIFB5dGhvbiAz77ya6K+35YWI5a6J6KOFIFB5dGhvbiDlubbli77pgIkgQWRkIFB5dGhvbiB0byBQQVRI77yM5oiW5omL5Yqo6L+Q6KGMIHB5IC0zIHByb3h5LnB5'));[Console]::WriteLine($s)}catch{}" 2>nul
echo.
pause
exit /b 1

:RUN
rem Port selection, auto-shift and every Chinese message live in proxy.py.
rem This script only resolves the interpreter and forwards the upstream.
%PYEXE% %PYARG% proxy.py --host 127.0.0.1 --upstream "%UPSTREAM%"
set "RC=%ERRORLEVEL%"
if "%RC%"=="0" goto :END
echo.
echo [proxy exited with code %RC%]
echo.
pause

:END
endlocal
exit /b 0
