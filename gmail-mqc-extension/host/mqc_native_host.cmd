@echo off
REM mqc_native_host.cmd — launcher for mqc_native_host.py.
REM
REM Chrome's Native Messaging protocol requires an .exe/.bat/.cmd on
REM Windows (it can't invoke .py directly).  This wrapper finds
REM python on PATH and runs the host script next to this file with
REM stdin/stdout untouched.
REM
REM If python isn't on PATH, edit PYTHON= below to the absolute
REM py.exe path (typically C:\Windows\py.exe) or your venv's python.

setlocal

set PYTHON=python
where %PYTHON% >nul 2>&1 || set PYTHON=py -3
where %PYTHON:~0,2% >nul 2>&1 || (
  echo mqc-native-host: python not found on PATH >&2
  exit /b 2
)

%PYTHON% "%~dp0mqc_native_host.py" %*
