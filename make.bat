@echo off
setlocal enableextensions enabledelayedexpansion

set PROJECT=carbide
set SRC=carbide.c
set INCLUDE_DIR=include
set HEADER=%INCLUDE_DIR%\Carbide\Recipe.h
set OUT=%PROJECT%.exe

set PREFIX=C:\Program Files\Carbide
set BINDIR=%PREFIX%\bin
set INCDIR=%PREFIX%\include\Carbide

set CACHE=.windows-compiler-path-cache

if /i "%~1"=="-h"  goto :usage
if /i "%~1"=="--help" goto :usage
if /i "%~1"=="help" goto :usage

:read_cache
if exist "%CACHE%" (
  for /f "usebackq tokens=1,* delims==" %%A in ("%CACHE%") do (
    set %%A=%%B
  )
  if defined TYPE if defined CC if exist "%CC%" (
    echo [*] Using cached compiler: TYPE=%TYPE%
    goto build
  )
)
goto discover

:write_cache
> "%CACHE%" (
  echo TYPE=%TYPE%
  echo CC=%CC%
  if defined ENV_BAT echo ENV_BAT=%ENV_BAT%
)
echo [*] Cached compiler to %CACHE%
goto build

:find_file
set "_root=%~1"
set "_name=%~2"
set "_out=%~3"
for /f "delims=" %%P in ('where /r "%_root%" %_name% 2^>nul') do (
  if not defined %_out% set %_out%=%%P
)
exit /b 0

:discover
echo [*] Discovering a C compiler...

where cl >nul 2>&1       && ( set TYPE=msvc     & for /f "delims=" %%p in ('where cl') do set CC=%%p    & goto cache )
where clang-cl >nul 2>&1 && ( set TYPE=clang-cl & for /f "delims=" %%p in ('where clang-cl') do set CC=%%p & goto cache )
where clang >nul 2>&1    && ( set TYPE=clang    & for /f "delims=" %%p in ('where clang') do set CC=%%p  & goto cache )
where gcc >nul 2>&1      && ( set TYPE=gcc      & for /f "delims=" %%p in ('where gcc') do set CC=%%p    & goto cache )

set VSX86=%ProgramFiles(x86)%\Microsoft Visual Studio
set VS64=%ProgramFiles%\Microsoft Visual Studio

call :find_file "%VSX86%" VsDevCmd.bat VSDEV
if not defined VSDEV call :find_file "%VS64%" VsDevCmd.bat VSDEV

if defined VSDEV (
  call :find_file "%VSX86%" cl.exe CLPATH
  if not defined CLPATH call :find_file "%VS64%" cl.exe CLPATH
  if defined CLPATH (
    set TYPE=msvc
    set CC=%CLPATH%
    set ENV_BAT=%VSDEV%
    goto cache
  )
)

set LLVMBIN=%ProgramFiles%\LLVM\bin
if exist "%LLVMBIN%\clang-cl.exe" (
  set TYPE=clang-cl
  set CC=%LLVMBIN%\clang-cl.exe
  goto cache
)
if exist "%LLVMBIN%\clang.exe" (
  set TYPE=clang
  set CC=%LLVMBIN%\clang.exe
  goto cache
)

for %%D in ("C:\msys64\ucrt64\bin" "C:\msys64\mingw64\bin" "C:\mingw64\bin") do (
  if exist "%%~D\gcc.exe" (
    set TYPE=gcc
    set CC=%%~D\gcc.exe
    goto cache
  )
)

for /f "delims=" %%P in ('dir /b /s "%ProgramFiles%\mingw-w64\*\mingw64\bin\gcc.exe" 2^>nul') do (
  set TYPE=gcc
  set CC=%%P
  goto cache
)

call :find_file "%VSX86%" cl.exe CLPATH
if not defined CLPATH call :find_file "%VS64%" cl.exe CLPATH
if defined CLPATH (
  set TYPE=msvc
  set CC=%CLPATH%
  
  if not defined VSDEV call :find_file "%VSX86%" VsDevCmd.bat VSDEV
  if not defined VSDEV call :find_file "%VS64%" VsDevCmd.bat VSDEV
  if defined VSDEV set ENV_BAT=%VSDEV%
  goto cache
)

echo [ERROR] No working compiler found (tried: MSVC, clang/clang-cl, mingw-gcc).
exit /b 1

:cache
call :write_cache

:build
echo [*] Building %PROJECT% with TYPE=%TYPE%
if /i "%TYPE%"=="msvc" (
  if defined ENV_BAT (
    echo [*] Initializing MSVC environment via: "%ENV_BAT%"
    call "%ENV_BAT%" -arch=x64 >nul
  ) else (
    echo [!] Proceeding without VsDevCmd; build may fail if env not set.
  )
  cl /nologo /Zi /EHsc /I "%INCLUDE_DIR%" "%SRC%" /Fe:%OUT%
  if errorlevel 1 exit /b 1
) else if /i "%TYPE%"=="clang-cl" (
  clang-cl /nologo /Zi /EHsc /I "%INCLUDE_DIR%" "%SRC%" /Fe:%OUT%
  if errorlevel 1 exit /b 1
) else if /i "%TYPE%"=="clang" (
  clang -O2 -g -Wall -Wextra -I "%INCLUDE_DIR%" "%SRC%" -o "%OUT%"
  if errorlevel 1 exit /b 1
) else if /i "%TYPE%"=="gcc" (
  gcc -O2 -g -Wall -Wextra -I "%INCLUDE_DIR%" "%SRC%" -o "%OUT%"
  if errorlevel 1 exit /b 1
) else (
  echo [ERROR] Unknown TYPE=%TYPE%
  exit /b 1
)

echo [+] Build complete: %OUT%

if /i "%~1"=="install" (
  echo [*] Installing to %PREFIX%
  if not exist "%BINDIR%" mkdir "%BINDIR%"
  if not exist "%INCDIR%" mkdir "%INCDIR%"
  copy /Y "%OUT%" "%BINDIR%\%PROJECT%.exe" >nul
  copy /Y "%HEADER%" "%INCDIR%\Recipe.h" >nul
  echo [+] Installed:
  echo    %BINDIR%\%PROJECT%.exe
  echo    %INCDIR%\Recipe.h
  goto :eof
)

if /i "%~1"=="uninstall" (
  echo [*] Uninstalling from %PREFIX%

  set "BIN_PATH=%BINDIR%\%PROJECT%.exe"
  set "HDR_PATH=%INCDIR%\Recipe.h"

  if exist "%BIN_PATH%" (
    del /f /q "%BIN_PATH%"
    echo [-] Removed %BIN_PATH%
  ) else (
    echo [i] Skipping: %BIN_PATH% not found
  )

  if exist "%HDR_PATH%" (
    del /f /q "%HDR_PATH%"
    echo [-] Removed %HDR_PATH%
  ) else (
    echo [i] Skipping: %HDR_PATH% not found
  )

  call :rmdir_if_empty "%INCDIR%"
  call :rmdir_if_empty "%BINDIR%"

  echo [+] Uninstall complete.
  goto :eof
)

goto :eof

:rmdir_if_empty
set "_dir=%~1"
if not exist "%_dir%\" goto :eof
set "empty=1"
for /f %%K in ('dir /b "%_dir%" 2^>nul') do set "empty=0"
if "!empty!"=="1" (
  rmdir "%_dir%" && echo [-] Removed empty dir %_dir% || echo [i] Could not remove dir %_dir%
)
goto :eof

:usage
echo Usage:
echo   %~nx0                 Build %OUT% locally
echo   %~nx0 install         Install into "%PREFIX%"
echo   %~nx0 uninstall       Remove installed files from "%PREFIX%"
echo.
echo Environment:
echo   PREFIX  (default: C:\Program Files\Carbide)
goto :eof
endlocal
