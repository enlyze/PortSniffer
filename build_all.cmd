@echo off
::
:: PortSniffer - Monitor the traffic of arbitrary serial or parallel ports
:: Copyright 2020 Colin Finck, ENLYZE GmbH <c.finck@enlyze.com>
::
:: SPDX-License-Identifier: MIT
::

setlocal

if "%_BUILDARCH%" == "x86" (
    set OBJ_DIR=obj%BUILD_ALT_DIR%\i386
) else if "%_BUILDARCH%" == "AMD64" (
    set OBJ_DIR=obj%BUILD_ALT_DIR%\amd64
) else (
    echo Unknown build architecture: %_BUILDARCH%
    echo Please run this script in a WDK command prompt.
    goto :EOF
)

set REDIST_DIR=redist_%_BUILDARCH%
mkdir %REDIST_DIR% 2>NUL
copy %BASEDIR%\redist\wdf\%_BUILDARCH%\WdfCoInstaller01009.dll %REDIST_DIR%
cd src

cd driver
rd /s /q %OBJ_DIR%
build
copy %OBJ_DIR%\EnlyzePortSniffer.sys ..\..\%REDIST_DIR%
cd ..

cd tool
rd /s /q %OBJ_DIR%
build
copy %OBJ_DIR%\PortSniffer-Tool.exe ..\..\%REDIST_DIR%
cd ..
