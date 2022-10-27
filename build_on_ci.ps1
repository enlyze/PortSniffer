#
# PortSniffer - Monitor the traffic of arbitrary serial or parallel ports
# Copyright 2020-2022 Colin Finck, ENLYZE GmbH <c.finck@enlyze.com>
#
# SPDX-License-Identifier: MIT
#

cd $PSScriptRoot

# Set the current Git revision in version.h
$gitRevision = & git rev-parse HEAD
((Get-Content -Path src\version.h -Raw) -Replace 'unknown revision',$gitRevision) | Set-Content -Path src\version.h

# Build release versions of driver and tool for x86 and amd64
cmd /c "call C:\WinDDK\7600.16385.1\bin\setenv.bat C:\WinDDK\7600.16385.1\ fre x86 WXP no_oacr && cd /d $pwd && build_all"
cmd /c "call C:\WinDDK\7600.16385.1\bin\setenv.bat C:\WinDDK\7600.16385.1\ fre x64 WNET no_oacr && cd /d $pwd && build_all"
