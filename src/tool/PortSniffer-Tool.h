//
// PortSniffer - Monitor the traffic of arbitrary serial or parallel ports
// Copyright 2020-2022 Colin Finck, ENLYZE GmbH <c.finck@enlyze.com>
//
// SPDX-License-Identifier: MIT
//

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <strsafe.h>
#include <SetupAPI.h>
#include <wdfinstaller.h>

#include "../ioctl.h"
#include "../version.h"

#include <devioctl.h>
#include <ntddpar.h>

#ifdef _PREFAST_
// This isn't kernel-mode code, so function stacks larger than 1KB are fine.
#pragma warning(disable:6262)

// This isn't kernel-mode code, so strsafe.h is fine.
#pragma warning(disable:28146)
#endif

// enum.c
typedef int (*ENUMMONITORABLEPORTSCALLBACK)(
    __in PCWSTR pwszPortName,
    __in HDEVINFO hDevInfo,
    __in PSP_DEVINFO_DATA DeviceInfoData
    );

int
EnumMonitorablePorts(
    __in ENUMMONITORABLEPORTSCALLBACK Callback,
    __in_opt PCWSTR pwszPortNameToFind
    );

// installation.c
int
CheckInstallation(void);

int
HandleInstallParameter(void);

int
HandleUninstallParameter(void);

// monitoring.c
int
HandleMonitorParameter(
    __in PCWSTR pwszPort,
    __in PCWSTR pwszTypes
    );

// PortSniffer-Tool.c
HANDLE
OpenPortSniffer(void);

// setup.c
int
AttachPortCallback(
    __in PCWSTR pwszPortName,
    __in HDEVINFO hDevInfo,
    __in PSP_DEVINFO_DATA DeviceInfoData
    );

int
DetachPortCallback(
    __in PCWSTR pwszPortName,
    __in HDEVINFO hDevInfo,
    __in PSP_DEVINFO_DATA DeviceInfoData
    );

PPORTSNIFFER_GET_ATTACHED_PORTS_RESPONSE
GetAttachedPorts(
    __in HANDLE hPortSniffer
    );

int
HandlePortsParameter(void);

int
HandleAttachedParameter(void);

int
HandleAttachParameter(
    __in PCWSTR pwszPortName
    );

int
HandleDetachParameter(
    __in PCWSTR pwszPortName
    );

int
HandleVersionParameter(void);

BOOL
VerifyDriverAndToolVersions(
    __in HANDLE hPortSniffer,
    __in BOOL bAlwaysPrintVersions,
    __out_opt PPORTSNIFFER_GET_VERSION_RESPONSE pResponse
    );
