//
// PortSniffer - Monitor the traffic of arbitrary serial or parallel ports
// Copyright 2020 Colin Finck, ENLYZE GmbH <c.finck@enlyze.com>
//
// SPDX-License-Identifier: MIT
//

#include "PortSniffer-Tool.h"

static const WCHAR _wszFilterName[] = L"EnlyzePortSniffer";
#define CCH_FILTER_NAME (sizeof(_wszFilterName) / sizeof(WCHAR) - 1)


static int
_DumpPortCallback(
    __in PCWSTR pwszPortName,
    __in HDEVINFO hDevInfo,
    __in PSP_DEVINFO_DATA DeviceInfoData
    )
{
    UNREFERENCED_PARAMETER(hDevInfo);
    UNREFERENCED_PARAMETER(DeviceInfoData);

    printf("%S\n", pwszPortName);
    return 0;
}

static int
_SetNewUpperFilters(
    __in PCWSTR pwszPortName,
    __in HDEVINFO hDevInfo,
    __in PSP_DEVINFO_DATA DeviceInfoData
    )
{
    // Prepare a new UpperFilters value with only our service name and the required double NUL termination for REG_MULTI_SZ.
    WCHAR wszUpperFilters[CCH_FILTER_NAME + 2];
    CopyMemory(wszUpperFilters, _wszFilterName, CCH_FILTER_NAME * sizeof(WCHAR));
    wszUpperFilters[CCH_FILTER_NAME] = L'\0';
    wszUpperFilters[CCH_FILTER_NAME + 1] = L'\0';

    // Set it for the device.
#pragma prefast(suppress : 6385, "We write a REG_MULTI_SZ here, so accessing the full 38 bytes is fine.")
    if (!SetupDiSetDeviceRegistryPropertyW(hDevInfo,
        DeviceInfoData,
        SPDRP_UPPERFILTERS,
        (const BYTE*)wszUpperFilters,
        sizeof(wszUpperFilters)))
    {
        fprintf(stderr, "SetupDiSetDeviceRegistryPropertyW failed for setting a new UpperFilters value, last error is %lu.\n", GetLastError());
        return 1;
    }

    printf("The PortSniffer Driver has been successfully attached to %S.\n", pwszPortName);
    return 0;
}

static int
_SetUpperFilters(
    __in PCWSTR pwszPortName,
    __in HDEVINFO hDevInfo,
    __in PSP_DEVINFO_DATA DeviceInfoData
    )
{
    DWORD cbAllocate;
    DWORD cbRequired;
    DWORD dwType;
    int iReturnValue = 1;
    PWSTR pwszCurrent;
    PWSTR pwszUpperFilters = NULL;

    // Check if we already have an UpperFilters value and how many bytes we need for its REG_MULTI_SZ string.
    SetupDiGetDeviceRegistryPropertyW(hDevInfo, DeviceInfoData, SPDRP_UPPERFILTERS, NULL, NULL, 0, &cbRequired);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        // No upper filters exist for this device yet.
        return _SetNewUpperFilters(pwszPortName, hDevInfo, DeviceInfoData);
    }

    // Reserve additional space for adding our service name.
    cbAllocate = cbRequired + sizeof(_wszFilterName);

    // Allocate a buffer large enough.
    pwszUpperFilters = HeapAlloc(GetProcessHeap(), 0, cbAllocate);
    if (!pwszUpperFilters)
    {
        fprintf(stderr, "HeapAlloc failed, last error is %lu.\n", GetLastError());
        goto Cleanup;
    }

    // Get the actual UpperFilters value.
    if (!SetupDiGetDeviceRegistryPropertyW(hDevInfo,
        DeviceInfoData,
        SPDRP_UPPERFILTERS,
        &dwType,
        (PBYTE)pwszUpperFilters,
        cbRequired,
        NULL))
    {
        fprintf(stderr, "SetupDiGetDeviceRegistryPropertyW failed, last error is %lu.\n", GetLastError());
        goto Cleanup;
    }

    // Check if we are already part of the UpperFilters value.
    for (pwszCurrent = pwszUpperFilters; *pwszCurrent; pwszCurrent += wcslen(pwszCurrent) + 1)
    {
        if (_wcsicmp(pwszCurrent, _wszFilterName) == 0)
        {
            // We are already part of UpperFilters. Nothing to do.
            printf("The PortSniffer Driver is already attached to %S.\n", pwszPortName);
            iReturnValue = 0;
            goto Cleanup;
        }
    }

    // Add us to UpperFilters and fix the REG_MULTI_SZ double NUL termination.
    CopyMemory(pwszCurrent, _wszFilterName, sizeof(_wszFilterName));
    pwszCurrent += sizeof(_wszFilterName) / sizeof(WCHAR);
    *pwszCurrent = 0;

    // Set the new UpperFilters value.
    if (!SetupDiSetDeviceRegistryPropertyW(hDevInfo,
        DeviceInfoData,
        SPDRP_UPPERFILTERS,
        (const BYTE*)pwszUpperFilters,
        cbAllocate))
    {
        fprintf(stderr, "SetupDiSetDeviceRegistryPropertyW failed for updating the UpperFilters value, last error is %lu.\n", GetLastError());
        goto Cleanup;
    }

    printf("The PortSniffer Driver has been successfully attached to %S.\n", pwszPortName);
    iReturnValue = 0;

Cleanup:
    if (pwszUpperFilters)
    {
        HeapFree(GetProcessHeap(), 0, pwszUpperFilters);
    }

    return iReturnValue;
}

static int
_UnsetUpperFilters(
    __in PCWSTR pwszPortName,
    __in HDEVINFO hDevInfo,
    __in PSP_DEVINFO_DATA DeviceInfoData
    )
{
    DWORD cbRequired;
    DWORD cbRemaining;
    DWORD dwType;
    int iReturnValue = 1;
    PWSTR pwszCurrent;
    PWSTR pwszRemaining;
    PWSTR pwszUpperFilters = NULL;

    // Check how many bytes we need for reading the UpperFilters REG_MULTI_SZ string.
    SetupDiGetDeviceRegistryPropertyW(hDevInfo, DeviceInfoData, SPDRP_UPPERFILTERS, NULL, NULL, 0, &cbRequired);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        // No UpperFilters exist, so nothing to do for us.
        printf("The PortSniffer Driver was not attached to %S.\n", pwszPortName);
        iReturnValue = 0;
        goto Cleanup;
    }

    // Allocate a buffer large enough.
    pwszUpperFilters = HeapAlloc(GetProcessHeap(), 0, cbRequired);
    if (!pwszUpperFilters)
    {
        fprintf(stderr, "HeapAlloc failed, last error is %lu.\n", GetLastError());
        goto Cleanup;
    }

    // Get the actual UpperFilters value.
    if (!SetupDiGetDeviceRegistryPropertyW(hDevInfo,
        DeviceInfoData,
        SPDRP_UPPERFILTERS,
        &dwType,
        (PBYTE)pwszUpperFilters,
        cbRequired,
        NULL))
    {
        fprintf(stderr, "SetupDiGetDeviceRegistryPropertyW failed, last error is %lu.\n", GetLastError());
        goto Cleanup;
    }

    // Check if we are actually part of the UpperFilters value.
    for (pwszCurrent = pwszUpperFilters; *pwszCurrent; pwszCurrent += wcslen(pwszCurrent) + 1)
    {
        if (_wcsicmp(pwszCurrent, _wszFilterName) == 0)
        {
            // We are part of UpperFilters. Overwrite us with the remaining data.
            pwszRemaining = pwszCurrent + wcslen(pwszCurrent) + 1;
            cbRemaining = (DWORD)(&pwszUpperFilters[cbRequired] - pwszRemaining);
            MoveMemory(pwszCurrent, pwszRemaining, cbRemaining);
            cbRequired = (DWORD)(&pwszCurrent[cbRemaining] - pwszUpperFilters);

            // Set the new UpperFilters value.
            if (!SetupDiSetDeviceRegistryPropertyW(hDevInfo,
                DeviceInfoData,
                SPDRP_UPPERFILTERS,
                (const BYTE*)pwszUpperFilters,
                cbRequired))
            {
                fprintf(stderr, "SetupDiSetDeviceRegistryPropertyW failed for removing us from the UpperFilters value, last error is %lu.\n", GetLastError());
                goto Cleanup;
            }

            printf("The PortSniffer Driver has been successfully detached from %S.\n", pwszPortName);
            iReturnValue = 0;
            goto Cleanup;
        }
    }

    // We aren't part of UpperFilters. Nothing to do for us.
    printf("The PortSniffer Driver was not attached to %S.\n", pwszPortName);
    iReturnValue = 0;

Cleanup:
    if (pwszUpperFilters)
    {
        HeapFree(GetProcessHeap(), 0, pwszUpperFilters);
    }

    return iReturnValue;
}

static int
_RestartDevice(
    __in HDEVINFO hDevInfo,
    __in PSP_DEVINFO_DATA DeviceInfoData
    )
{
    SP_DEVINSTALL_PARAMS_W devinstallParams = { 0 };
    SP_PROPCHANGE_PARAMS propchangeParams = { 0 };

    // Stop the device.
    propchangeParams.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
    propchangeParams.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
    propchangeParams.Scope = DICS_FLAG_CONFIGSPECIFIC;
    propchangeParams.StateChange = DICS_STOP;

    if (!SetupDiSetClassInstallParamsW(hDevInfo,
        DeviceInfoData,
        (PSP_CLASSINSTALL_HEADER)&propchangeParams,
        sizeof(propchangeParams)))
    {
        fprintf(stderr, "Could not set parameters for stopping device, last error is %lu.\n", GetLastError());
        return 1;
    }

    if (!SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo, DeviceInfoData))
    {
        fprintf(stderr, "Could not stop the device, last error is %lu.\n", GetLastError());
        return 1;
    }

    // Start the device.
    propchangeParams.StateChange = DICS_START;

    if (!SetupDiSetClassInstallParamsW(hDevInfo,
        DeviceInfoData,
        (PSP_CLASSINSTALL_HEADER)&propchangeParams,
        sizeof(propchangeParams)))
    {
        fprintf(stderr, "Could not set parameters for starting device, last error is %lu.\n", GetLastError());
        return 1;
    }

    if (!SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo, DeviceInfoData))
    {
        fprintf(stderr, "Could not start the device, last error is %lu.\n", GetLastError());
        return 1;
    }

    // Check if a reboot is required.
    devinstallParams.cbSize = sizeof(devinstallParams);

    if (!SetupDiGetDeviceInstallParamsW(hDevInfo, DeviceInfoData, &devinstallParams))
    {
        fprintf(stderr, "Could not get device installation parameters, last error is %lu.\n", GetLastError());
        return 1;
    }

    if (devinstallParams.Flags & DI_NEEDREBOOT)
    {
        printf("A reboot is required for the changes to take effect.\n");
    }

    return 0;
}

int
AttachPortCallback(
    __in PCWSTR pwszPortName,
    __in HDEVINFO hDevInfo,
    __in PSP_DEVINFO_DATA DeviceInfoData
    )
{
    int iReturnValue;

    iReturnValue = _SetUpperFilters(pwszPortName, hDevInfo, DeviceInfoData);
    if (iReturnValue != 0)
    {
        return iReturnValue;
    }

    return _RestartDevice(hDevInfo, DeviceInfoData);
}

int
DetachPortCallback(
    __in PCWSTR pwszPortName,
    __in HDEVINFO hDevInfo,
    __in PSP_DEVINFO_DATA DeviceInfoData
    )
{
    int iReturnValue;

    iReturnValue = _UnsetUpperFilters(pwszPortName, hDevInfo, DeviceInfoData);
    if (iReturnValue != 0)
    {
        return iReturnValue;
    }

    return _RestartDevice(hDevInfo, DeviceInfoData);
}

PPORTSNIFFER_GET_ATTACHED_PORTS_RESPONSE
GetAttachedPorts(
    __in HANDLE hPortSniffer
    )
{
    DWORD cbResponse;
    PPORTSNIFFER_GET_ATTACHED_PORTS_RESPONSE pResponse;

    // PORTSNIFFER_IOCTL_CONTROL_GET_ATTACHED_PORTS returns a variable-sized buffer, with its Length as the first field.
    // Retrieve this length, resize our buffer, and try again with a larger buffer.
    // As the number of attached ports may change in-between, we do this in an infinite loop until we succeed.
    cbResponse = sizeof(ULONG);
    for (;;)
    {
        pResponse = HeapAlloc(GetProcessHeap(), 0, cbResponse);
        if (!pResponse)
        {
            fprintf(stderr, "HeapAlloc failed, last error is %lu.\n", GetLastError());
            return NULL;
        }

        if (DeviceIoControl(hPortSniffer,
            (DWORD)PORTSNIFFER_IOCTL_CONTROL_GET_ATTACHED_PORTS,
            NULL,
            0,
            pResponse,
            cbResponse,
            &cbResponse,
            NULL))
        {
            return pResponse;
        }

        if (GetLastError() == ERROR_MORE_DATA)
        {
            cbResponse = pResponse->Length;
            HeapFree(GetProcessHeap(), 0, pResponse);
        }
        else
        {
            fprintf(stderr, "DeviceIoControl failed for PORTSNIFFER_IOCTL_CONTROL_GET_ATTACHED_PORTS, last error is %lu.\n", GetLastError());
            HeapFree(GetProcessHeap(), 0, pResponse);
            return NULL;
        }
    }
}

int
HandlePortsParameter(void)
{
    return EnumMonitorablePorts(_DumpPortCallback, NULL);
}

int
HandleAttachedParameter(void)
{
    HANDLE hPortSniffer;
    int iReturnValue = 1;
    PCWSTR p;
    PPORTSNIFFER_GET_ATTACHED_PORTS_RESPONSE pResponse = NULL;

    // Connect to our driver.
    hPortSniffer = OpenPortSniffer();
    if (hPortSniffer == INVALID_HANDLE_VALUE)
    {
        goto Cleanup;
    }

    // Ask it for all attached ports.
    pResponse = GetAttachedPorts(hPortSniffer);
    if (!pResponse)
    {
        goto Cleanup;
    }

    // Print the attached ports we got.
    for (p = pResponse->PortNames; *p; p += wcslen(pResponse->PortNames) + 1)
    {
        printf("%S\n", p);
    }

    iReturnValue = 0;

Cleanup:
    if (pResponse)
    {
        HeapFree(GetProcessHeap(), 0, pResponse);
    }

    if (hPortSniffer != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hPortSniffer);
    }

    return iReturnValue;
}

int
HandleAttachParameter(
    __in PCWSTR pwszPortName
    )
{
    int iReturnValue;

    iReturnValue = CheckInstallation();
    if (iReturnValue != 0)
    {
        return iReturnValue;
    }

    iReturnValue = EnumMonitorablePorts(AttachPortCallback, pwszPortName);
    if (iReturnValue == ERROR_FILE_NOT_FOUND)
    {
        fprintf(stderr, "Could not find the given port!\n");
    }

    return iReturnValue;
}

int
HandleDetachParameter(
    __in PCWSTR pwszPortName
    )
{
    int iReturnValue;

    iReturnValue = EnumMonitorablePorts(DetachPortCallback, pwszPortName);
    if (iReturnValue == ERROR_FILE_NOT_FOUND)
    {
        fprintf(stderr, "Could not find the given port!\n");
    }

    return iReturnValue;
}

int
HandleVersionParameter(void)
{
    DWORD cbReturned;
    HANDLE hPortSniffer = INVALID_HANDLE_VALUE;
    int iReturnValue = 1;
    PORTSNIFFER_GET_VERSION_RESPONSE response;

    // Connect to our driver.
    hPortSniffer = OpenPortSniffer();
    if (hPortSniffer == INVALID_HANDLE_VALUE)
    {
        goto Cleanup;
    }

    // Ask it for its version.
    if (!DeviceIoControl(hPortSniffer,
        (DWORD)PORTSNIFFER_IOCTL_CONTROL_GET_VERSION,
        NULL,
        0,
        &response,
        sizeof(response),
        &cbReturned,
        NULL))
    {
        fprintf(stderr, "DeviceIoControl failed for PORTSNIFFER_IOCTL_CONTROL_GET_VERSION, last error is %lu.\n", GetLastError());
        goto Cleanup;
    }

    // Print driver and tool versions.
    printf("PortSniffer Driver Version %u.%u\n", response.MajorVersion, response.MinorVersion);
    printf("PortSniffer Tool Version %u.%u\n", PORTSNIFFER_MAJOR_VERSION, PORTSNIFFER_MINOR_VERSION);
    printf("\n");

    // Compare them.
    if (response.MajorVersion == PORTSNIFFER_MAJOR_VERSION)
    {
        if (response.MinorVersion == PORTSNIFFER_MINOR_VERSION)
        {
            printf("Setup is COMPATIBLE: The full version numbers match.\n");
        }
        else
        {
            printf("Setup is COMPATIBLE: The major version numbers match.\n");
        }
    }
    else
    {
        printf("Setup is INCOMPATIBLE: The major version numbers differ!\n");
        printf("Please install the PortSniffer Driver that comes with this tool.\n");
    }

    iReturnValue = 0;

Cleanup:
    if (hPortSniffer != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hPortSniffer);
    }

    return iReturnValue;
}
