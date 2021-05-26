//
// PortSniffer - Monitor the traffic of arbitrary serial or parallel ports
// Copyright 2020-2021 Colin Finck, ENLYZE GmbH <c.finck@enlyze.com>
//
// SPDX-License-Identifier: MIT
//

#include "PortSniffer-Tool.h"

static BOOL _bTerminationRequested = FALSE;


static BOOL WINAPI
_CtrlHandlerRoutine(
    __in DWORD dwCtrlType
    )
{
    UNREFERENCED_PARAMETER(dwCtrlType);

    _bTerminationRequested = TRUE;
    return TRUE;
}

static BOOL
_ParseTypes(
    __in PCWSTR pwszTypes,
    __out PUSHORT pMonitorMask
    )
{
    PCWSTR p;

    *pMonitorMask = 0;
    for (p = pwszTypes; *p; p++)
    {
        if (*p == L'R')
        {
            *pMonitorMask |= PORTSNIFFER_MONITOR_READ;
        }
        else if (*p == L'W')
        {
            *pMonitorMask |= PORTSNIFFER_MONITOR_WRITE;
        }
        else
        {
            fprintf(stderr, "Invalid character for TYPES: %lc\n", *p);
            return FALSE;
        }
    }

    if (*pMonitorMask == 0)
    {
        fprintf(stderr, "No TYPES to monitor were given.\n");
        return FALSE;
    }

    return TRUE;
}

static BOOL
_PrintResponse(
    __in PPORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE pPopResponse
    )
{
    char cType;
    USHORT i;

    // Indicate the monitored request via a single character.
    if (pPopResponse->Type == PORTSNIFFER_MONITOR_READ)
    {
        cType = 'R';
    }
    else if (pPopResponse->Type == PORTSNIFFER_MONITOR_WRITE)
    {
        cType = 'W';
    }
    else
    {
        fprintf(stderr, "Captured an invalid request type: %X\n", pPopResponse->Type);
        return FALSE;
    }

    // Print in the format "TYPE | LENGTH | DATA IN HEX".
    printf("%c | %4u |", cType, pPopResponse->DataLength);

    for (i = 0; i < pPopResponse->DataLength; i++)
    {
        printf(" %02X", pPopResponse->Data[i]);
    }

    printf("\n");
    return TRUE;
}

int
HandleMonitorParameter(
    __in PCWSTR pwszPort,
    __in PCWSTR pwszTypes
    )
{
    BOOL bMonitoringStarted = FALSE;
    DWORD cbReturned;
    HANDLE hPortSniffer = INVALID_HANDLE_VALUE;
    int iReturnValue = 1;
    BYTE PopResponseBuffer[PORTSNIFFER_PORTLOG_ENTRY_LENGTH];
    PPORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE pPopResponse = (PPORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE)PopResponseBuffer;
    PORTSNIFFER_POP_PORTLOG_ENTRY_REQUEST PopRequest;
    PORTSNIFFER_RESET_PORT_MONITORING_REQUEST ResetPortMonitoringRequest;

    // Check the input parameters and prepare the IOCTL requests.
    if (wcslen(pwszPort) >= PORTSNIFFER_PORTNAME_LENGTH)
    {
        fprintf(stderr, "Port name is too long: %S\n", pwszPort);
        goto Cleanup;
    }

    StringCchCopyW(PopRequest.PortName, PORTSNIFFER_PORTNAME_LENGTH, pwszPort);
    StringCchCopyW(ResetPortMonitoringRequest.PortName, PORTSNIFFER_PORTNAME_LENGTH, pwszPort);

    if (!_ParseTypes(pwszTypes, &ResetPortMonitoringRequest.MonitorMask))
    {
        goto Cleanup;
    }

    // Connect to our driver.
    hPortSniffer = OpenPortSniffer();
    if (hPortSniffer == INVALID_HANDLE_VALUE)
    {
        goto Cleanup;
    }

    // Start monitoring on this port.
    if (!DeviceIoControl(hPortSniffer,
        (DWORD)PORTSNIFFER_IOCTL_CONTROL_RESET_PORT_MONITORING,
        &ResetPortMonitoringRequest,
        sizeof(PORTSNIFFER_RESET_PORT_MONITORING_REQUEST),
        NULL,
        0,
        &cbReturned,
        NULL))
    {
        if (GetLastError() == ERROR_FILE_NOT_FOUND)
        {
            fprintf(stderr, "The PortSniffer Driver is not attached to %S!\n", pwszPort);
            fprintf(stderr, "Please run this tool using the /attach option.\n");
        }
        else
        {
            fprintf(stderr, "DeviceIoControl failed for PORTSNIFFER_IOCTL_CONTROL_RESET_PORT_MONITORING, last error is %lu.\n", GetLastError());
        }

        goto Cleanup;
    }

    bMonitoringStarted = TRUE;

    // Handle Ctrl+C requests to gracefully stop monitoring.
    if (!SetConsoleCtrlHandler(_CtrlHandlerRoutine, TRUE))
    {
        fprintf(stderr, "SetConsoleCtrlHandler failed, last error is %lu.\n", GetLastError());
        goto Cleanup;
    }

    // Fetch new port log entries from our driver until we are terminated.
    while (!_bTerminationRequested)
    {
        if (!DeviceIoControl(hPortSniffer,
            (DWORD)PORTSNIFFER_IOCTL_CONTROL_POP_PORTLOG_ENTRY,
            &PopRequest,
            sizeof(PORTSNIFFER_POP_PORTLOG_ENTRY_REQUEST),
            PopResponseBuffer,
            sizeof(PopResponseBuffer),
            &cbReturned,
            NULL))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
            {
                Sleep(10);
                continue;
            }
            else if (GetLastError() == ERROR_FILE_NOT_FOUND)
            {
                fprintf(stderr, "The PortSniffer Driver is no longer attached to %S!\n", pwszPort);
                fprintf(stderr, "Please run this tool using the /attach option.\n");
                goto Cleanup;
            }
            else
            {
                fprintf(stderr, "DeviceIoControl failed for PORTSNIFFER_POP_PORTLOG_ENTRY_REQUEST, last error is %lu.\n", GetLastError());
                goto Cleanup;
            }
        }

        if (!_PrintResponse(pPopResponse))
        {
            goto Cleanup;
        }
    }

    iReturnValue = 0;

Cleanup:
    if (bMonitoringStarted)
    {
        // Tell our driver to stop monitoring now that we are gone.
        // Failure to do so won't really do any harm, but accumulate port log entries until we have MAX_LOG_ENTRIES_PER_PORT.
        ResetPortMonitoringRequest.MonitorMask = PORTSNIFFER_MONITOR_NONE;
        DeviceIoControl(hPortSniffer,
            (DWORD)PORTSNIFFER_IOCTL_CONTROL_RESET_PORT_MONITORING,
            &ResetPortMonitoringRequest,
            sizeof(PORTSNIFFER_RESET_PORT_MONITORING_REQUEST),
            NULL,
            0,
            &cbReturned,
            NULL);
    }

    if (hPortSniffer != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hPortSniffer);
    }

    return iReturnValue;
}
