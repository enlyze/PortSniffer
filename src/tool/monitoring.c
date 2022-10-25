//
// PortSniffer - Monitor the traffic of arbitrary serial or parallel ports
// Copyright 2020-2022 Colin Finck, ENLYZE GmbH <c.finck@enlyze.com>
//
// SPDX-License-Identifier: MIT
//

#include "PortSniffer-Tool.h"

typedef struct _FLAG_TRANSLATION
{
    ULONG FlagBit;
    const char* pszFlagName;
}
FLAG_TRANSLATION;

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
        else if (*p == L'C')
        {
            *pMonitorMask |= PORTSNIFFER_MONITOR_IOCTL;
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

static void
_PrintBitmask(
    __in ULONG Bitmask,
    __in const FLAG_TRANSLATION* TranslationTable,
    __in size_t TranslationTableEntries
    )
{
    BOOL bPrintedOne = FALSE;
    size_t i;

    for (i = 0; i < TranslationTableEntries; i++)
    {
        if (Bitmask & TranslationTable[i].FlagBit)
        {
            if (bPrintedOne)
            {
                printf("|");
            }

            printf("%s", TranslationTable[i].pszFlagName);
            bPrintedOne = TRUE;
        }
    }
}

static BOOL
_PrintIoctlResponse(
    __in PPORTSNIFFER_IOCTL_DATA pIoctlData
    )
{
    const FLAG_TRANSLATION ControlHandShakeTranslationTable[] = {
        { SERIAL_DTR_CONTROL, "SERIAL_DTR_CONTROL" },
        { SERIAL_DTR_HANDSHAKE, "SERIAL_DTR_HANDSHAKE" },
        { SERIAL_CTS_HANDSHAKE, "SERIAL_CTS_HANDSHAKE"},
        { SERIAL_DSR_HANDSHAKE, "SERIAL_DSR_HANDSHAKE" },
        { SERIAL_DCD_HANDSHAKE, "SERIAL_DCD_HANDSHAKE" },
        { SERIAL_DSR_SENSITIVITY, "SERIAL_DSR_SENSITIVITY" },
        { SERIAL_ERROR_ABORT, "SERIAL_ERROR_ABORT" }
    };
    const FLAG_TRANSLATION FlowReplaceTranslationTable[] = {
        { SERIAL_AUTO_TRANSMIT, "SERIAL_AUTO_TRANSMIT" },
        { SERIAL_AUTO_RECEIVE, "SERIAL_AUTO_RECEIVE" },
        { SERIAL_ERROR_CHAR, "SERIAL_ERROR_CHAR" },
        { SERIAL_NULL_STRIPPING, "SERIAL_NULL_STRIPPING" },
        { SERIAL_BREAK_CHAR, "SERIAL_BREAK_CHAR" },
        { SERIAL_RTS_CONTROL, "SERIAL_RTS_CONTROL" },
        { SERIAL_RTS_HANDSHAKE, "SERIAL_RTS_HANDSHAKE" },
        { SERIAL_XOFF_CONTINUE, "SERIAL_XOFF_CONTINUE" }
    };
    const char* pszParity[] = { "NO_PARITY", "ODD_PARITY", "EVEN_PARITY", "MARK_PARITY", "SPACE_PARITY" };
    const char* pszStopBits[] = { "STOP_BIT_1", "STOP_BITS_1_5", "STOP_BITS_2" };

    switch (pIoctlData->IoControlCode)
    {
        case IOCTL_SERIAL_CLR_DTR:
            printf("IOCTL_SERIAL_CLR_DTR");
            return TRUE;

        case IOCTL_SERIAL_CLR_RTS:
            printf("IOCTL_SERIAL_CLR_RTS");
            return TRUE;

        case IOCTL_SERIAL_SET_BAUD_RATE:
            printf("IOCTL_SERIAL_SET_BAUD_RATE: %lu", pIoctlData->u.SerialBaudRate.BaudRate);
            return TRUE;

        case IOCTL_SERIAL_SET_BREAK_OFF:
            printf("IOCTL_SERIAL_SET_BREAK_OFF");
            return TRUE;

        case IOCTL_SERIAL_SET_BREAK_ON:
            printf("IOCTL_SERIAL_SET_BREAK_ON");
            return TRUE;

        case IOCTL_SERIAL_SET_DTR:
            printf("IOCTL_SERIAL_SET_DTR");
            return TRUE;

        case IOCTL_SERIAL_SET_HANDFLOW:
            printf("IOCTL_SERIAL_SET_HANDFLOW: ControlHandShake:");
            _PrintBitmask(pIoctlData->u.SerialHandflow.ControlHandShake, ControlHandShakeTranslationTable, _countof(ControlHandShakeTranslationTable));
            printf(", FlowReplace:");
            _PrintBitmask(pIoctlData->u.SerialHandflow.FlowReplace, FlowReplaceTranslationTable, _countof(FlowReplaceTranslationTable));
            printf(", XonLimit:%ld, XoffLimit:%ld", pIoctlData->u.SerialHandflow.XonLimit, pIoctlData->u.SerialHandflow.XoffLimit);
            return TRUE;

        case IOCTL_SERIAL_SET_LINE_CONTROL:
        {
            printf("IOCTL_SERIAL_SET_LINE_CONTROL: ");

            if (pIoctlData->u.SerialLineControl.StopBits < _countof(pszStopBits))
            {
                printf("StopBits:%s, ", pszStopBits[pIoctlData->u.SerialLineControl.StopBits]);
            }

            if (pIoctlData->u.SerialLineControl.Parity < _countof(pszParity))
            {
                printf("Parity:%s, ", pszParity[pIoctlData->u.SerialLineControl.Parity]);
            }

            printf("WordLength:%u", pIoctlData->u.SerialLineControl.WordLength);
            return TRUE;
        }

        case IOCTL_SERIAL_SET_QUEUE_SIZE:
            printf("IOCTL_SERIAL_SET_QUEUE_SIZE: InSize:%lu, OutSize:%lu",
                   pIoctlData->u.SerialQueueSize.InSize,
                   pIoctlData->u.SerialQueueSize.OutSize);
            return TRUE;

        case IOCTL_SERIAL_SET_RTS:
            printf("IOCTL_SERIAL_SET_RTS");
            return TRUE;

        case IOCTL_SERIAL_SET_TIMEOUTS:
            printf("IOCTL_SERIAL_SET_TIMEOUTS: ReadIntervalTimeout:%lu, ReadTotalTimeoutMultiplier:%lu, ReadTotalTimeoutConstant:%lu, WriteTotalTimeoutMultiplier:%lu, WriteTotalTimeoutConstant:%lu",
                   pIoctlData->u.SerialTimeouts.ReadIntervalTimeout,
                   pIoctlData->u.SerialTimeouts.ReadTotalTimeoutMultiplier,
                   pIoctlData->u.SerialTimeouts.ReadTotalTimeoutConstant,
                   pIoctlData->u.SerialTimeouts.WriteTotalTimeoutMultiplier,
                   pIoctlData->u.SerialTimeouts.WriteTotalTimeoutConstant);
            return TRUE;

        case IOCTL_SERIAL_SET_XON:
            printf("IOCTL_SERIAL_SET_XON");
            return TRUE;

        case IOCTL_SERIAL_SET_XOFF:
            printf("IOCTL_SERIAL_SET_XOFF");
            return TRUE;

        default:
            fprintf(stderr, "Captured an unknown IOCTL code: 0x%08X\n", pIoctlData->IoControlCode);
            return FALSE;
    }
}

static BOOL
_PrintResponse(
    __in PPORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE pPopResponse
    )
{
    char cType;
    PFILETIME pFileTimeStamp;
    PPORTSNIFFER_IOCTL_DATA pIoctlData;
    SYSTEMTIME SystemTimeStamp;
    USHORT i;

    // Convert the timestamp into a printable format.
    // The LARGE_INTEGER Timestamp can be casted to a FILETIME (but not necessarily vice-versa!)
    pFileTimeStamp = (PFILETIME)&pPopResponse->Timestamp;
    FileTimeToSystemTime(pFileTimeStamp, &SystemTimeStamp);

    // Indicate the monitored request via a single character.
    if (pPopResponse->Type == PORTSNIFFER_MONITOR_READ)
    {
        cType = 'R';
    }
    else if (pPopResponse->Type == PORTSNIFFER_MONITOR_WRITE)
    {
        cType = 'W';
    }
    else if (pPopResponse->Type == PORTSNIFFER_MONITOR_IOCTL)
    {
        cType = 'C';
    }
    else
    {
        fprintf(stderr, "Captured an invalid request type: 0x%04X\n", pPopResponse->Type);
        return FALSE;
    }

    // Print in the format "UTC TIMESTAMP | TYPE | LENGTH | DATA".
    printf("%04u-%02u-%02u %02u:%02u:%02u.%03u | %c | %4u |",
           SystemTimeStamp.wYear, SystemTimeStamp.wMonth, SystemTimeStamp.wDay,
           SystemTimeStamp.wHour, SystemTimeStamp.wMinute, SystemTimeStamp.wSecond, SystemTimeStamp.wMilliseconds,
           cType, pPopResponse->DataLength);

    if (pPopResponse->Type == PORTSNIFFER_MONITOR_IOCTL)
    {
        // IOCTLs need specialized printing depending on the IOCTL code.
        pIoctlData = (PPORTSNIFFER_IOCTL_DATA)pPopResponse->Data;
        printf(" ");

        if (!_PrintIoctlResponse(pIoctlData))
        {
            return FALSE;
        }
    }
    else
    {
        // For read and write requests, we just dump the bytes of the buffer.
        for (i = 0; i < pPopResponse->DataLength; i++)
        {
            printf(" %02X", pPopResponse->Data[i]);
        }
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

    // Verify that driver and tool are compatible.
    if (!VerifyDriverAndToolVersions(hPortSniffer, FALSE, NULL))
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

    // Print the table header.
    printf("UTC TIMESTAMP           | T |  LEN | DATA\n");

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
