//
// PortSniffer - Monitor the traffic of arbitrary serial or parallel ports
// Copyright 2020-2021 Colin Finck, ENLYZE GmbH <c.finck@enlyze.com>
//
// SPDX-License-Identifier: MIT
//

#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "../ioctl.h"
#include "../version.h"


#define CONTROL_DEVICE_NAME_STRING          L"\\Device\\EnlyzePortSniffer"
#define CONTROL_SYMBOLIC_LINK_NAME_STRING   L"\\DosDevices\\EnlyzePortSniffer"
#define POOL_TAG                            (ULONG)'nSoP'

// The worst case is a serial port at 115200 baud, which is read via 1-byte requests.
// 115200 baud makes 14400 bytes/second. Considering that the PortSniffer-Tool polls the
// driver in 10 millisecond intervals (100 times/second), we need to buffer up to
// 144 1-byte log entries.
// Choose 160 (divisible by 32) as the upper limit here to be on the safe side.
#define MAX_LOG_ENTRIES_PER_PORT            160


typedef struct _PORTLOG_ENTRY
{
    WDFMEMORY Memory;
    struct _PORTLOG_ENTRY* Next;
    PORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE Response;
}
PORTLOG_ENTRY, *PPORTLOG_ENTRY;


typedef struct _FILTER_CONTEXT
{
    UNICODE_STRING PortName;
    USHORT MonitorMask;

    PPORTLOG_ENTRY LogEntryHead;
    PPORTLOG_ENTRY LogEntryTail;
    WDFWAITLOCK LogEntryLock;
    USHORT LogEntryCount;

    WDFWORKITEM ReadWorkItem;
}
FILTER_CONTEXT, *PFILTER_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(FILTER_CONTEXT, GetFilterContext)


typedef struct _READ_WORK_ITEM_CONTEXT
{
    WDFREQUEST Request;
    PUCHAR ReadBuffer;
    size_t BytesRead;
    PFILTER_CONTEXT FilterContext;
}
READ_WORK_ITEM_CONTEXT, *PREAD_WORK_ITEM_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(READ_WORK_ITEM_CONTEXT, GetReadWorkItemContext)


DRIVER_INITIALIZE DriverEntry;

__drv_requiresIRQL(PASSIVE_LEVEL)
NTSTATUS
PortSnifferControlCreate(
    __in WDFDRIVER Driver
    );

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL
PortSnifferControlEvtIoDeviceControl;

__drv_requiresIRQL(PASSIVE_LEVEL)
void
PortSnifferControlGetAttachedPorts(
    __in WDFREQUEST Request
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
void
PortSnifferControlGetVersion(
    __in WDFREQUEST Request
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
void
PortSnifferControlPopPortLogEntry(
    __in WDFREQUEST Request
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
NTSTATUS
PortSnifferControlPopPortLogEntryInternal(
    __inout PFILTER_CONTEXT FilterContext,
    __out PPORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE Response,
    __out PULONG_PTR ResponseLength
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
void
PortSnifferControlResetPortMonitoring(
    __in WDFREQUEST Request
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
void
PortSnifferFilterAddPortLogEntry(
    __inout PFILTER_CONTEXT FilterContext,
    __in USHORT Type,
    __in PUCHAR Data,
    __in size_t DataLength
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
void
PortSnifferFilterClearPortLog(
    __inout PFILTER_CONTEXT FilterContext
    );

EVT_WDF_DRIVER_DEVICE_ADD PortSnifferFilterEvtDeviceAdd;

EVT_WDF_DEVICE_CONTEXT_CLEANUP PortSnifferFilterEvtDeviceCleanup;

EVT_WDF_IO_QUEUE_IO_READ PortSnifferFilterEvtIoRead;

EVT_WDF_REQUEST_COMPLETION_ROUTINE PortSnifferFilterEvtIoReadCompletionRoutine;

EVT_WDF_WORKITEM PortSnifferFilterEvtIoReadCompletionWorkItem;

EVT_WDF_IO_QUEUE_IO_WRITE PortSnifferFilterEvtIoWrite;
