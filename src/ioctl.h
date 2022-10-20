//
// PortSniffer - Monitor the traffic of arbitrary serial or parallel ports
// Copyright 2020-2022 Colin Finck, ENLYZE GmbH <c.finck@enlyze.com>
//
// SPDX-License-Identifier: MIT
//

#pragma once

#include <ntddser.h>

// A single page should be a sufficient maximum length for a single PORTSNIFFER_PORTLOG_POP_ENTRY_RESPONSE.
// Always allocate an output buffer this large for PORTSNIFFER_IOCTL_CONTROL_PORTLOG_POP_ENTRY.
#define PORTSNIFFER_PORTLOG_ENTRY_LENGTH    4096

// From the SYMBOLIC_NAME_LENGTH constant in WDK's serial sample.
// This length includes the terminating NUL character, so always perform a >= sanity check on this value.
#define PORTSNIFFER_PORTNAME_LENGTH         128

#define PORTSNIFFER_CONTROL_DEVICE_TYPE     0x806A
#define PORTSNIFFER_CONTROL_IOCTL_INDEX     0x800


// Query the version of the running PortSniffer Driver.
typedef struct _PORTSNIFFER_GET_VERSION_RESPONSE
{
    USHORT MajorVersion;
    USHORT MinorVersion;
}
PORTSNIFFER_GET_VERSION_RESPONSE, *PPORTSNIFFER_GET_VERSION_RESPONSE;

#define PORTSNIFFER_IOCTL_CONTROL_GET_VERSION               CTL_CODE(PORTSNIFFER_CONTROL_DEVICE_TYPE, PORTSNIFFER_CONTROL_IOCTL_INDEX, METHOD_BUFFERED, FILE_READ_ACCESS)


// Get the names of all ports the PortSniffer Driver is currently attached to.
typedef struct _PORTSNIFFER_GET_ATTACHED_PORTS_RESPONSE
{
    // Size in bytes of the entire response.
    // Call this IOCTL with a buffer for only the Length field to get the required size.
    ULONG Length;

    // Port names separated by NUL terminators, with a final NUL to terminate the string sequence (just like a REG_MULTI_SZ value).
    WCHAR PortNames[ANYSIZE_ARRAY];
}
PORTSNIFFER_GET_ATTACHED_PORTS_RESPONSE, *PPORTSNIFFER_GET_ATTACHED_PORTS_RESPONSE;

#define PORTSNIFFER_IOCTL_CONTROL_GET_ATTACHED_PORTS        CTL_CODE(PORTSNIFFER_CONTROL_DEVICE_TYPE, PORTSNIFFER_CONTROL_IOCTL_INDEX + 1, METHOD_BUFFERED, FILE_READ_ACCESS)


// Start or stop monitoring a single port and specify what traffic shall be monitored.
// Any call to this IOCTL will also clear the port log.
typedef struct _PORTSNIFFER_RESET_PORT_MONITORING_REQUEST
{
    WCHAR PortName[PORTSNIFFER_PORTNAME_LENGTH];
    USHORT MonitorMask;
}
PORTSNIFFER_RESET_PORT_MONITORING_REQUEST, *PPORTSNIFFER_RESET_PORT_MONITORING_REQUEST;

#define PORTSNIFFER_MONITOR_NONE            0x0000
#define PORTSNIFFER_MONITOR_READ            0x0001
#define PORTSNIFFER_MONITOR_WRITE           0x0002
#define PORTSNIFFER_MONITOR_IOCTL           0x0004

#define PORTSNIFFER_IOCTL_CONTROL_RESET_PORT_MONITORING     CTL_CODE(PORTSNIFFER_CONTROL_DEVICE_TYPE, PORTSNIFFER_CONTROL_IOCTL_INDEX + 2, METHOD_BUFFERED, FILE_WRITE_ACCESS)


// Pop the first monitoring log entry for a given port.
typedef struct _PORTSNIFFER_POP_PORTLOG_ENTRY_REQUEST
{
    WCHAR PortName[PORTSNIFFER_PORTNAME_LENGTH];
}
PORTSNIFFER_POP_PORTLOG_ENTRY_REQUEST, *PPORTSNIFFER_POP_PORTLOG_ENTRY_REQUEST;

typedef struct _PORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE
{
    LARGE_INTEGER Timestamp;
    USHORT Type;
    USHORT DataLength;
    BYTE Data[ANYSIZE_ARRAY];
}
PORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE, *PPORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE;

#define PORTSNIFFER_IOCTL_CONTROL_POP_PORTLOG_ENTRY         CTL_CODE(PORTSNIFFER_CONTROL_DEVICE_TYPE, PORTSNIFFER_CONTROL_IOCTL_INDEX + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)


// Data format when Type of PORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE is PORTSNIFFER_MONITOR_IOCTL.
typedef struct _PORTSNIFFER_IOCTL_DATA
{
    ULONG IoControlCode;
    union
    {
        SERIAL_BAUD_RATE SerialBaudRate;
        SERIAL_HANDFLOW SerialHandflow;
        SERIAL_LINE_CONTROL SerialLineControl;
        SERIAL_QUEUE_SIZE SerialQueueSize;
        SERIAL_TIMEOUTS SerialTimeouts;
    }
    u;
}
PORTSNIFFER_IOCTL_DATA, *PPORTSNIFFER_IOCTL_DATA;
