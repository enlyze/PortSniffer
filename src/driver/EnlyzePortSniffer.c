//
// PortSniffer - Monitor the traffic of arbitrary serial or parallel ports
// Copyright 2020-2022 Colin Finck, ENLYZE GmbH <c.finck@enlyze.com>
//
// SPDX-License-Identifier: MIT
//

#include "EnlyzePortSniffer.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, PortSnifferControlCreate)
#pragma alloc_text (PAGE, PortSnifferControlEvtIoDeviceControl)
#pragma alloc_text (PAGE, PortSnifferControlGetAttachedPorts)
#pragma alloc_text (PAGE, PortSnifferControlGetVersion)
#pragma alloc_text (PAGE, PortSnifferControlPopPortLogEntry)
#pragma alloc_text (PAGE, PortSnifferControlPopPortLogEntryInternal)
#pragma alloc_text (PAGE, PortSnifferControlResetPortMonitoring)
#pragma alloc_text (PAGE, PortSnifferFilterAddPortLogEntry)
#pragma alloc_text (PAGE, PortSnifferFilterClearPortLog)
#pragma alloc_text (PAGE, PortSnifferFilterEvtDeviceAdd)
#pragma alloc_text (PAGE, PortSnifferFilterEvtDeviceCleanup)
#pragma alloc_text (PAGE, PortSnifferFilterEvtIoRead)
#pragma alloc_text (PAGE, PortSnifferFilterEvtIoReadCompletionWorkItem)
#pragma alloc_text (PAGE, PortSnifferFilterEvtIoWrite)
#endif

WDFDEVICE ControlDevice = NULL;
WDFCOLLECTION FilterDevices = NULL;
WDFWAITLOCK FilterDevicesLock = NULL;
WDFLOOKASIDE PortLogLookaside = NULL;


__drv_functionClass(DRIVER_INITIALIZE)
__drv_sameIRQL
NTSTATUS
DriverEntry(
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    )
{
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;

    KdPrint(("ENLYZE PortSniffer Driver " PORTSNIFFER_VERSION_COMBINED "\n"));

    // Create our driver object.
    WDF_DRIVER_CONFIG_INIT(&config, PortSnifferFilterEvtDeviceAdd);
    status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfDriverCreate failed, status = 0x%08lX\n", status));
        return status;
    }

    // Maintain a collection of all active port filter devices.
    status = WdfCollectionCreate(WDF_NO_OBJECT_ATTRIBUTES, &FilterDevices);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfCollectionCreate failed, status = 0x%08lX\n", status));
        return status;
    }

    // Guard accesses to that collection.
    status = WdfWaitLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &FilterDevicesLock);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfWaitLockCreate failed, status = 0x%08lX\n", status));
        return status;
    }

    // Create a lookaside list to serve all memory requests for port log entries.
    status = WdfLookasideListCreate(WDF_NO_OBJECT_ATTRIBUTES,
        PORTSNIFFER_PORTLOG_ENTRY_LENGTH,
        PagedPool,
        WDF_NO_OBJECT_ATTRIBUTES,
        POOL_TAG,
        &PortLogLookaside);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfLookasideListCreate failed, status = 0x%08lX\n", status));
        return status;
    }

    return STATUS_SUCCESS;
}

__drv_requiresIRQL(PASSIVE_LEVEL)
NTSTATUS
PortSnifferControlCreate(
    __in WDFDRIVER Driver
    )
{
    DECLARE_CONST_UNICODE_STRING(ntDeviceName, CONTROL_DEVICE_NAME_STRING);
    DECLARE_CONST_UNICODE_STRING(symbolicLinkName, CONTROL_SYMBOLIC_LINK_NAME_STRING);

    WDFDEVICE controlDevice = NULL;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    PWDFDEVICE_INIT deviceInit = NULL;
    WDF_OBJECT_ATTRIBUTES ioQueueAttributes;
    WDF_IO_QUEUE_CONFIG ioQueueConfig;
    NTSTATUS status;

    PAGED_CODE();
    KdPrint(("PortSnifferControlCreate(%p)\n", Driver));

    // Allocate a WDFDEVICE_INIT structure for creating an administrator-only control device.
    deviceInit = WdfControlDeviceInitAllocate(Driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (deviceInit == NULL)
    {
        KdPrint(("WdfControlDeviceInitAllocate failed\n"));
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    // Set the control device name.
    status = WdfDeviceInitAssignName(deviceInit, &ntDeviceName);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfDeviceInitAssignName failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    // For now, we only want a single application to simultaneously access the control device (no concurrency).
    WdfDeviceInitSetExclusive(deviceInit, TRUE);

    // Create our control device.
    WDF_OBJECT_ATTRIBUTES_INIT(&deviceAttributes);
    status = WdfDeviceCreate(&deviceInit, &deviceAttributes, &controlDevice);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfDeviceCreate failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    // Register a callback for the application's DeviceIoControl calls to our control device.
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig, WdfIoQueueDispatchSequential);
    ioQueueConfig.EvtIoDeviceControl = PortSnifferControlEvtIoDeviceControl;

    // Ensure that all callback routines are run at IRQL == PASSIVE_LEVEL as we are acquiring a wait lock there.
    WDF_OBJECT_ATTRIBUTES_INIT(&ioQueueAttributes);
    ioQueueAttributes.ExecutionLevel = WdfExecutionLevelPassive;

    // Set up an I/O Queue to handle requests to our control device.
    status = WdfIoQueueCreate(controlDevice, &ioQueueConfig, &ioQueueAttributes, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfIoQueueCreate failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    // Create a symbolic link to our control device for the application.
    status = WdfDeviceCreateSymbolicLink(controlDevice, &symbolicLinkName);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfDeviceCreateSymbolicLink failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    // Finish up and prevent controlDevice from being freed in the Cleanup step.
    WdfControlFinishInitializing(controlDevice);
    ControlDevice = controlDevice;
    controlDevice = NULL;
    status = STATUS_SUCCESS;

Cleanup:
    if (controlDevice)
    {
        WdfObjectDelete(controlDevice);
    }

    if (deviceInit)
    {
        WdfDeviceInitFree(deviceInit);
    }

    return status;
}

__drv_functionClass(EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL)
__drv_sameIRQL
__drv_maxIRQL(DISPATCH_LEVEL)
void
PortSnifferControlEvtIoDeviceControl(
    __in WDFQUEUE Queue,
    __in WDFREQUEST Request,
    __in size_t OutputBufferLength,
    __in size_t InputBufferLength,
    __in ULONG IoControlCode
    )
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    PAGED_CODE();
    KdPrint(("PortSnifferControlEvtIoDeviceControl(%p, %p, %Iu, %Iu, %lu)\n", Queue, Request, OutputBufferLength, InputBufferLength, IoControlCode));

    switch (IoControlCode)
    {
        case PORTSNIFFER_IOCTL_CONTROL_GET_VERSION:
            PortSnifferControlGetVersion(Request);
            break;

        case PORTSNIFFER_IOCTL_CONTROL_GET_ATTACHED_PORTS:
            PortSnifferControlGetAttachedPorts(Request);
            break;

        case PORTSNIFFER_IOCTL_CONTROL_RESET_PORT_MONITORING:
            PortSnifferControlResetPortMonitoring(Request);
            break;

        case PORTSNIFFER_IOCTL_CONTROL_POP_PORTLOG_ENTRY:
            PortSnifferControlPopPortLogEntry(Request);
            break;

        default:
            WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
            break;
    }
}

__drv_requiresIRQL(PASSIVE_LEVEL)
void
PortSnifferControlGetAttachedPorts(
    __in WDFREQUEST Request
    )
{
    ULONG count;
    WDFDEVICE device;
    ULONG i;
    PWSTR p;
    PFILTER_CONTEXT filterContext;
    PPORTSNIFFER_GET_ATTACHED_PORTS_RESPONSE response;
    size_t responseBufferLength;
    NTSTATUS status;

    PAGED_CODE();
    KdPrint(("PortSnifferControlGetAttachedPorts(%p)\n", Request));

    // Get the output buffer that must have enough space for at least the Length field.
    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(ULONG), &response, &responseBufferLength);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfRequestRetrieveOutputBuffer failed, status = 0x%08lX\n", status));
        WdfRequestComplete(Request, status);
        return;
    }

    // Calculate the required output buffer size.
    WdfWaitLockAcquire(FilterDevicesLock, NULL);
    count = WdfCollectionGetCount(FilterDevices);

    response->Length = FIELD_OFFSET(PORTSNIFFER_GET_ATTACHED_PORTS_RESPONSE, PortNames);
    for (i = 0; i < count; i++)
    {
        device = WdfCollectionGetItem(FilterDevices, i);
        filterContext = GetFilterContext(device);
        response->Length += filterContext->PortName.Length + sizeof(WCHAR);
    }

    response->Length += sizeof(WCHAR);

    // Check if the provided buffer is large enough.
    if (responseBufferLength >= response->Length)
    {
        // Copy the port names to the provided buffer.
        // They are separated by NUL terminators, with a final NUL to terminate the string sequence (just like REG_MULTI_SZ).
        p = response->PortNames;
        for (i = 0; i < count; i++)
        {
            device = WdfCollectionGetItem(FilterDevices, i);
            filterContext = GetFilterContext(device);

            RtlCopyMemory(p, filterContext->PortName.Buffer, filterContext->PortName.Length);
            p += filterContext->PortName.Length / sizeof(WCHAR);
            *p = L'\0';
            p++;
        }

        *p = L'\0';
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, response->Length);
    }
    else
    {
        // Return only the Length field containing the required buffer size.
        WdfRequestCompleteWithInformation(Request, STATUS_BUFFER_OVERFLOW, sizeof(ULONG));
    }

    WdfWaitLockRelease(FilterDevicesLock);
}

__drv_requiresIRQL(PASSIVE_LEVEL)
void
PortSnifferControlGetVersion(
    __in WDFREQUEST Request
    )
{
    PPORTSNIFFER_GET_VERSION_RESPONSE response;
    NTSTATUS status;

    PAGED_CODE();
    KdPrint(("PortSnifferControlGetVersion(%p)\n", Request));

    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(PORTSNIFFER_GET_VERSION_RESPONSE), &response, NULL);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfRequestRetrieveOutputBuffer failed, status = 0x%08lX\n", status));
        WdfRequestComplete(Request, status);
        return;
    }

    response->MajorVersion = PORTSNIFFER_MAJOR_VERSION;
    response->MinorVersion = PORTSNIFFER_MINOR_VERSION;

    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(PORTSNIFFER_GET_VERSION_RESPONSE));
}

__drv_requiresIRQL(PASSIVE_LEVEL)
void
PortSnifferControlPopPortLogEntry(
    __in WDFREQUEST Request
    )
{
    ULONG count;
    WDFDEVICE device;
    PFILTER_CONTEXT filterContext;
    ULONG i;
    PPORTSNIFFER_POP_PORTLOG_ENTRY_REQUEST popRequest;
    PPORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE response;
    ULONG_PTR responseLength = 0;
    NTSTATUS status;
    UNICODE_STRING unicodePortName;

    PAGED_CODE();
    KdPrint(("PortSnifferControlPopPortLogEntry(%p)\n", Request));

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(PORTSNIFFER_POP_PORTLOG_ENTRY_REQUEST), &popRequest, NULL);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfRequestRetrieveInputBuffer failed, status = 0x%08lX\n", status));
        WdfRequestComplete(Request, status);
        return;
    }

    status = WdfRequestRetrieveOutputBuffer(Request, PORTSNIFFER_PORTLOG_ENTRY_LENGTH, &response, NULL);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfRequestRetrieveOutputBuffer failed, status = 0x%08lX\n", status));
        WdfRequestComplete(Request, status);
        return;
    }

    // The caller may have sent us a non-NUL-terminated buffer, causing a buffer overrun if fed directly to wcscmp.
    // Avoid that by NUL-terminating the last possible character ourselves.
    popRequest->PortName[PORTSNIFFER_PORTNAME_LENGTH - 1] = L'\0';
    RtlInitUnicodeString(&unicodePortName, popRequest->PortName);

    // Look for the requested port name.
    status = STATUS_NO_SUCH_DEVICE;
    WdfWaitLockAcquire(FilterDevicesLock, NULL);
    count = WdfCollectionGetCount(FilterDevices);

    for (i = 0; i < count; i++)
    {
        device = WdfCollectionGetItem(FilterDevices, i);
        filterContext = GetFilterContext(device);

        if (RtlCompareUnicodeString(&filterContext->PortName, &unicodePortName, FALSE) == 0)
        {
            status = PortSnifferControlPopPortLogEntryInternal(filterContext, response, &responseLength);
            break;
        }
    }

    WdfWaitLockRelease(FilterDevicesLock);
    WdfRequestCompleteWithInformation(Request, status, responseLength);
}

__drv_requiresIRQL(PASSIVE_LEVEL)
NTSTATUS
PortSnifferControlPopPortLogEntryInternal(
    __inout PFILTER_CONTEXT FilterContext,
    __out PPORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE Response,
    __out PULONG_PTR ResponseLength
    )
{
    PPORTLOG_ENTRY entry;
    NTSTATUS status;

    PAGED_CODE();
    KdPrint(("PortSnifferControlPopPortLogEntryInternal(%p, %p, %p)\n", FilterContext, Response, ResponseLength));

    WdfWaitLockAcquire(FilterContext->LogEntryLock, NULL);

    if (FilterContext->LogEntryCount > 0)
    {
        // Get the first log entry and copy its information to the response buffer.
        entry = FilterContext->LogEntryHead;
        *ResponseLength = FIELD_OFFSET(PORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE, Data) + entry->Response.DataLength;
        RtlCopyMemory(Response, &entry->Response, *ResponseLength);

        // Remove the entry from the list.
        if (FilterContext->LogEntryTail == entry)
        {
            FilterContext->LogEntryTail = NULL;
        }

        FilterContext->LogEntryHead = entry->Next;
        FilterContext->LogEntryCount--;

        // Return its memory back to the lookaside list.
        WdfObjectDelete(entry->Memory);

        status = STATUS_SUCCESS;
    }
    else
    {
        *ResponseLength = 0;
        status = STATUS_NO_MORE_ENTRIES;
    }

    WdfWaitLockRelease(FilterContext->LogEntryLock);

    return status;
}

__drv_requiresIRQL(PASSIVE_LEVEL)
void
PortSnifferControlResetPortMonitoring(
    __in WDFREQUEST Request
    )
{
    ULONG count;
    WDFDEVICE device;
    PFILTER_CONTEXT filterContext;
    ULONG i;
    PPORTSNIFFER_RESET_PORT_MONITORING_REQUEST portMonitoringRequest;
    NTSTATUS status;
    UNICODE_STRING unicodePortName;

    PAGED_CODE();
    KdPrint(("PortSnifferControlResetPortMonitoring(%p)\n", Request));

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(PORTSNIFFER_RESET_PORT_MONITORING_REQUEST), &portMonitoringRequest, NULL);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfRequestRetrieveInputBuffer failed, status = 0x%08lX\n", status));
        WdfRequestComplete(Request, status);
        return;
    }

    // The caller may have sent us a non-NUL-terminated buffer, causing a buffer overrun if fed directly to wcscmp.
    // Avoid that by NUL-terminating the last possible character ourselves.
    portMonitoringRequest->PortName[PORTSNIFFER_PORTNAME_LENGTH - 1] = L'\0';
    RtlInitUnicodeString(&unicodePortName, portMonitoringRequest->PortName);

    // Look for the requested port name.
    status = STATUS_NO_SUCH_DEVICE;
    WdfWaitLockAcquire(FilterDevicesLock, NULL);
    count = WdfCollectionGetCount(FilterDevices);

    for (i = 0; i < count; i++)
    {
        device = WdfCollectionGetItem(FilterDevices, i);
        filterContext = GetFilterContext(device);

        if (RtlCompareUnicodeString(&filterContext->PortName, &unicodePortName, FALSE) == 0)
        {
            // Set the new monitor mask, clear recorded events, and exit the loop.
            filterContext->MonitorMask = portMonitoringRequest->MonitorMask;
            PortSnifferFilterClearPortLog(filterContext);
            status = STATUS_SUCCESS;
            break;
        }
    }

    WdfWaitLockRelease(FilterDevicesLock);
    WdfRequestComplete(Request, status);
}

__drv_requiresIRQL(PASSIVE_LEVEL)
void
PortSnifferFilterAddPortLogEntry(
    __inout PFILTER_CONTEXT FilterContext,
    __in USHORT Type,
    __in PUCHAR Data,
    __in size_t DataLength
    )
{
    // We always allocate the same PORTSNIFFER_PORTLOG_ENTRY_LENGTH bytes for every log entry.
    // The actual data may consume everything that's left after the other fields.
    const USHORT MaxDataLength = PORTSNIFFER_PORTLOG_ENTRY_LENGTH - FIELD_OFFSET(PORTLOG_ENTRY, Response.Data);

    PPORTLOG_ENTRY entry;
    WDFMEMORY entryMemory;
    NTSTATUS status;

    PAGED_CODE();
    KdPrint(("PortSnifferFilterAddPortLogEntry(%p, %x, %p, %Iu)\n", FilterContext, Type, Data, DataLength));

    WdfWaitLockAcquire(FilterContext->LogEntryLock, NULL);

    // Don't add anything if the application hasn't popped entries for some time.
    if (FilterContext->LogEntryCount >= MAX_LOG_ENTRIES_PER_PORT)
    {
        KdPrint(("List is full, not adding log entry\n"));
        goto Cleanup;
    }

    // Allocate a new log entry of PORTSNIFFER_PORTLOG_ENTRY_LENGTH bytes from our lookaside list.
    status = WdfMemoryCreateFromLookaside(PortLogLookaside, &entryMemory);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfMemoryCreateFromLookaside failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    // Truncate any data that goes beyond our maximum supported length.
    if (DataLength > MaxDataLength)
    {
        KdPrint(("Truncating log entry data from %Iu to %u bytes\n", DataLength, MaxDataLength));
        DataLength = MaxDataLength;
    }

    // Set all log entry information.
    entry = WdfMemoryGetBuffer(entryMemory, NULL);
    entry->Memory = entryMemory;
    entry->Next = NULL;
    KeQuerySystemTime(&entry->Response.Timestamp);
    entry->Response.Type = Type;
    entry->Response.DataLength = (USHORT)DataLength;
    RtlCopyMemory(entry->Response.Data, Data, DataLength);

    // Add us to the end of the list.
    if (FilterContext->LogEntryCount > 0)
    {
        FilterContext->LogEntryTail->Next = entry;
    }
    else
    {
        FilterContext->LogEntryHead = entry;
    }

    FilterContext->LogEntryTail = entry;
    FilterContext->LogEntryCount++;

Cleanup:
    WdfWaitLockRelease(FilterContext->LogEntryLock);
}

__drv_requiresIRQL(PASSIVE_LEVEL)
void
PortSnifferFilterClearPortLog(
    __inout PFILTER_CONTEXT FilterContext
    )
{
    PPORTLOG_ENTRY entry;
    PPORTLOG_ENTRY nextEntry;

    PAGED_CODE();
    KdPrint(("PortSnifferFilterClearPortLog(%p)\n", FilterContext));

    WdfWaitLockAcquire(FilterContext->LogEntryLock, NULL);

    // Return the memory for each entry back to the lookaside list.
    for (entry = FilterContext->LogEntryHead; entry; entry = nextEntry)
    {
        nextEntry = entry->Next;
        WdfObjectDelete(entry->Memory);
    }

    // Clear the bookkeeping information.
    FilterContext->LogEntryHead = NULL;
    FilterContext->LogEntryTail = NULL;
    FilterContext->LogEntryCount = 0;

    WdfWaitLockRelease(FilterContext->LogEntryLock);
}

__drv_functionClass(EVT_WDF_DRIVER_DEVICE_ADD)
__drv_sameIRQL
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
PortSnifferFilterEvtDeviceAdd(
    __in WDFDRIVER Driver,
    __inout PWDFDEVICE_INIT DeviceInit
    )
{
    DECLARE_CONST_UNICODE_STRING(portNameValueName, L"PortName");

    ULONG count;
    WDFDEVICE device;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    PFILTER_CONTEXT filterContext;
    WDF_OBJECT_ATTRIBUTES ioQueueAttributes;
    WDF_IO_QUEUE_CONFIG ioQueueConfig;
    WDF_OBJECT_ATTRIBUTES logEntryLockAttributes;
    WDFSTRING portNameValueData;
    WDF_OBJECT_ATTRIBUTES portNameValueDataAttributes;
    WDF_OBJECT_ATTRIBUTES readWorkItemAttributes;
    WDF_WORKITEM_CONFIG readWorkItemConfig;
    WDFKEY regKey = WDF_NO_HANDLE;
    NTSTATUS status;

    PAGED_CODE();
    KdPrint(("PortSnifferFilterEvtDeviceAdd(%p, %p)\n", Driver, DeviceInit));

    // Register us as a filter device.
    WdfFdoInitSetFilter(DeviceInit);

    // Register a callback to clean up the control device for the last port.
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, FILTER_CONTEXT);
    deviceAttributes.EvtCleanupCallback = PortSnifferFilterEvtDeviceCleanup;

    // Create our filter device and attach it to the stack of the port device.
    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfDeviceCreate failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    // Query the port name and store it in our context.
    status = WdfDeviceOpenRegistryKey(device, PLUGPLAY_REGKEY_DEVICE, KEY_READ, WDF_NO_OBJECT_ATTRIBUTES, &regKey);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfFdoInitOpenRegistryKey failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    WDF_OBJECT_ATTRIBUTES_INIT(&portNameValueDataAttributes);
    portNameValueDataAttributes.ParentObject = device;
    status = WdfStringCreate(NULL, &portNameValueDataAttributes, &portNameValueData);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfStringCreate failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    status = WdfRegistryQueryString(regKey, &portNameValueName, portNameValueData);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfRegistryQueryString failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    filterContext = GetFilterContext(device);
    WdfStringGetUnicodeString(portNameValueData, &filterContext->PortName);
    if (filterContext->PortName.Length >= PORTSNIFFER_PORTNAME_LENGTH)
    {
        KdPrint(("PortName is too long: %wZ\n", &filterContext->PortName));
        status = STATUS_NAME_TOO_LONG;
        goto Cleanup;
    }

    // Initialize a Work Item for adding port log read entries at IRQL == PASSIVE_LEVEL.
    WDF_WORKITEM_CONFIG_INIT(&readWorkItemConfig, PortSnifferFilterEvtIoReadCompletionWorkItem);
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&readWorkItemAttributes, READ_WORK_ITEM_CONTEXT);
    readWorkItemAttributes.ParentObject = device;
    status = WdfWorkItemCreate(&readWorkItemConfig, &readWorkItemAttributes, &filterContext->ReadWorkItem);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfWorkItemCreate failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    // Initialize the remaining context fields.
    filterContext->MonitorMask = PORTSNIFFER_MONITOR_NONE;

    filterContext->LogEntryHead = NULL;
    filterContext->LogEntryTail = NULL;
    filterContext->LogEntryCount = 0;

    WDF_OBJECT_ATTRIBUTES_INIT(&logEntryLockAttributes);
    logEntryLockAttributes.ParentObject = device;
    status = WdfWaitLockCreate(&logEntryLockAttributes, &filterContext->LogEntryLock);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfWaitLockCreate failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    // Register callbacks for read and write requests.
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig, WdfIoQueueDispatchParallel);
    ioQueueConfig.EvtIoRead = PortSnifferFilterEvtIoRead;
    ioQueueConfig.EvtIoWrite = PortSnifferFilterEvtIoWrite;

    // Ensure that all callback routines are run at IRQL == PASSIVE_LEVEL as we are dealing with paged-pool memory there.
    WDF_OBJECT_ATTRIBUTES_INIT(&ioQueueAttributes);
    ioQueueAttributes.ExecutionLevel = WdfExecutionLevelPassive;

    // Set up an I/O Queue to handle requests to our filter device.
    status = WdfIoQueueCreate(device, &ioQueueConfig, &ioQueueAttributes, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfIoQueueCreate failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    // Add it to the collection of all our active filter devices.
    WdfWaitLockAcquire(FilterDevicesLock, NULL);
    status = WdfCollectionAdd(FilterDevices, device);
    count = WdfCollectionGetCount(FilterDevices);
    WdfWaitLockRelease(FilterDevicesLock);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfCollectionAdd failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    // Create our control device if this is the first port.
    if (count == 1)
    {
        status = PortSnifferControlCreate(Driver);
        if (!NT_SUCCESS(status))
        {
            KdPrint(("PortSnifferControlCreate failed, status = 0x%08lX\n", status));
            goto Cleanup;
        }
    }

    status = STATUS_SUCCESS;

Cleanup:
    if (regKey != WDF_NO_HANDLE)
    {
        WdfRegistryClose(regKey);
    }

    return status;
}

void
PortSnifferFilterEvtDeviceCleanup(
    WDFDEVICE Device
    )
{
    ULONG count;

    PAGED_CODE();
    KdPrint(("PortSnifferFilterEvtDeviceCleanup(%p)\n", Device));

    WdfWaitLockAcquire(FilterDevicesLock, NULL);
    count = WdfCollectionGetCount(FilterDevices);

    // Delete our control device if this is the last port.
    if (count == 1)
    {
        KdPrint(("Deleting the control device.\n"));
        WdfObjectDelete(ControlDevice);
        ControlDevice = NULL;
    }

    // Delete our filter device from the collection.
    WdfCollectionRemove(FilterDevices, Device);
    WdfWaitLockRelease(FilterDevicesLock);
}

__drv_functionClass(EVT_WDF_IO_QUEUE_IO_READ)
__drv_sameIRQL
__drv_maxIRQL(DISPATCH_LEVEL)
void
PortSnifferFilterEvtIoRead(
    __in WDFQUEUE Queue,
    __in WDFREQUEST Request,
    __in size_t Length
    )
{
    WDFDEVICE device;
    PFILTER_CONTEXT filterContext;
    WDFMEMORY outputMemory;
    WDF_REQUEST_SEND_OPTIONS sendOptions;
    BOOLEAN sendResult;
    NTSTATUS status;
    WDFIOTARGET target;

    UNREFERENCED_PARAMETER(Length);

    PAGED_CODE();
    KdPrint(("PortSnifferFilterEvtIoRead(%p, %p, %Iu)\n", Queue, Request, Length));

    device = WdfIoQueueGetDevice(Queue);
    filterContext = GetFilterContext(device);
    target = WdfDeviceGetIoTarget(device);
    WdfRequestFormatRequestUsingCurrentType(Request);

    if (filterContext->MonitorMask & PORTSNIFFER_MONITOR_READ)
    {
        // We monitor read requests for this port.
        // As an upper filter driver, we have to wait until lower drivers have filled the read buffer.
        status = WdfRequestRetrieveOutputMemory(Request, &outputMemory);
        if (!NT_SUCCESS(status))
        {
            KdPrint(("WdfRequestRetrieveOutputMemory failed, status = 0x%08lX\n", status));
            WdfRequestComplete(Request, status);
            return;
        }

        status = WdfIoTargetFormatRequestForRead(target, Request, outputMemory, NULL, NULL);
        if (!NT_SUCCESS(status))
        {
            KdPrint(("WdfIoTargetFormatRequestForRead failed, status = 0x%08lX\n", status));
            WdfRequestComplete(Request, status);
            return;
        }

        WdfRequestSetCompletionRoutine(Request, PortSnifferFilterEvtIoReadCompletionRoutine, filterContext);
        sendResult = WdfRequestSend(Request, target, WDF_NO_SEND_OPTIONS);
    }
    else
    {
        // We don't monitor read requests for this port.
        // Forward the request and we're done.
        WDF_REQUEST_SEND_OPTIONS_INIT(&sendOptions, WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);
        sendResult = WdfRequestSend(Request, target, &sendOptions);
    }

    if (!sendResult)
    {
        status = WdfRequestGetStatus(Request);
        KdPrint(("WdfRequestSend failed, status = 0x%08lX\n", status));
        WdfRequestComplete(Request, status);
    }
}

void
PortSnifferFilterEvtIoReadCompletionRoutine(
    __in WDFREQUEST Request,
    __in WDFIOTARGET Target,
    __in PWDF_REQUEST_COMPLETION_PARAMS Params,
    __in WDFCONTEXT Context
    )
{
    PFILTER_CONTEXT filterContext;
    PREAD_WORK_ITEM_CONTEXT readWorkItemContext;

    UNREFERENCED_PARAMETER(Target);

    KdPrint(("PortSnifferFilterEvtIoReadCompletionRoutine(%p, %p, %p, %p)\n", Request, Target, Params, Context));

    if (!NT_SUCCESS(Params->IoStatus.Status) || Params->Parameters.Read.Length == 0)
    {
        WdfRequestComplete(Request, Params->IoStatus.Status);
        return;
    }

    // This is a successfully completed read request, which we want to log.
    // As Completion Routines always run at IRQL <= DISPATCH_LEVEL, we need to queue a Work Item to ensure IRQL == PASSIVE_LEVEL
    // and therefore be able to call PortSnifferFilterAddPortLogEntry.
    filterContext = (PFILTER_CONTEXT)Context;
    readWorkItemContext = GetReadWorkItemContext(filterContext->ReadWorkItem);
    readWorkItemContext->Request = Request;
    readWorkItemContext->ReadBuffer = WdfMemoryGetBuffer(Params->Parameters.Read.Buffer, NULL);
    readWorkItemContext->BytesRead = Params->Parameters.Read.Length;
    readWorkItemContext->FilterContext = filterContext;

    WdfWorkItemEnqueue(filterContext->ReadWorkItem);
}

__drv_functionClass(EVT_WDF_WORKITEM)
__drv_sameIRQL
__drv_maxIRQL(PASSIVE_LEVEL)
void
PortSnifferFilterEvtIoReadCompletionWorkItem(
    __in WDFWORKITEM WorkItem
    )
{
    PREAD_WORK_ITEM_CONTEXT readWorkItemContext;

    PAGED_CODE();
    KdPrint(("PortSnifferFilterEvtIoReadCompletionWorkItem(%p)\n", WorkItem));

    // Now that we are running at IRQL == PASSIVE_LEVEL, log the read request and finally complete it.
    readWorkItemContext = GetReadWorkItemContext(WorkItem);
    PortSnifferFilterAddPortLogEntry(readWorkItemContext->FilterContext,
        PORTSNIFFER_MONITOR_READ,
        readWorkItemContext->ReadBuffer,
        readWorkItemContext->BytesRead
    );

    WdfRequestComplete(readWorkItemContext->Request, STATUS_SUCCESS);
}

__drv_functionClass(EVT_WDF_IO_QUEUE_IO_WRITE)
__drv_sameIRQL
__drv_maxIRQL(DISPATCH_LEVEL)
void
PortSnifferFilterEvtIoWrite(
    __in WDFQUEUE Queue,
    __in WDFREQUEST Request,
    __in size_t Length
    )
{
    PUCHAR buffer;
    WDFDEVICE device;
    PFILTER_CONTEXT filterContext;
    size_t length;
    WDF_REQUEST_SEND_OPTIONS sendOptions;
    NTSTATUS status;
    WDFIOTARGET target;

    UNREFERENCED_PARAMETER(Length);

    PAGED_CODE();
    KdPrint(("PortSnifferFilterEvtIoWrite(%p, %p, %Iu)\n", Queue, Request, Length));

    device = WdfIoQueueGetDevice(Queue);
    filterContext = GetFilterContext(device);
    target = WdfDeviceGetIoTarget(device);
    WdfRequestFormatRequestUsingCurrentType(Request);

    if (filterContext->MonitorMask & PORTSNIFFER_MONITOR_WRITE)
    {
        // We monitor read requests for this port.
        // As an upper filter driver, we can just get everything we need from the write buffer.
        status = WdfRequestRetrieveInputBuffer(Request, 0, &buffer, &length);
        if (!NT_SUCCESS(status))
        {
            KdPrint(("WdfRequestRetrieveInputBuffer failed, status = 0x%08lX\n", status));
            WdfRequestComplete(Request, status);
            return;
        }

        PortSnifferFilterAddPortLogEntry(filterContext, PORTSNIFFER_MONITOR_WRITE, buffer, length);
    }

    WDF_REQUEST_SEND_OPTIONS_INIT(&sendOptions, WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);
    if (!WdfRequestSend(Request, target, &sendOptions))
    {
        status = WdfRequestGetStatus(Request);
        KdPrint(("WdfRequestSend failed, status = 0x%08lX\n", status));
        WdfRequestComplete(Request, status);
    }
}
