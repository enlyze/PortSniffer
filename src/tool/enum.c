//
// PortSniffer - Monitor the traffic of arbitrary serial or parallel ports
// Copyright 2020 Colin Finck, ENLYZE GmbH <c.finck@enlyze.com>
//
// SPDX-License-Identifier: MIT
//

#include "PortSniffer-Tool.h"

static const GUID* _MonitorableGuids[] = {
    &GUID_DEVINTERFACE_COMPORT,
    &GUID_DEVINTERFACE_PARALLEL
};


int
EnumMonitorablePorts(
    __in ENUMMONITORABLEPORTSCALLBACK Callback,
    __in_opt PCWSTR pwszPortNameToFind
    )
{
    BOOL bContinue = TRUE;
    DWORD cbPortName;
    SP_DEVINFO_DATA devInfoData;
    DWORD dwDeviceIndex;
    DWORD dwGuidIndex;
    DWORD dwType;
    HDEVINFO hDevInfo;
    HKEY hKey;
    int iReturnValue = ERROR_FILE_NOT_FOUND;
    LSTATUS lStatus;
    WCHAR wszPortName[PORTSNIFFER_PORTNAME_LENGTH];

    // Iterate over all legacy port GUIDs.
    for (dwGuidIndex = 0; dwGuidIndex < sizeof(_MonitorableGuids) / sizeof(_MonitorableGuids[0]); dwGuidIndex++)
    {
        // Get a handle to this GUID's device information.
        hDevInfo = SetupDiGetClassDevsW(_MonitorableGuids[dwGuidIndex], NULL, NULL, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT | DIGCF_PROFILE);
        if (hDevInfo == INVALID_HANDLE_VALUE)
        {
            continue;
        }

        // Iterate over all devices of this GUID.
        devInfoData.cbSize = sizeof(devInfoData);
        for (dwDeviceIndex = 0; SetupDiEnumDeviceInfo(hDevInfo, dwDeviceIndex, &devInfoData); dwDeviceIndex++)
        {
            // Open the per-device hardware information registry key for this device.
            hKey = SetupDiOpenDevRegKey(hDevInfo, &devInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_QUERY_VALUE);
            if (hKey == NULL)
            {
                continue;
            }

            // Get the port name.
            cbPortName = sizeof(wszPortName);
            lStatus = RegQueryValueExW(hKey, L"PortName", NULL, &dwType, (LPBYTE)wszPortName, &cbPortName);
            RegCloseKey(hKey);

            if (lStatus != ERROR_SUCCESS)
            {
                continue;
            }

            if (dwType != REG_SZ)
            {
                continue;
            }

            // Shall we filter per port name?
            if (pwszPortNameToFind)
            {
                if (wcscmp(wszPortName, pwszPortNameToFind) == 0)
                {
                    // We have found the one and only port the caller is interested in.
                    // Call the callback function for this port and stop searching.
                    iReturnValue = Callback(wszPortName, hDevInfo, &devInfoData);
                    bContinue = FALSE;
                    break;
                }
            }
            else
            {
                // No filter -> call the callback function for each port.
                iReturnValue = Callback(wszPortName, hDevInfo, &devInfoData);
            }
        }

        SetupDiDestroyDeviceInfoList(hDevInfo);
        if (!bContinue)
        {
            break;
        }
    }

    return iReturnValue;
}
