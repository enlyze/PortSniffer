//
// PortSniffer - Monitor the traffic of arbitrary serial or parallel ports
// Copyright 2020 Colin Finck, ENLYZE GmbH <c.finck@enlyze.com>
//
// SPDX-License-Identifier: MIT
//

#include "PortSniffer-Tool.h"

typedef ULONG (*WDFPREDEVICEINSTALLEX)(LPCWSTR InfPath, LPCWSTR InfSectionName, PWDF_COINSTALLER_INSTALL_OPTIONS ClientOptions);
typedef ULONG (*WDFPREDEVICEREMOVE)(LPCWSTR InfPath, LPCWSTR InfSectionName);
typedef ULONG (*WDFPOSTDEVICEINSTALL)(LPCWSTR InfPath, LPCWSTR InfSectionName);
typedef ULONG (*WDFPOSTDEVICEREMOVE)(LPCWSTR InfPath, LPCWSTR InfSectionName);

static const char _szInfContent[] =
    "[Version]\n"
    "Signature = \"$Windows NT$\"\n"
    "[EnlyzePortSniffer.NT.Wdf]\n"
    "KmdfService = EnlyzePortSniffer, EnlyzePortSniffer_Service_kmdfInst\n"
    "[EnlyzePortSniffer_Service_kmdfInst]\n"
    "KmdfLibraryVersion = 1.9";
static const WCHAR _wszCoInstallerFile[] = L"\\WdfCoInstaller01009.dll";
static const WCHAR _wszDriverDestinationPath[] = L"%SystemRoot%\\system32\\drivers\\EnlyzePortSniffer.sys";
static const WCHAR _wszDriverFile[] = L"\\EnlyzePortSniffer.sys";
static const WCHAR _wszInfFile[] = L"\\EnlyzePortSniffer.inf";
static const WCHAR _wszInfSectionName[] = L"EnlyzePortSniffer.NT.Wdf";
static const WCHAR _wszServiceName[] = L"EnlyzePortSniffer";


static BOOL
_CreateInf(
    __in PCWSTR pwszCurrentDirectory,
    __out_ecount(MAX_PATH) PWSTR pwszInfPath
    )
{
    BOOL bReturnValue = FALSE;
    DWORD cbWritten;
    HANDLE hFile = NULL;

    if (FAILED(StringCchCopyW(pwszInfPath, MAX_PATH, pwszCurrentDirectory))
        || FAILED(StringCchCatW(pwszInfPath, MAX_PATH, _wszInfFile)))
    {
        fprintf(stderr, "Could not build path to .inf file!\n");
        goto Cleanup;
    }

    hFile = CreateFileW(pwszInfPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "Could not create \"%S\", last error is %lu.\n", pwszInfPath, GetLastError());
        goto Cleanup;
    }

    if (!WriteFile(hFile, _szInfContent, sizeof(_szInfContent) - 1, &cbWritten, NULL))
    {
        fprintf(stderr, "Could not write to \"%S\", last error is %lu.\n", pwszInfPath, GetLastError());
        goto Cleanup;
    }

    bReturnValue = TRUE;

Cleanup:
    if (hFile)
    {
        CloseHandle(hFile);
    }

    return bReturnValue;
}

static BOOL
_DetachFromAllPorts(void)
{
    BOOL bReturnValue = FALSE;
    HANDLE hPortSniffer;
    PCWSTR p;
    PPORTSNIFFER_GET_ATTACHED_PORTS_RESPONSE pResponse = NULL;

    // Connect to our driver.
    hPortSniffer = OpenPortSniffer();
    if (hPortSniffer == INVALID_HANDLE_VALUE)
    {
        // Our driver is not running, so it's not attached to any ports.
        bReturnValue = TRUE;
        goto Cleanup;
    }

    // Ask it for all attached ports.
    pResponse = GetAttachedPorts(hPortSniffer);
    if (!pResponse)
    {
        goto Cleanup;
    }

    // Detach from the ports we got.
    for (p = pResponse->PortNames; *p; p += wcslen(pResponse->PortNames) + 1)
    {
        if (EnumMonitorablePorts(DetachPortCallback, p) != 0)
        {
            goto Cleanup;
        }
    }

    bReturnValue = TRUE;

Cleanup:
    if (pResponse)
    {
        HeapFree(GetProcessHeap(), 0, pResponse);
    }

    if (hPortSniffer != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hPortSniffer);
    }

    return bReturnValue;
}

static BOOL
_GetDriverDestinationPath(
    __out_ecount(MAX_PATH) PWSTR pwszPath
    )
{
    DWORD cchExpanded;

    cchExpanded = ExpandEnvironmentStringsW(_wszDriverDestinationPath, pwszPath, MAX_PATH);
    if (cchExpanded == 0 || cchExpanded > MAX_PATH)
    {
        fprintf(stderr, "ExpandEnvironmentStringsW failed, last error is %lu.\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

static HANDLE
_LoadWdfCoInstaller(
    __in PCWSTR pwszCurrentDirectory
    )
{
    HANDLE hCoInstaller;
    WCHAR wszCoInstallerPath[MAX_PATH];

    if (FAILED(StringCchCopyW(wszCoInstallerPath, MAX_PATH, pwszCurrentDirectory))
        || FAILED(StringCchCatW(wszCoInstallerPath, MAX_PATH, _wszCoInstallerFile)))
    {
        fprintf(stderr, "Could not build path to CoInstaller!\n");
        return NULL;
    }

    hCoInstaller = LoadLibraryW(wszCoInstallerPath);
    if (hCoInstaller == NULL)
    {
        fprintf(stderr, "Could not load \"%S\", last error is %lu.\n", wszCoInstallerPath, GetLastError());
        return NULL;
    }

    return hCoInstaller;
}

int
CheckInstallation(void)
{
    HANDLE hSC = NULL;
    HANDLE hService = NULL;
    int iReturnValue = 1;
    WCHAR wszDriverDestinationPath[MAX_PATH];

    // Check whether the driver file exists.
    if (!_GetDriverDestinationPath(wszDriverDestinationPath))
    {
        goto Cleanup;
    }

    if (GetFileAttributesW(wszDriverDestinationPath) == INVALID_FILE_ATTRIBUTES)
    {
        fprintf(stderr, "The PortSniffer Driver is not installed!\n");
        fprintf(stderr, "Please run this tool using the /install option.\n");
        goto Cleanup;
    }

    // Check whether the driver service exists.
    hSC = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSC)
    {
        fprintf(stderr, "OpenSCManagerW failed, last error is %lu.\n", GetLastError());
        goto Cleanup;
    }

    hService = OpenServiceW(hSC, _wszServiceName, SERVICE_QUERY_STATUS);
    if (!hService)
    {
        fprintf(stderr, "The PortSniffer Driver service is not installed!\n");
        fprintf(stderr, "Please run this tool using the /install option.\n");
        goto Cleanup;
    }

    iReturnValue = 0;

Cleanup:
    if (hService)
    {
        CloseServiceHandle(hService);
    }

    if (hSC)
    {
        CloseServiceHandle(hSC);
    }

    return iReturnValue;
}

int
HandleInstallParameter(void)
{
    WDF_COINSTALLER_INSTALL_OPTIONS clientOptions;
    HANDLE hCoInstaller;
    HANDLE hSC = NULL;
    HANDLE hService = NULL;
    ULONG installStatus;
    int iReturnValue = 1;
    WDFPREDEVICEINSTALLEX pfnWdfPreDeviceInstallEx;
    WDFPOSTDEVICEINSTALL pfnWdfPostDeviceInstall;
    WCHAR wszCurrentDirectory[MAX_PATH];
    WCHAR wszDriverDestinationPath[MAX_PATH];
    WCHAR wszDriverSourcePath[MAX_PATH];
    WCHAR wszInfPath[MAX_PATH] = { 0 };

    // Get the current directory.
    if (GetCurrentDirectoryW(MAX_PATH, wszCurrentDirectory) == 0)
    {
        fprintf(stderr, "GetCurrentDirectoryW failed, last error is %lu.\n", GetLastError());
        goto Cleanup;
    }

    // Try to load the WDF CoInstaller.
    hCoInstaller = _LoadWdfCoInstaller(wszCurrentDirectory);
    if (hCoInstaller == NULL)
    {
        goto Cleanup;
    }

    pfnWdfPreDeviceInstallEx = (WDFPREDEVICEINSTALLEX)GetProcAddress(hCoInstaller, "WdfPreDeviceInstallEx");
    pfnWdfPostDeviceInstall = (WDFPOSTDEVICEINSTALL)GetProcAddress(hCoInstaller, "WdfPostDeviceInstall");
    if (!pfnWdfPreDeviceInstallEx || !pfnWdfPostDeviceInstall)
    {
        fprintf(stderr, "Could not load WdfPreDeviceInstallEx or WdfPostDeviceInstall, last error is %lu.\n", GetLastError());
        goto Cleanup;
    }

    // Create the .inf file.
    if (!_CreateInf(wszCurrentDirectory, wszInfPath))
    {
        goto Cleanup;
    }

    // Run the CoInstaller's pre-installation steps.
    WDF_COINSTALLER_INSTALL_OPTIONS_INIT(&clientOptions);
    installStatus = pfnWdfPreDeviceInstallEx(wszInfPath, _wszInfSectionName, &clientOptions);
    if (installStatus == ERROR_SUCCESS_REBOOT_REQUIRED)
    {
        printf("A reboot is required to complete the installation of WDF components.\n");
        printf("Please rerun this installation afterwards.\n");
        iReturnValue = ERROR_SUCCESS_REBOOT_REQUIRED;
        goto Cleanup;
    }
    else if (installStatus != ERROR_SUCCESS)
    {
        fprintf(stderr, "WdfPreDeviceInstallEx failed with status %lu.\n", installStatus);
        goto Cleanup;
    }

    // Copy the driver.
    if (FAILED(StringCchCopyW(wszDriverSourcePath, MAX_PATH, wszCurrentDirectory))
        || FAILED(StringCchCatW(wszDriverSourcePath, MAX_PATH, _wszDriverFile)))
    {
        fprintf(stderr, "Could not build path to .sys file!\n");
        goto Cleanup;
    }

    if (!_GetDriverDestinationPath(wszDriverDestinationPath))
    {
        goto Cleanup;
    }

    if (!CopyFileW(wszDriverSourcePath, wszDriverDestinationPath, FALSE))
    {
        fprintf(stderr, "CopyFileW failed, last error is %lu.\n", GetLastError());
        goto Cleanup;
    }

    // (Re)create the driver service.
    hSC = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSC == NULL)
    {
        fprintf(stderr, "OpenSCManagerW failed, last error is %lu.\n", GetLastError());
        goto Cleanup;
    }

    hService = OpenServiceW(hSC, _wszServiceName, SERVICE_ALL_ACCESS);
    if (hService)
    {
        if (!DeleteService(hService))
        {
            fprintf(stderr, "DeleteService failed, last error is %lu.\n", GetLastError());
            goto Cleanup;
        }

        CloseServiceHandle(hService);
    }

    hService = CreateServiceW(hSC,
        _wszServiceName,
        _wszServiceName,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        wszDriverDestinationPath,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);
    if (hService == NULL)
    {
        fprintf(stderr, "CreateServiceW failed, last error is %lu.\n", GetLastError());
        goto Cleanup;
    }

    // Run the CoInstaller's post-installation steps.
    installStatus = pfnWdfPostDeviceInstall(wszInfPath, _wszInfSectionName);
    if (installStatus != ERROR_SUCCESS)
    {
        fprintf(stderr, "WdfPostDeviceInstall failed with status %lu.\n", installStatus);
        goto Cleanup;
    }

    printf("The PortSniffer Driver has been installed successfully!\n");
    iReturnValue = 0;

Cleanup:
    if (hService)
    {
        CloseServiceHandle(hService);
    }

    if (hSC)
    {
        CloseServiceHandle(hSC);
    }

    if (*wszInfPath)
    {
        // Try to delete the .inf file.
        // Failure to do so doesn't matter here.
        DeleteFileW(wszInfPath);
    }

    return iReturnValue;
}

int
HandleUninstallParameter(void)
{
    HANDLE hCoInstaller;
    HANDLE hSC = NULL;
    HANDLE hService = NULL;
    ULONG installStatus;
    int iReturnValue = 1;
    WDFPREDEVICEREMOVE pfnWdfPreDeviceRemove;
    WDFPOSTDEVICEREMOVE pfnWdfPostDeviceRemove;
    WCHAR wszCurrentDirectory[MAX_PATH];
    WCHAR wszDriverDestinationPath[MAX_PATH];
    WCHAR wszInfPath[MAX_PATH] = { 0 };

    // Detach from all ports first.
    if (!_DetachFromAllPorts())
    {
        goto Cleanup;
    }

    // Get the current directory.
    if (GetCurrentDirectoryW(MAX_PATH, wszCurrentDirectory) == 0)
    {
        fprintf(stderr, "GetCurrentDirectoryW failed, last error is %lu.\n", GetLastError());
        goto Cleanup;
    }

    // Try to load the WDF CoInstaller.
    hCoInstaller = _LoadWdfCoInstaller(wszCurrentDirectory);
    if (hCoInstaller == NULL)
    {
        goto Cleanup;
    }

    pfnWdfPreDeviceRemove = (WDFPREDEVICEREMOVE)GetProcAddress(hCoInstaller, "WdfPreDeviceRemove");
    pfnWdfPostDeviceRemove = (WDFPOSTDEVICEREMOVE)GetProcAddress(hCoInstaller, "WdfPostDeviceRemove");
    if (!pfnWdfPreDeviceRemove || !pfnWdfPostDeviceRemove)
    {
        fprintf(stderr, "Could not load WdfPreDeviceRemove or WdfPostDeviceRemove, last error is %lu.\n", GetLastError());
        goto Cleanup;
    }

    // Create the .inf file.
    if (!_CreateInf(wszCurrentDirectory, wszInfPath))
    {
        goto Cleanup;
    }

    // Run the CoInstaller's pre-removal steps.
    installStatus = pfnWdfPreDeviceRemove(wszInfPath, _wszInfSectionName);
    if (installStatus != ERROR_SUCCESS)
    {
        fprintf(stderr, "WdfPreDeviceRemove failed with status %lu.\n", installStatus);
        goto Cleanup;
    }

    // Delete the driver service.
    hSC = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSC == NULL)
    {
        fprintf(stderr, "OpenSCManagerW failed, last error is %lu.\n", GetLastError());
        goto Cleanup;
    }

    hService = OpenServiceW(hSC, _wszServiceName, SERVICE_ALL_ACCESS);
    if (hService == NULL)
    {
        fprintf(stderr, "OpenServiceW failed, last error is %lu.\n", GetLastError());
        goto Cleanup;
    }

    if (!DeleteService(hService))
    {
        fprintf(stderr, "DeleteService failed, last error is %lu.\n", GetLastError());
        goto Cleanup;
    }

    CloseServiceHandle(hService);
    hService = NULL;

    // Delete the driver.
    if (!_GetDriverDestinationPath(wszDriverDestinationPath))
    {
        goto Cleanup;
    }

    if (!DeleteFileW(wszDriverDestinationPath))
    {
        fprintf(stderr, "DeleteFileW failed, last error is %lu.\n", GetLastError());
        goto Cleanup;
    }

    // Run the CoInstaller's post-removal steps.
    installStatus = pfnWdfPostDeviceRemove(wszInfPath, _wszInfSectionName);
    if (installStatus != ERROR_SUCCESS)
    {
        fprintf(stderr, "WdfPostDeviceRemove failed with status %lu.\n", installStatus);
        goto Cleanup;
    }

    printf("The PortSniffer Driver has been uninstalled successfully!\n");
    iReturnValue = 0;

Cleanup:
    if (hService)
    {
        CloseServiceHandle(hService);
    }

    if (hSC)
    {
        CloseServiceHandle(hSC);
    }

    if (*wszInfPath)
    {
        // Try to delete the .inf file.
        // Failure to do so doesn't matter here.
        DeleteFileW(wszInfPath);
    }

    return iReturnValue;
}
