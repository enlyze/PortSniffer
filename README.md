<img width="150" align="right" src="img/PortSniffer.svg" />

# ENLYZE PortSniffer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An open-source driver and tool to monitor the traffic between applications and arbitrary serial or parallel ports.  
Compatible with Windows XP or later (32-bit and 64-bit).

## Comparison with Sysinternals Portmon
ENLYZE PortSniffer has been inspired by the [Sysinternals Portmon](https://docs.microsoft.com/en-us/sysinternals/downloads/portmon) tool, but has several distinct differences:

**Advantages**
* Based on the modern Kernel-Mode Driver Framework (KMDF) instead of the legacy NT4 driver model, thereby correctly reacting to Plug&Play events concerning serial/parallel ports.
* Compatible with 64-bit Windows versions.
* The freely available source code under the permissive MIT license and a documented public interface allow easy integration into an own application.

**Disadvantages**
* Comes with only a simple CLI application instead of a feature-rich GUI.

## How to build
1. Install the [Windows Driver Kit 7.1.0](https://www.microsoft.com/en-us/download/details.aspx?id=11800).
2. Open the WDK Build Environment for the minimum Windows version you want to support, your desired architecture, and the debug level.
   I use _Windows XP x86 Free Build Environment_ and _Windows Server 2003 x64 Free Build Environment_ for release versions.
3. Move to the root directory of your Git checkout and call `build_all`.

The `build_on_ci.ps1` PowerShell script automates the building of release binaries with precise version information.
It is currently unused, because I haven't found a public CI system with WDK 7.1.0 yet.

## Goals
All bug reports and pull requests improving the driver and tool quality are very welcome!  
The code has been written to follow all known best practices and coding style guidelines for Windows driver development.
It currently builds with zero compiler and PREfast warnings, and shall continue to do so.

As of now, there are no plans to add a GUI.
Due to the documented public interface, a GUI could very well be developed as a separate project outside the PortSniffer repository.
If somebody wants to do that, this is the recommended approach, as it would also free you from the limitations of the WDK 7.1.0 Build Environment.

There are also no plans to move away from WDK 7.1.0, because the driver shall remain compatible with Windows XP.

## Driver Signature
Currently, the published driver binaries are unsigned and therefore only work when disabling Driver Signature Enforcement under 64-bit Windows versions.
If you don't do that, ports will fail with a _Windows cannot verify the digital signature ... (Code 52)_ error in Device Manager after attaching the PortSniffer to them.

To temporarily disable Driver Signature Enforcement when booting Windows:

1. Press F8 continuously during boot to let the Advanced Boot Options screen appear.
   You can also directly boot into it via `shutdown /r /o`.

2. For Windows 7, you just have to choose _Disable Driver Signature Enforcement_ and you can continue booting.  
   For Windows 8 or 10, click Troubleshoot -> Advanced options -> Startup Settings and press 7 to _Disable driver signature enforcement_.

I'm not aware of any permanent solution to disable Driver Signature Enforcement.
Enabling the infamous _Test Mode_ in the bootloader is not sufficient -- at least not for a filter driver like the PortSniffer.

Future versions of the PortSniffer binaries may come with a signature.
However, [Microsoft has recently been changing their driver signing policies](https://www.osr.com/blog/2021/04/08/lost-cause-no-driver-updates-allowed-except-for-win-10/) and I'm currently not aware of a solution that works equally well for all Windows versions down to Windows 7.

Note that 32-bit operating systems are not affected by this Windows limitation.
They accept unsigned drivers just fine.

## Contact
Colin Finck ([c.finck@enlyze.com](mailto:c.finck@enlyze.com))
