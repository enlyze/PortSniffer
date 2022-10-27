# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (without a PATCH version).


## [2.1] - 2022-10-27
- Fixed clean uninstallation and incompatibility to Windows 10 by requiring a reboot after uninstallation (#10)
- Added verifying driver and tool versions before monitoring (#10)  
  This prevents surprising and mostly invalid results when an incompatible PortSniffer driver is installed.
- Added a CI based on GitHub Actions to reproducibly build the driver binaries (#11)
- Disabled buffering of stdout (#12)  
  This allows for live monitoring under all circumstances without delays.

## [2.0] - 2022-10-20
- Added recording and printing a timestamp with every log entry (#8)
- Added printing a table header (#8)
- Added optional monitoring of interesting `IOCTL_SERIAL_*` requests (#9)  
  This also adds a `C` type to `PortSniffer-Tool /monitor`.

## [1.4] - 2021-08-13
- Fixed logging when reads and writes come in simultaneously (#4)

## [1.3] - 2021-07-08
- Fixed logging partial reads and don't log unsuccessful reads at all

## [1.2] - 2021-05-28
- Fixed handling the worst case of 1-byte requests at 115200 baud
- Improved error messages in PortSniffer-Tool

## [1.1] - 2020-10-19
- PortSniffer-Tool: Fixed recreating the driver service when reinstalling via `/install` (without calling `/uninstall` first)
- PortSniffer-Tool: Changed to return distinct status codes when succeeded, but with a reboot required

## [1.0] - 2020-10-19
- Initial release
