//
// PortSniffer - Monitor the traffic of arbitrary serial or parallel ports
// Copyright 2020 Colin Finck, ENLYZE GmbH <c.finck@enlyze.com>
//
// SPDX-License-Identifier: MIT
//

#pragma once

// Make sure to change at least the minor version with every incompatible change!
#define PORTSNIFFER_MAJOR_VERSION       1
#define PORTSNIFFER_MINOR_VERSION       0

// The following two lines of macro magic turn arbitrary preprocessor constants into strings.
#define STRINGIFY_INTERNAL(x)           #x
#define STRINGIFY(x)                    STRINGIFY_INTERNAL(x)

#define PORTSNIFFER_REVISION_STRING     "unknown revision"
#define PORTSNIFFER_VERSION_COMBINED    STRINGIFY(PORTSNIFFER_MAJOR_VERSION) "." STRINGIFY(PORTSNIFFER_MINOR_VERSION) " (" PORTSNIFFER_REVISION_STRING ")"















