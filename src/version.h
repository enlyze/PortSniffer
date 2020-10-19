//
// PortSniffer - Monitor the traffic of arbitrary serial or parallel ports
// Copyright 2020 Colin Finck, ENLYZE GmbH <c.finck@enlyze.com>
//
// SPDX-License-Identifier: MIT
//

#pragma once

// We use Semantic Versioning (https://semver.org) without a patch version here.
// Increase the major version on API-incompatible changes, increase the minor version on API-compatible changes.
#define PORTSNIFFER_MAJOR_VERSION       1
#define PORTSNIFFER_MINOR_VERSION       1

// The following two lines of macro magic turn arbitrary preprocessor constants into strings.
#define STRINGIFY_INTERNAL(x)           #x
#define STRINGIFY(x)                    STRINGIFY_INTERNAL(x)

#define PORTSNIFFER_REVISION_STRING     "unknown revision"
#define PORTSNIFFER_VERSION_COMBINED    STRINGIFY(PORTSNIFFER_MAJOR_VERSION) "." STRINGIFY(PORTSNIFFER_MINOR_VERSION) " (" PORTSNIFFER_REVISION_STRING ")"
