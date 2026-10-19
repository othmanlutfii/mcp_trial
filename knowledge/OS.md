# OS Version Support Status Mapping

## Overview

Policy: OS Version Support Status Mapping.
Purpose: defines the mapping between operating system versions and their support status, used to determine whether an asset's operating system is under active vendor support or has reached end of support.
Used by: asset_import._calc_os_support(). The canonical machine-readable source is a JSON configuration (OS family > OS version > support status). Edit the source configuration instead of hardcoding values in code.
Support status values: Active Support, End of Support.
OS families covered: macOS, Windows Client, Windows Server, RHEL (Red Hat Enterprise Linux), Oracle Linux, CentOS, Ubuntu, Other (Linux Mint and generic Linux).
Lookup rule: a version is matched by its exact name as listed. A version that is not listed (for example RHEL 9.1 or Ubuntu 18.04) has no stated support status in this mapping and must not be assumed.
Generic entries: "Windows" and "Linux" are generic fallback names listed with the status End of Support.

## Support Status Mapping

### macOS

Policy: OS Version Support Status Mapping. OS family: macOS.
Active Support: Tahoe (26), Sequoia (15), Sonoma (14).
End of Support: Ventura (13), Monterey (12).
Summary: For macOS, versions 26 (Tahoe), 15 (Sequoia), and 14 (Sonoma) are under Active Support. Versions 13 (Ventura) and 12 (Monterey) have reached End of Support.

### Windows Client

Policy: OS Version Support Status Mapping. OS family: Windows Client.
Active Support: Windows 11.
End of Support: Windows 10, Windows 7, Windows (generic entry).
Summary: For Windows Client, only Windows 11 is under Active Support. Windows 10, Windows 7, and the generic "Windows" entry are End of Support.

### Windows Server

Policy: OS Version Support Status Mapping. OS family: Windows Server.
Active Support: Windows Server 2025, Windows Server 2022, Windows Server 2019, Windows Server 2016.
End of Support: Windows Server 2012 R2, Windows Server 2012, Windows Server 2008 R2.
Summary: For Windows Server, versions 2016, 2019, 2022, and 2025 are under Active Support. Versions 2012, 2012 R2, and 2008 R2 have reached End of Support.

### RHEL (Red Hat Enterprise Linux)

Policy: OS Version Support Status Mapping. OS family: RHEL (Red Hat Enterprise Linux).
Active Support: RHEL 10.0, RHEL 9.6, RHEL 9.5, RHEL 9.4, RHEL 8.10.
End of Support (RHEL 9): RHEL 9.3, RHEL 9.0.
End of Support (RHEL 8): RHEL 8.9, 8.8, 8.7, 8.6, 8.5, 8.4, 8.3, 8.2, 8.1.
End of Support (RHEL 7): RHEL 7.9, 7.8, 7.7, 7.6, 7.5, 7.4, 7.2.
End of Support (RHEL 6): RHEL 6.6, 6.4, 6.3, 6.1.
Summary: For RHEL, Active Support applies only to 10.0, 9.6, 9.5, 9.4, and 8.10. All other listed versions (9.3, 9.0, 8.1 to 8.9, all listed 7.x and 6.x) are End of Support.

### Oracle Linux

Policy: OS Version Support Status Mapping. OS family: Oracle Linux.
Active Support: Oracle Linux 9.6, 9.5, 9.4, 8.10.
End of Support: Oracle Linux 8.9, 8.8, 8.6, 7.7, 6.10, 6.9.
Summary: For Oracle Linux, Active Support applies only to 9.6, 9.5, 9.4, and 8.10. Versions 8.9, 8.8, 8.6, 7.7, 6.10, and 6.9 are End of Support.

### CentOS

Policy: OS Version Support Status Mapping. OS family: CentOS.
Active Support: none listed.
End of Support: CentOS Stream 8, CentOS 8.5, 8.3, 8.2, 7.9, 7.8, 7.7, 7.6, 7.5, 7.4, 7.3, 7.2, 7.0, 6.10, 6.9, 6.8, 6.7, 6.5.
Summary: For CentOS, every listed version (CentOS Stream 8 and all listed 8.x, 7.x, and 6.x releases) is End of Support. No CentOS version is under Active Support.

### Ubuntu

Policy: OS Version Support Status Mapping. OS family: Ubuntu.
Active Support: Ubuntu 24.04, Ubuntu 22.04.
End of Support: Ubuntu 20.04, Ubuntu 16.04.
Summary: For Ubuntu, versions 24.04 and 22.04 are under Active Support. Versions 20.04 and 16.04 have reached End of Support.

### Other

Policy: OS Version Support Status Mapping. OS family: Other.
Active Support: Linux Mint 21.
End of Support: Linux (generic entry).
Summary: Linux Mint 21 is under Active Support. The generic "Linux" entry is End of Support.