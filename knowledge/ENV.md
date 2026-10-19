# Cross-Environment Access Control (Environment Segregation)

## Overview

Policy: Cross-Environment Access Control (Environment Segregation).
Purpose: as part of environment security controls (environment segregation), access between system environments is restricted and only permitted in accordance with business needs and applicable provisions, including restrictions on access to the Production environment.
Scope: the request provisions for cross-environment firewall access, split into Server rules (S-1 to S-4) and Workstation rules (W-1 to W-5).
Environments mentioned: Dev, UAT, SIT, Pre-Prod, Prod (server environments), and LAN Campus (workstation).
Related documents: Exception Form (temporary access with justification), Production Data Usage Form (Production data downgrade activities).
General principle: access from any server environment (Dev, UAT, SIT, Pre-Prod, Prod) to a workstation (LAN Campus) is not permitted by default, because the destination is considered an EUC (End User Computing) application. It can only be opened if the specific conditions in Rule W-2 or W-5 are met.
Not specified: any source/destination pair that is not covered by a rule below has no stated provision in this policy.

## Server Rules

### Rule S-1: Non-Production to Non-Production (Dev, UAT, SIT)

Policy: Cross-Environment Access Control. Category: Server.
Source: Dev, UAT, or SIT.
Destination: UAT, SIT, or Dev (access among the Dev, UAT, and SIT environments).
Firewall rule: Can be opened.
Required documents: none stated.
Summary: For servers, firewall access between Dev, UAT, and SIT can be opened without additional documents.

### Rule S-2: Production to Pre-Production (Prod and Pre-Prod)

Policy: Cross-Environment Access Control. Category: Server.
Source: Prod or Pre-Prod.
Destination: Pre-Prod or Prod (access between Prod and Pre-Prod).
Firewall rule: Can be opened.
Required documents: none stated.
Summary: For servers, firewall access between Prod and Pre-Prod can be opened without additional documents.

### Rule S-3: Dev to/from Prod or Pre-Prod

Policy: Cross-Environment Access Control. Category: Server.
Source: Dev, Prod, or Pre-Prod.
Destination: Prod, Pre-Prod, or Dev.
Applicable pairs: Dev to Prod, Dev to Pre-Prod, Prod to Dev, Pre-Prod to Dev (access between Dev and Production-side environments).
Firewall rule: Can be opened if the conditions below are met.
Condition 1: opened temporarily, with a clear justification, and accompanied by an Exception Form document.
Condition 2: if related to Production data downgrade activities, the Production Data Usage Form document must be attached.
Summary: For servers, access between Dev and Prod/Pre-Prod is an exception, not a default. It can be opened if it is temporary, has a clear justification, and is accompanied by an Exception Form, plus the Production Data Usage Form if it involves Production data downgrade.

### Rule S-4: UAT or SIT to/from Prod or Pre-Prod

Policy: Cross-Environment Access Control. Category: Server.
Source: UAT, SIT, Prod, or Pre-Prod.
Destination: Prod, Pre-Prod, UAT, or SIT.
Applicable pairs: UAT to Prod, UAT to Pre-Prod, SIT to Prod, SIT to Pre-Prod, and the reverse directions (access between UAT/SIT and Production-side environments).
Firewall rule: Can be opened if the conditions below are met.
Condition 1: opened temporarily, with a clear justification, and accompanied by an Exception Form document.
Condition 2: if related to Production data downgrade activities, the Production Data Usage Form document must be attached.
Data quality note: the detail of this provision was cut off in the original source image, so additional conditions may exist that are not captured here.
Summary: For servers, access between UAT/SIT and Prod/Pre-Prod follows the same exception conditions as Rule S-3 (temporary, justified, Exception Form, plus Production Data Usage Form for data downgrade), but the source text is incomplete.

## Workstation Rules

### Rule W-1: LAN Campus to Non-Production (Dev, UAT, SIT)

Policy: Cross-Environment Access Control. Category: Workstation.
Source: LAN Campus (workstation).
Destination: Dev, UAT, or SIT (server environment).
Firewall rule: Can be opened.
Required documents: none stated.
Summary: For workstations, access from LAN Campus to Dev, UAT, or SIT can be opened.

### Rule W-2: Non-Production (UAT, SIT, Dev) to LAN Campus

Policy: Cross-Environment Access Control. Category: Workstation.
Source: UAT, SIT, or Dev (server environment).
Destination: LAN Campus (workstation).
Default: not permitted, because the destination is considered an EUC (End User Computing) application.
Firewall rule: Can be opened if [condition not yet defined, to be completed].
Summary: For workstations, access from UAT, SIT, or Dev servers to LAN Campus is not permitted by default (EUC), but can be opened if the stated condition is met.

### Rule W-3: LAN Campus to LAN Campus

Policy: Cross-Environment Access Control. Category: Workstation.
Source: LAN Campus (workstation).
Destination: LAN Campus (workstation).
Default: all access is blocked (default deny).
Firewall rule: Can be opened if there is a need for file transfer (SMB/SFTP).
Summary: For workstations, LAN Campus to LAN Campus is blocked by default and can only be opened if there is a need for file transfer (SMB/SFTP).

### Rule W-4: LAN Campus to Production (Prod, Pre-Prod)

Policy: Cross-Environment Access Control. Category: Workstation.
Source: LAN Campus (workstation).
Destination: Prod or Pre-Prod (server environment).
Firewall rule: Can be opened if the access is for web-based application access, subject to the use of permitted ports.
Summary: For workstations, access from LAN Campus to Prod or Pre-Prod can only be opened for web-based application access over permitted ports.

### Rule W-5: Production (Prod, Pre-Prod) to LAN Campus

Policy: Cross-Environment Access Control. Category: Workstation.
Source: Prod or Pre-Prod (server environment).
Destination: LAN Campus (workstation).
Default: not permitted, because the destination is considered an EUC (End User Computing) application.
Firewall rule: Can be opened if the access is for data downgrade activities and the Production Data Usage Form document is attached.
Summary: For workstations, access from Prod or Pre-Prod servers to LAN Campus is not permitted by default (EUC), but can be opened if it is for data downgrade activities and the Production Data Usage Form is attached.