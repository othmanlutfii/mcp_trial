# Cross-Environment Access Control (Environment Segregation)

## Overview

Policy: Cross-Environment Access Control (Environment Segregation).
Purpose: as part of environment security controls (environment segregation), access between system environments is restricted and only permitted in accordance with business needs and applicable provisions, including restrictions on access to the Production environment.
Scope: the request provisions for cross-environment firewall access, split into Server rules (S-1 to S-4) and Workstation rules (W-1 to W-5).
Environments mentioned: Dev, UAT, SIT, Pre-Prod, Prod (server environments), and LAN Campus (workstation).
Related documents: Exception Form (temporary access with justification), Production Data Usage Form (Production data downgrade activities).
General principle 1: server-to-server access across different environments is not permitted by default. It is allowed only for the environment pairs explicitly listed in Rules S-1 to S-4; S-3 and S-4 require the stated exception conditions.
General principle 2: access from any server environment (Dev, UAT, SIT, Pre-Prod, Prod) to a workstation (LAN Campus) is not permitted by default, because the destination is considered an EUC (End User Computing) application. It can only be opened if the specific conditions in Rule W-2 or W-5 are met.
General principle 3: PC/LAN administrative access to PROD or PRE-PROD servers using SSH or database ports must not connect directly to the target server. Use the approved PAM access flow: connect to the PAM service through its approved client/web interface, then initiate the SSH/database session from the PAM server to the production target. The two network connections must be assessed and authorized separately.
General principle 4: SFTP from LAN to PROD/PRE-PROD on port 22 or an explicitly identified custom SFTP port has a requester-category exception under Rule W-4. Non-SKTI requesters may request direct SFTP access, subject to the applicable port, segment, and approval checks. SKTI requesters must use the approved PAM flow. This exception is limited to SFTP and does not permit direct SSH or database access.
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
Firewall rule: Can be opened, subject to the applicable port provisions in PORT.md.
Port examples: direct PC/LAN access to non-production servers is permitted for SSH (port 22) under Rule P-4 and database ports under Rule P-7.
Required documents: none stated.
Summary: For workstations, access from LAN Campus to Dev, UAT, or SIT can be opened using ports permitted by PORT.md. Direct SSH and database access from PC/LAN to non-production servers is permitted under Rules P-4 and P-7.

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
Firewall rule: Can be opened directly only for web-based application access, using HTTPS/preferred secure ports permitted by PORT.md.
SFTP exception: for the SFTP service on port 22 or an explicitly identified custom SFTP port, a non-SKTI requester may request direct LAN-to-production-server access, subject to the applicable port, segment, and approval checks. An SKTI requester must use the approved PAM flow. Confirm the requester category; if it is unavailable or unclear, do not assume the direct-access exception applies and send the request for review.
Other administrative access: direct PC/LAN connections to production servers for SSH (not SFTP) or database ports are not permitted. Use the approved PAM access flow: PC/LAN to the PAM service through its approved client/web interface, then a separate PAM-server-to-production-server connection for SSH/database access under Rules P-4 and P-7.
Required review: assess and authorize each network leg separately. The PC/LAN-to-PAM connection must use an approved PAM access port; the PAM-to-production-server connection must comply with the applicable segment and environment rules.
Summary: For workstations, direct access from LAN Campus to Prod or Pre-Prod is limited to web-based application access on permitted secure ports, with a specific SFTP exception: non-SKTI requesters may request direct SFTP on port 22 or an identified custom SFTP port, while SKTI requesters must use PAM. Other direct SSH and database access remains blocked and must use PAM. If requester category is unknown, review it rather than assuming an exception.

### Rule W-5: Production (Prod, Pre-Prod) to LAN Campus

Policy: Cross-Environment Access Control. Category: Workstation.
Source: Prod or Pre-Prod (server environment).
Destination: LAN Campus (workstation).
Default: not permitted, because the destination is considered an EUC (End User Computing) application.
Firewall rule: Can be opened if the access is for data downgrade activities and the Production Data Usage Form document is attached.
Summary: For workstations, access from Prod or Pre-Prod servers to LAN Campus is not permitted by default (EUC), but can be opened if it is for data downgrade activities and the Production Data Usage Form is attached.