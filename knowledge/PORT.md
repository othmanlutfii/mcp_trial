# Port and Protocol Security Policy

## Overview

Policy: Port and Protocol Security Policy.
Purpose: as part of the security hardening process, not all ports or protocols may be freely used. The ports below are not permitted to be opened, or may only be opened upon fulfillment of certain requirements and approval in accordance with applicable provisions.
Scope: port rules P-1 to P-12 and the additional notes on risk exceptions.
General principle 1: all ports and services are blocked by default (default deny) unless a specific rule below allows them.
General principle 2: an exception form is the standard mechanism to open a blocked port (stated in Rules P-2 and P-3). An operational justification is the mechanism for Rule P-12.
General principle 3: insecure protocols must be replaced by secure ones: HTTP to HTTPS, POP3 to POP3S (995), SMTP to SMTPS (465), SMB v1 to SMB 3.0 or higher.
General principle 4: access to DC COLO servers uses custom redirect ports: SSH 20022, SFTP 30022, RDP 103389.
Environment terms: production, non-production, endpoint (PC), PAM server, DC COLO server.
Not specified: any port or service not covered by a rule below falls under Rule P-1 (default deny).

## Port Rules

### Rule P-1: Any Port, Any Service

Policy: Port and Protocol Security Policy.
Port: Any. Service: Any.
Provision: all access is blocked by default (default deny).
Summary: Every port and service is blocked by default. Only the ports with specific rules below may be opened under their stated conditions.

### Rule P-2: HTTP (Port 80 or Custom HTTP Port)

Policy: Port and Protocol Security Policy.
Port: 80 or any custom HTTP port. Service: HTTP.
Default: all access is blocked (default deny).
Can be opened if: an exception form is submitted.
Required action: must be redirected to use HTTPS via an SSL or self-signed certificate.
Note: the production environment is required to use SSL.
Summary: HTTP (port 80 or any custom HTTP port) is blocked by default. It can be opened with an exception form and must be redirected to HTTPS. Production must use SSL.

### Rule P-3: FTP (Ports 20-21 or Custom FTP Port)

Policy: Port and Protocol Security Policy.
Port: 20-21 or any custom FTP port. Service: FTP.
Default: all access is blocked (default deny).
Can be opened if: an exception form is submitted.
Summary: FTP (ports 20-21 or any custom FTP port) is blocked by default and can only be opened with an exception form.

### Rule P-4: SSH or SFTP (Port 22 or Custom Port)

Policy: Port and Protocol Security Policy.
Port: 22 or any custom SSH/SFTP port. Service: SSH or SFTP.
Can be opened for (1): connections between servers within the production environment, with justification (for example HA requirements, replication).
Can be opened for (2): connections between servers within the non-production environment, with justification (for example HA requirements, replication).
Can be opened for (3): connections from an endpoint (PC) to a server in the non-production environment.
Redirect (4): port 22 SSH access from a server to a DC COLO server must be redirected to custom port 20022.
Redirect (5): port 22 SFTP access from a server to a DC COLO server must be redirected to custom port 30022.
Summary: SSH/SFTP can be opened server-to-server within production or within non-production (with justification), and from an endpoint (PC) to a non-production server. SSH to a DC COLO server must use port 20022 and SFTP must use port 30022.

### Rule P-5: RDP (Port 3389 or Custom RDP Port)

Policy: Port and Protocol Security Policy.
Port: 3389 or any custom RDP port. Service: RDP.
Can be opened for (1): connections from an endpoint (PC) to a server in the non-production environment.
Can be opened for (2): connections from a PAM server to a server in the production environment.
Redirect (3): port 3389 RDP access from a server to a DC COLO server must be redirected to custom port 103389.
Summary: RDP can be opened from an endpoint (PC) to a non-production server, and from a PAM server to a production server. RDP to a DC COLO server must use port 103389.

### Rule P-6: SMB v1 (Port 445)

Policy: Port and Protocol Security Policy.
Port: 445. Service: SMB v1.
Default: all access is blocked (default deny).
Required action: use SMB version 3.0 or higher.
Fallback: if there are dependency issues with other servers, use version 2.0.
Summary: SMB v1 on port 445 is blocked by default. Use SMB 3.0 or higher, and SMB 2.0 only if there are dependency issues with other servers.

### Rule P-7: Database Ports

Policy: Port and Protocol Security Policy.
Port: 3306, 1521, 1522, 1530, 1540, 5432, 27017, 1433, or other custom database ports.
Service: MySQL, MariaDB, Oracle DB, PostgreSQL, MongoDB, Microsoft SQL Server.
Can be opened for (1): connections from an endpoint (PC) to a server in the non-production environment.
Can be opened for (2): connections between servers within the production environment.
Can be opened for (3): connections between servers within the non-production environment.
Can be opened for (4): connections from a PAM server to a server in the production environment.
Summary: Database ports can be opened from an endpoint (PC) to non-production servers, between servers within production, between servers within non-production, and from a PAM server to production servers. An endpoint (PC) to a production server is not listed.

### Rule P-8: Telnet (Port 23)

Policy: Port and Protocol Security Policy.
Port: 23. Service: Telnet Remote Access.
Provision: all network access is blocked by default (default deny).
Summary: Telnet (port 23) is blocked by default. No exception is stated.

### Rule P-9: POP3 (Port 110)

Policy: Port and Protocol Security Policy.
Port: 110. Service: POP3.
Default: all access is blocked (default deny).
Required action: must be redirected to use POP3S (port 995).
Summary: POP3 (port 110) is blocked by default and must be redirected to POP3S on port 995.

### Rule P-10: SMTP (Port 25)

Policy: Port and Protocol Security Policy.
Port: 25. Service: SMTP.
Default: all access is blocked (default deny).
Required action: must be redirected to use SMTPS (port 465).
Summary: SMTP (port 25) is blocked by default and must be redirected to SMTPS on port 465.

### Rule P-11: VNC (Ports 5900-5903)

Policy: Port and Protocol Security Policy.
Port: 5900-5903. Service: VNC.
Provision: all access is blocked by default (default deny).
Summary: VNC (ports 5900-5903) is blocked by default. No exception is stated.

### Rule P-12: Dynamic / Ephemeral Ports (49152-65535)

Policy: Port and Protocol Security Policy.
Port: 49152-65535. Service: Dynamic / Ephemeral.
Default: all access is blocked (default deny).
Can be opened if: there is a justification based on operational needs.
Summary: Dynamic/ephemeral ports (49152-65535) are blocked by default and can be opened with a justification based on operational needs.

## Additional Notes

### Note N-1: Exception for Risky Ports or Services

Policy: Port and Protocol Security Policy.
Provision: the use of ports or services that carry security risk is permitted if there is a recommendation from the principal, substantiated by a supporting statement letter or related documentation.
Summary: A risky port or service can still be used if the principal recommends it and a supporting statement letter or related documentation backs it up.