# Network Segment Security Policy (Server Farm and DMZ)

## Overview

Policy: Network Segment Security Policy (Server Farm and DMZ).
Purpose: as part of network segment security, access between segments (Server Farm and DMZ) is restricted.
Scope: firewall provisions for Server to Server access (Rules SS-1 to SS-10) and Workstation to Server access (Rules WS-1 to WS-3).
Segments mentioned: IP Data or VS - Server Farm, IP Management - Server Farm, IP Data or VS - DMZ, IP Management - DMZ, and LAN Campus (workstation).
Management ports: 22, 3389, 445, 7001-7002. Any other port is a non-management (specific) port.
General principle 1: management ports are only opened toward IP Management segments. Access to IP Data or VS segments is limited to non-management ports.
General principle 2: access whose source is an IP Management segment is blocked by default (default deny). The source must be redirected to use IP Data or VS.
General principle 3: the DMZ segment is isolated from users, so direct access from workstations (LAN Campus) is not permitted. The exception applies only to appliance devices on the DMZ that cannot use the F5 or forwarding mechanism.
Not specified: any source/destination pair that is not covered by a rule below has no stated provision in this policy.

## Server to Server Rules

### Rule SS-1: Server Farm Data/VS to Server Farm Data/VS

Policy: Network Segment Security Policy. Category: Server to Server.
Source: IP Data or VS - Server Farm.
Destination: IP Data or VS - Server Farm.
Firewall rule: Can be opened for the need of several specific ports other than the management ports (22, 3389, 445, 7001-7002).
Summary: Within the Server Farm, access between Data/VS IPs can be opened for specific non-management ports only. Management ports are not allowed here.

### Rule SS-2: Server Farm Data/VS to Server Farm Management

Policy: Network Segment Security Policy. Category: Server to Server.
Source: IP Data or VS - Server Farm.
Destination: IP Management - Server Farm.
Firewall rule: Can be opened for the need of management ports (22, 3389, 445, 7001-7002).
Summary: In the Server Farm, management ports (22, 3389, 445, 7001-7002) can be opened from Data/VS IPs to Management IPs.

### Rule SS-3: Server Farm Management to Server Farm Data/VS

Policy: Network Segment Security Policy. Category: Server to Server.
Source: IP Management - Server Farm.
Destination: IP Data or VS - Server Farm.
Default: all access is blocked (default deny).
Required action: the source IP must be redirected to use IP Data or VS - Server Farm.
Summary: In the Server Farm, access from a Management IP to Data/VS IPs is blocked by default. The source must use an IP Data or VS - Server Farm instead.

### Rule SS-4: DMZ Data/VS to DMZ Data/VS

Policy: Network Segment Security Policy. Category: Server to Server.
Source: IP Data or VS - DMZ.
Destination: IP Data or VS - DMZ.
Firewall rule: Can be opened for the need of several specific ports other than the management ports (22, 3389, 445, 7001-7002).
Summary: Within the DMZ, access between Data/VS IPs can be opened for specific non-management ports only. Management ports are not allowed here.

### Rule SS-5: DMZ Data/VS to DMZ Management

Policy: Network Segment Security Policy. Category: Server to Server.
Source: IP Data or VS - DMZ.
Destination: IP Management - DMZ.
Firewall rule: Can be opened for the need of management ports (22, 3389, 445, 7001-7002).
Summary: In the DMZ, management ports (22, 3389, 445, 7001-7002) can be opened from Data/VS IPs to Management IPs.

### Rule SS-6: DMZ Management to DMZ Data/VS

Policy: Network Segment Security Policy. Category: Server to Server.
Source: IP Management - DMZ.
Destination: IP Data or VS - DMZ.
Default: all access is blocked (default deny).
Required action: the source IP must be redirected to use IP Data or VS.
Summary: In the DMZ, access from a Management IP to Data/VS IPs is blocked by default. The source must use an IP Data or VS instead.

### Rule SS-7: Server Farm Data/VS to DMZ Data/VS

Policy: Network Segment Security Policy. Category: Server to Server.
Source: IP Data or VS - Server Farm.
Destination: IP Data or VS - DMZ.
Firewall rule: Can be opened for the need of several specific ports other than the management ports (22, 3389, 445, 7001-7002).
Summary: From the Server Farm to the DMZ, access between Data/VS IPs can be opened for specific non-management ports only.

### Rule SS-8: Server Farm Data/VS to DMZ Management

Policy: Network Segment Security Policy. Category: Server to Server.
Source: IP Data or VS - Server Farm.
Destination: IP Management - DMZ.
Firewall rule: Can be opened for the specific ports 22, 3389, 445, 7001-7002.
Summary: From the Server Farm to a DMZ Management IP, only the management ports (22, 3389, 445, 7001-7002) can be opened.

### Rule SS-9: Server Farm Data/VS to DMZ VS/Data

Policy: Network Segment Security Policy. Category: Server to Server.
Source: IP Data or VS - Server Farm.
Destination: IP VS or IP Data - DMZ.
Firewall rule: Can be opened for the need of several ports other than the management ports (22, 3389, 445, 7001-7002).
Data quality note: this rule overlaps with Rule SS-7 (same source, same destination type, same port condition). It is kept as stated in the source.
Summary: From the Server Farm to DMZ VS/Data IPs, access can be opened for non-management ports only.

### Rule SS-10: DMZ Data/VS to Server Farm (VS, Data, Management)

Policy: Network Segment Security Policy. Category: Server to Server.
Source: IP Data or VS - DMZ.
Destination: IP VS, IP Data, or IP Management - Server Farm.
Firewall rule 1: can be opened for the need of specific ports.
Firewall rule 2: all access is blocked by default (default deny) for a source from IP Management - DMZ. It must be redirected to use IP Data or VS.
Summary: From the DMZ to the Server Farm, access from Data/VS IPs can be opened for specific ports. A source from IP Management - DMZ is blocked by default and must use an IP Data or VS.

## Workstation to Server Rules

### Rule WS-1: LAN Campus to Server Farm Data/VS

Policy: Network Segment Security Policy. Category: Workstation to Server.
Source: LAN Campus (workstation).
Destination: IP Data or VS - Server Farm.
Non-production environment: can be opened for the need of specific ports other than the management ports (22, 3389, 445, 7001-7002).
Production environment: all access is blocked by default (default deny).
Summary: From LAN Campus to Server Farm Data/VS IPs, non-management ports can be opened for non-production only. Access to production is blocked by default.

### Rule WS-2: LAN Campus to Server Farm Management

Policy: Network Segment Security Policy. Category: Workstation to Server.
Source: LAN Campus (workstation).
Destination: IP Management - Server Farm.
Non-production environment: can be opened for the need of specific management ports (22, 3389, 445, 7001-7002).
Production environment: all access is blocked by default (default deny).
Data quality note: this row is numbered "1" in the source, a duplicate of the previous row. It is treated here as the second rule.
Summary: From LAN Campus to Server Farm Management IPs, management ports (22, 3389, 445, 7001-7002) can be opened for non-production only. Production access is blocked by default.

### Rule WS-3: LAN Campus to DMZ

Policy: Network Segment Security Policy. Category: Workstation to Server.
Source: LAN Campus (workstation).
Destination: IP Data, IP Management, or IP VS - DMZ.
Default: all access is blocked (default deny).
Required action: must be redirected to use the forwarding mechanism or IP F5 to the Server Farm segment.
Note: the DMZ segment is isolated from users, so direct access is not permitted. The exception applies only to appliance devices on the DMZ that cannot use the F5 or forwarding mechanism.
Summary: LAN Campus cannot access the DMZ directly. Access must go through the forwarding mechanism or IP F5 to the Server Farm segment, except for appliance devices on the DMZ that cannot use F5 or forwarding.