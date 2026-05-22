# Zero-Trust Government Gateway
A secure Node.js API gateway featuring multi-layer defense for government digital services. Built following GovSOC (Government Security Operations Center) principles.

## 🛡️ Core Features
- **Identity Protection:** Password hashing using `Bcrypt`.
- **Access Control:** Role-Based Access Control (RBAC) via JSON Web Tokens (`JWT`).
- **Perimeter Defense:** Rate-limiting, Security Headers (`Helmet.js`), and IP Blocklisting.
- **Active Monitoring (SIEM/SOAR):** Automated logging and threat analysis that dynamically bans brute-force attackers.

## ⚙️ How it Works
1. **The Gateway:** All traffic is inspected by middleware before reaching the server.
2. **The Watchtower:** A persistent logging system (`server.log`) records all 401 (Unauthorized) and 200 (Admin Access) events.
3. **The Banhammer:** An automated analyzer script parses the logs and updates the server's internal firewall to block malicious IP addresses in real-time.