const fs = require('fs');
const path = require('path');

const logPath = path.join(__dirname, 'server.log');

console.log("\n[SYSTEM] Loading GovSOC Watchtower...");

if (!fs.existsSync(logPath)) {
    console.log("[!] CRITICAL: 'server.log' not found. Run some attacks first!\n");
} else {
    const logs = fs.readFileSync(logPath, 'utf8').split('\n').filter(line => line.trim() !== "");
    console.log(`[OK] Analyzing ${logs.length} log entries...\n`);

    let failedLogins = 0;
    let adminAccesses = 0;

    logs.forEach(log => {
        if (log.includes(' 401')) {
            failedLogins++;
            console.log(`🚨 THREAT DETECTED: ${log}`);
        }
        if (log.includes('/api/admin/data') && log.includes(' 200')) {
            adminAccesses++;
            console.log(`⚠️ SENSITIVE ACCESS: ${log}`);
        }
    });

    console.log("\n--- FINAL REPORT ---");
    console.log(`Failed Attempts: ${failedLogins}`);
    console.log(`Admin Entries:   ${adminAccesses}`);
    console.log("--------------------\n");
    // --- ACTIVE DEFENSE TRIGGER ---
if (failedLogins >= 3) {
    console.log("❌ CRITICAL: Brute force detected! Triggering Automatic Ban...");
    
    // Send a network request to our own server to ban the attacker's IP
    // Note: '::1' is the computer code for 'localhost' (Your IP)
    fetch('http://localhost:5000/api/internal/ban', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ipToBan: '::1' }) 
    })
    .then(res => res.json())
    .then(data => console.log(`🛡️  WATCHTOWER ACTION: ${data.message}`))
    .catch(err => console.log("Error communicating with server."));
}
}