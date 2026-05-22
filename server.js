// The list of banned IP addresses
const blocklist = [];
const fs = require('fs');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();

// --- THE AIR-GAPPED VAULT (In-Memory Database) ---
const usersDB = []; 
const SECRET_KEY = "offline_sandbox_secret_key_999";

// --- SECURITY MIDDLEWARE ---
app.use(helmet()); 
app.use(express.json()); 
// --- THE BOUNCER ---
app.use((req, res, next) => {
    // Check if the user's IP is on the list
    if (blocklist.includes(req.ip)) {
        console.log(`🚫 DEFENSE TRIGGERED: Rejected banned IP -> ${req.ip}`);
        return res.status(403).json({ message: "ACCESS DENIED: Your IP has been banned." });
    }
    next();
});
// --- THE WATCHTOWER (Global Logging Middleware) ---
app.use((req, res, next) => {
    // We wait for the request to finish so we can see if it succeeded or failed (Status Code)
    res.on('finish', () => {
        const timestamp = new Date().toISOString();
        // Format: [Time] IP_Address - HTTP_Method URL - Status_Code
        const logEntry = `[${timestamp}] ${req.ip} - ${req.method} ${req.originalUrl} - ${res.statusCode}\n`;
        
        // Write it to a hidden file called server.log
        fs.appendFileSync(path.join(__dirname, 'server.log'), logEntry);
    });
    next();
});
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    message: "Too many requests from this IP."
});
app.use('/api/', limiter);

// --- ROUTES ---

// 1. Registration Route
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password, role } = req.body;
        
        if (usersDB.find(u => u.email === email)) {
            return res.status(400).json({ message: "User already exists" });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = { 
            id: Date.now().toString(), 
            username, 
            email, 
            password: hashedPassword, 
            role: role || 'user' 
        };
        usersDB.push(newUser);

        console.log("Vault Updated. Current Users:", usersDB.map(u => u.username)); 

        res.status(201).json({ message: "User registered securely" });
    } catch (error) {
        res.status(500).json({ message: "Server Error" });
    }
});

// 2. Login Route
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const user = usersDB.find(u => u.email === email);
        if (!user) return res.status(401).json({ message: "Invalid Credentials" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: "Invalid Credentials" });

        const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });

        res.json({ token, message: "Logged in successfully" });
    } catch (error) {
        res.status(500).json({ message: "Login failed" });
    }
});

// 3. The Security Guards (Inline Middleware)
const protect = (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            req.user = jwt.verify(token, SECRET_KEY); 
            next();
        } catch (error) {
            res.status(401).json({ message: "Not authorized, token failed" });
        }
    } else {
        res.status(401).json({ message: "Not authorized, no token" });
    }
};

const authorize = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: `Access Denied.` });
        }
        next();
    };
};

// 4. The Protected Admin Route
app.get('/api/admin/data', protect, authorize('admin'), (req, res) => {
    res.json({ message: "Welcome, Admin. You have bypassed the perimeter." });
});

const PORT = 5000;
// --- INTERNAL BAN ROUTE ---
app.post('/api/internal/ban', (req, res) => {
    const { ipToBan } = req.body;
    if (!blocklist.includes(ipToBan)) {
        blocklist.push(ipToBan); // Add IP to the list
        console.log(`🚨 ACTIVE DEFENSE: IP ${ipToBan} has been added to the blocklist!`);
    }
    res.json({ message: "Target neutralized." });
});
app.listen(PORT, () => console.log(`Offline Sandbox running on port ${PORT}`));