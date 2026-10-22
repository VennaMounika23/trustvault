const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const db = require('./database');

const app = express();
app.use(express.json());
app.use(cors());

// Static files middleware (Frontend UI serve cheyadaniki)
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'trustvault_secret_key_2026';

const uploadDir = './uploads';
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage: storage });

function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: "Access token missing" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid or expired token" });
        req.user = user;
        next();
    });
}

// 1. REGISTER API
app.post('/api/register', async (req, res) => {
    const { name, email, password, role } = req.body;
    
    if (!name || !email || !password || !role) {
        return res.status(400).json({ error: "All fields are required" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(
            `INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)`,
            [name, email, hashedPassword, role],
            function (err) {
                if (err) {
                    return res.status(400).json({ error: "Email already exists or invalid data" });
                }
                res.status(201).json({ message: "User registered successfully", userId: this.lastID });
            }
        );
    } catch (err) {
        res.status(500).json({ error: "Server error during registration" });
    }
});

// 2. LOGIN API
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: "Login successful", token, role: user.role });
    });
});

// 3. UPLOAD DOCUMENT API
app.post('/api/documents', verifyToken, upload.single('file'), (req, res) => {
    if (req.user.role === 'viewer') {
        return res.status(403).json({ error: "Viewers cannot upload documents" });
    }

    const { title, category } = req.body;
    const filename = req.file ? req.file.filename : null;
    const owner_id = req.user.id;

    if (!title || !category || !filename) {
        return res.status(400).json({ error: "All fields including file are required" });
    }

    db.run(
        `INSERT INTO documents (title, filename, category, owner_id) VALUES (?, ?, ?, ?)`,
        [title, filename, category, owner_id],
        function(err) {
            if (err) return res.status(500).json({ error: "Database error during upload" });
            
            db.run(`INSERT INTO audit_logs (user_id, action, document_id, status) VALUES (?, ?, ?, ?)`,
                [req.user.id, 'UPLOAD', this.lastID, 'success']);

            res.status(201).json({ message: "Document uploaded successfully", documentId: this.lastID });
        }
    );
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});