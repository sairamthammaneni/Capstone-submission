const express = require('express');
const path = require('path');
const admin = require('firebase-admin');
const bcrypt = require('bcrypt');

const app = express();
const PORT = 3000;

const serviceAccount = require('./key.json');

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://ex-project-2c271n.firebaseio.com"
});

const db = admin.firestore();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

// Routes
app.get('/index', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'signup.html')));

// Signup Route
app.post('/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ error: "All fields are required!" });
        }

        // Basic email validation
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ error: "Invalid email format" });
        }

        // Password length check
        if (password.length < 6) {
            return res.status(400).json({ error: "Password must be at least 6 characters" });
        }

        const existingUser = await db.collection('users').where('email', '==', email).get();
        if (!existingUser.empty) {
            return res.status(400).json({ error: "Email already registered!" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await db.collection('users').add({
            name,
            email,
            password: hashedPassword,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(200).json({ message: "User registered successfully!" });
    } catch (error) {
        console.error("Signup error:", error);
        res.status(500).json({ error: "An unexpected error occurred. Please try again later." });
    }
});

// Login Route
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: "Both email and password are required!" });
        }

        const snapshot = await db.collection('users').where('email', '==', email).get();
        if (snapshot.empty) {
            return res.status(400).json({ error: "Invalid credentials" });
        }

        let userData = null;
        snapshot.forEach((doc) => {
            userData = doc.data();
        });

        if (userData) {
            const passwordMatch = await bcrypt.compare(password, userData.password);
            if (passwordMatch) {
                return res.status(200).json({ 
                    message: "Login successful!",
                    redirect: "/dashboard.html"
                });
            }
        }

        res.status(400).json({ error: "Invalid credentials" });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ error: "An unexpected error occurred. Please try again later." });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
