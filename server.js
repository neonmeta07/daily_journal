const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const cookieParser = require('cookie-parser');
const MySQLStore = require('express-mysql-session')(session);

const app = express();

// Error handling
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (err) => {
    console.error('Unhandled Rejection:', err);
});

// Database configuration
const dbConfig = {
    host: 'localhost',
    user: 'root',
    password: 'AnDrEw_JiN07',
    database: 'signup_db'
};

const pool = mysql.createPool(dbConfig);
const promisePool = pool.promise();

const sessionStore = new MySQLStore({
    expiration: 86400000,
    createDatabaseTable: true,
    checkExpirationInterval: 900000,
    schema: {
        tableName: 'sessions',
        columnNames: {
            session_id: 'session_id',
            expires: 'expires',
            data: 'data'
        }
    }
}, pool);

// Middleware for cache control
app.use((req, res, next) => {
    if (req.path.startsWith('/dashboard') || req.path.startsWith('/api')) {
        res.header('Cache-Control', 'private, no-cache, no-store, must-revalidate');
        res.header('Expires', '-1');
        res.header('Pragma', 'no-cache');
    }
    next();
});

app.use(cookieParser());
app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Cookie', 'Set-Cookie']
}));

app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    name: 'heartscript.sid',
    secret: 'your-strong-secret-key-123',
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        secure: false,
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true,
        sameSite: 'lax'
    }
}));

// Enhanced session logging middleware
app.use((req, res, next) => {
    console.log('Session check:', {
        sessionID: req.sessionID,
        user: req.session.user,
        path: req.path,
        method: req.method
    });
    next();
});

app.use(express.static(path.join(__dirname)));

// Test database connection
promisePool.query("SELECT 1")
    .then(() => console.log("Database connected successfully"))
    .catch(err => console.error("Database connection failed:", err));

// Enhanced authentication middleware
const requireAuth = (req, res, next) => {
    if (!req.session.user || !req.session.user.id) {
        return res.status(401).json({ message: 'Unauthorized' });
    }
    next();
};

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'landing_page.html'));
});

app.get('/dashboard', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get('/api/check-auth', (req, res) => {
    res.json({ 
        authenticated: !!req.session.user,
        user: req.session.user || null
    });
});

app.get('/api/get-user', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    res.json({
        id: req.session.user.id,
        first_name: req.session.user.first_name || 'Friend',
        username: req.session.user.username,
        email: req.session.user.email
    });
});

// Journal routes with enhanced user verification
app.get('/api/journal', requireAuth, async (req, res) => {
    const userId = req.session.user.id;
    console.log('Fetching journal:', {
        userId,
        sessionID: req.sessionID,
        user: req.session.user,
        cookies: req.cookies,
        path: req.path,
        method: req.method
    });
    try {
        // Validate user exists
        const [userCheck] = await promisePool.query(
            "SELECT id, username FROM users WHERE id = ?",
            [userId]
        );
        if (userCheck.length === 0) {
            req.session.destroy();
            return res.status(401).json({ message: 'Invalid user session' });
        }
        console.log('User validated:', userCheck[0]);

        const [entries] = await promisePool.query(
            "SELECT id, title, content, created_at FROM journal_entries WHERE user_id = ? ORDER BY created_at DESC",
            [userId]
        );
        console.log('Entries fetched for user', userId, ':', entries);
        res.json(entries);
    } catch (err) {
        console.error('Error fetching journals:', {
            error: err.message,
            sqlState: err.sqlState,
            sqlMessage: err.sqlMessage,
            userId
        });
        res.status(500).json({ success: false, message: 'Could not load journals' });
    }
});

app.post('/api/journal', requireAuth, async (req, res) => {
    const { title, content } = req.body;
    const userId = req.session.user.id;
    
    if (!userId) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    console.log('Saving journal for user:', userId, 'Session:', req.session);
    
    try {
        const [result] = await promisePool.query(
            "INSERT INTO journal_entries (user_id, title, content) VALUES (?, ?, ?)",
            [userId, title, content]
        );
        res.json({ 
            success: true, 
            message: 'Journal entry saved',
            entryId: result.insertId
        });
    } catch (err) {
        console.error('Journal save error:', err);
        res.status(500).json({ success: false, message: 'Could not save journal entry' });
    }
});

app.delete('/api/journal/:id', requireAuth, async (req, res) => {
    const entryId = req.params.id;
    const userId = req.session.user.id;
    
    try {
        const [result] = await promisePool.query(
            "DELETE FROM journal_entries WHERE id = ? AND user_id = ?",
            [entryId, userId]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'Entry not found or not owned by user' });
        }
        
        res.json({ success: true, message: 'Journal entry deleted' });
    } catch (err) {
        console.error('Journal delete error:', err);
        res.status(500).json({ success: false, message: 'Could not delete journal entry' });
    }
});

// Authentication routes
app.post('/submit-signup', async (req, res) => {
    const { "first-name": firstName, "last-name": lastName, email, username, password, dob, gender } = req.body;

    try {
        const [existingUsers] = await promisePool.query(
            "SELECT * FROM users WHERE email = ? OR username = ?",
            [email, username]
        );

        if (existingUsers.length > 0) {
            const errors = {};
            if (existingUsers.some(u => u.email === email)) errors.email = "Email already exists";
            if (existingUsers.some(u => u.username === username)) errors.username = "Username already exists";
            return res.status(400).json({ errors });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const [insertResult] = await promisePool.query(
            "INSERT INTO users (first_name, last_name, email, username, password, dob, gender) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [firstName, lastName, email, username, hashedPassword, dob, gender]
        );

        req.session.user = {
            id: insertResult.insertId,
            username: username,
            email: email,
            first_name: firstName
        };

        req.session.save(err => {
            if (err) {
                console.error('Session save error:', err);
                return res.status(500).json({ success: false, message: 'Session error' });
            }

            res.json({
                success: true,
                redirect: '/dashboard',
                user: req.session.user
            });
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Registration failed',
            error: error.message
        });
    }
});

app.post('/submit-signin', async (req, res) => {
    const { username, password } = req.body;

    try {
        const [results] = await promisePool.query(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            [username, username]
        );

        if (results.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Authentication failed',
                errors: { username: 'User not found. Please sign up first.' }
            });
        }

        const user = results[0];

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({
                success: false,
                message: 'Authentication failed',
                errors: { password: 'Incorrect password' }
            });
        }

        req.session.user = {
            id: user.id,
            username: user.username,
            email: user.email,
            first_name: user.first_name
        };

        req.session.save(err => {
            if (err) {
                console.error('Session save error:', err);
                return res.status(500).json({ success: false, message: 'Session error' });
            }

            console.log('User session set:', req.session.user);

            res.json({
                success: true,
                redirect: '/dashboard',
                user: req.session.user
            });
        });

    } catch (error) {
        console.error('Sign-in error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: error.message
        });
    }
});

app.get('/logout', (req, res) => {
    const sessionId = req.sessionID;
    
    req.session.destroy(err => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({
                success: false,
                message: 'Error logging out'
            });
        }
        
        // Clear the session from the store
        sessionStore.destroy(sessionId, (storeErr) => {
            if (storeErr) {
                console.error('Error destroying session in store:', storeErr);
            }
            
            res.clearCookie('heartscript.sid');
            res.header('Cache-Control', 'private, no-cache, no-store, must-revalidate');
            res.header('Expires', '-1');
            res.header('Pragma', 'no-cache');
            res.json({
                success: true,
                message: 'Logged out successfully!',
                redirect: '/'
            });
        });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

process.on('SIGINT', () => {
    pool.end(err => {
        if (err) {
            console.error('Error closing database connection:', err);
        } else {
            console.log('Database connection closed');
        }
        process.exit();
    });
});