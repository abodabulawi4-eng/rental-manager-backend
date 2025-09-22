// server.js

// 1. Import necessary libraries
const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const port = 5000;
const SECRET_KEY = 'your_super_secret_key';

// 2. Apply middleware
const corsOptions = {
    origin: 'https://prismatic-sorbet-e64d09.netlify.app'
};

app.use(cors(corsOptions));
app.use(bodyParser.json());

// 3. Connect to the database and create tables
const db = new sqlite3.Database('./rental-manager.db', (err) => {
    if (err) {
        console.error('Error connecting to the database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        createTables();
    }
});

const createTables = () => {
    db.serialize(() => {
        db.run('DROP TABLE IF EXISTS users');
        db.run('DROP TABLE IF EXISTS properties');
        db.run('DROP TABLE IF EXISTS tenants');
        db.run('DROP TABLE IF EXISTS invoices');
        db.run('DROP TABLE IF EXISTS expenses');

        db.run(`CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user',
            is_approved INTEGER DEFAULT 0
        )`);

        db.run(`CREATE TABLE properties (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            name TEXT,
            address TEXT,
            total_units INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )`);

        db.run(`CREATE TABLE tenants (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            property_id INTEGER,
            full_name TEXT,
            phone TEXT,
            address TEXT,
            start_date TEXT,
            rent_amount REAL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (property_id) REFERENCES properties(id)
        )`);

        db.run(`CREATE TABLE invoices (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            tenant_id INTEGER,
            amount REAL,
            due_date TEXT,
            paid_date TEXT,
            status TEXT DEFAULT 'pending',
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        )`);

        db.run(`CREATE TABLE expenses (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            description TEXT,
            amount REAL,
            date TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )`);

        db.get('SELECT id FROM users WHERE email = ?', ['admin@test.com'], (err, row) => {
            if (err) {
                console.error('Error checking for admin user:', err.message);
                return;
            }
            if (!row) {
                bcrypt.hash('adminpassword', 10, (err, hash) => {
                    if (err) {
                        console.error('Error hashing password:', err.message);
                        return;
                    }
                    db.run('INSERT INTO users (email, password, role, is_approved) VALUES (?, ?, ?, ?)', ['admin@test.com', hash, 'admin', 1], (err) => {
                        if (err) {
                            console.error('Error creating admin user:', err.message);
                        } else {
                            console.log('Admin user created successfully.');
                        }
                    });
                });
            }
        });
    });
};

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// 4. API Endpoints
// Auth Endpoints
app.post('/register', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: 'Failed to hash password' });

        const stmt = db.prepare('INSERT INTO users (email, password) VALUES (?, ?)');
        stmt.run(email, hash, function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(409).json({ error: 'Email already exists' });
                }
                return res.status(500).json({ error: 'Registration failed' });
            }
            res.status(201).json({ message: 'User registered successfully. Your account is awaiting admin approval.' });
        });
        stmt.finalize();
    });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err) return res.status(500).json({ error: 'Login failed' });
        if (!user) return res.status(400).json({ error: 'Invalid credentials' });

        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return res.status(500).json({ error: 'Login failed' });
            if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

            if (user.is_approved === 0) {
                return res.status(403).json({ error: 'Your account is awaiting admin approval.' });
            }

            const isAdmin = user.role === 'admin';
            const token = jwt.sign({ id: user.id, email: user.email, isAdmin: isAdmin }, SECRET_KEY, { expiresIn: '1h' });
            res.json({ token, isAdmin });
        });
    });
});

// Admin Endpoints
app.get('/admin/users/pending', authenticateToken, (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Access denied. Admin role required.' });
    }
    db.all('SELECT id, email, role FROM users WHERE is_approved = 0', [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ users: rows });
    });
});

app.post('/admin/users/:id/approve', authenticateToken, (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Access denied. Admin role required.' });
    }
    const { id } = req.params;

    db.run('UPDATE users SET is_approved = 1 WHERE id = ?', [id], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }
        res.json({ message: 'User approved successfully.' });
    });
});

app.delete('/admin/users/:id/deny', authenticateToken, (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Access denied. Admin role required.' });
    }
    const { id } = req.params;
    db.run('DELETE FROM users WHERE id = ?', [id], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }
        res.json({ message: 'User denied and deleted successfully.' });
    });
});

// Property Endpoints
app.get('/properties', authenticateToken, (req, res) => {
    db.all('SELECT * FROM properties WHERE user_id = ?', [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.get('/all-properties', authenticateToken, (req, res) => {
    db.all('SELECT * FROM properties', [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

app.post('/properties', authenticateToken, (req, res) => {
    const { name, address, total_units } = req.body;
    db.run('INSERT INTO properties (user_id, name, address, total_units) VALUES (?, ?, ?, ?)', [req.user.id, name, address, total_units], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ id: this.lastID });
    });
});

app.put('/properties/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { name, address, total_units } = req.body;
    db.run('UPDATE properties SET name = ?, address = ?, total_units = ? WHERE id = ? AND user_id = ?', [name, address, total_units, id, req.user.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Property not found or you are not authorized' });
        res.json({ message: 'Property updated successfully' });
    });
});

app.delete('/properties/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.run('DELETE FROM properties WHERE id = ? AND user_id = ?', [id, req.user.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Property not found or you are not authorized' });
        res.json({ message: 'Property deleted successfully' });
    });
});

// Tenant Endpoints
app.get('/tenants', authenticateToken, (req, res) => {
    db.all('SELECT * FROM tenants WHERE user_id = ?', [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/tenants', authenticateToken, (req, res) => {
    const { property_id, full_name, phone, address, start_date, rent_amount } = req.body;
    db.run('INSERT INTO tenants (user_id, property_id, full_name, phone, address, start_date, rent_amount) VALUES (?, ?, ?, ?, ?, ?, ?)', [req.user.id, property_id, full_name, phone, address, start_date, rent_amount], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ id: this.lastID });
    });
});

app.put('/tenants/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { property_id, full_name, phone, address, start_date, rent_amount } = req.body;
    db.run('UPDATE tenants SET property_id = ?, full_name = ?, phone = ?, address = ?, start_date = ?, rent_amount = ? WHERE id = ? AND user_id = ?', [property_id, full_name, phone, address, start_date, rent_amount, id, req.user.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Tenant not found or you are not authorized' });
        res.json({ message: 'Tenant updated successfully' });
    });
});

app.delete('/tenants/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.run('DELETE FROM tenants WHERE id = ? AND user_id = ?', [id, req.user.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Tenant not found or you are not authorized' });
        res.json({ message: 'Tenant deleted successfully' });
    });
});

// Invoice Endpoints
app.get('/invoices', authenticateToken, (req, res) => {
    db.all('SELECT * FROM invoices WHERE user_id = ?', [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/invoices', authenticateToken, (req, res) => {
    const { tenant_id, amount, due_date } = req.body;
    db.run('INSERT INTO invoices (user_id, tenant_id, amount, due_date) VALUES (?, ?, ?, ?)', [req.user.id, tenant_id, amount, due_date], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ id: this.lastID });
    });
});

app.put('/invoices/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { tenant_id, amount, due_date, status, paid_date } = req.body;
    db.run('UPDATE invoices SET tenant_id = ?, amount = ?, due_date = ?, status = ?, paid_date = ? WHERE id = ? AND user_id = ?', [tenant_id, amount, due_date, status, paid_date, id, req.user.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Invoice not found or you are not authorized' });
        res.json({ message: 'Invoice updated successfully' });
    });
});

app.delete('/invoices/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.run('DELETE FROM invoices WHERE id = ? AND user_id = ?', [id, req.user.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Invoice not found or you are not authorized' });
        res.json({ message: 'Invoice deleted successfully' });
    });
});

// Expense Endpoints
app.get('/expenses', authenticateToken, (req, res) => {
    db.all('SELECT * FROM expenses WHERE user_id = ?', [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/expenses', authenticateToken, (req, res) => {
    const { description, amount, date } = req.body;
    db.run('INSERT INTO expenses (user_id, description, amount, date) VALUES (?, ?, ?, ?)', [req.user.id, description, amount, date], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ id: this.lastID });
    });
});

app.put('/expenses/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { description, amount, date } = req.body;
    db.run('UPDATE expenses SET description = ?, amount = ?, date = ? WHERE id = ? AND user_id = ?', [description, amount, date, id, req.user.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Expense not found or you are not authorized' });
        res.json({ message: 'Expense updated successfully' });
    });
});

app.delete('/expenses/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.run('DELETE FROM expenses WHERE id = ? AND user_id = ?', [id, req.user.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Expense not found or you are not authorized' });
        res.json({ message: 'Expense deleted successfully' });
    });
});

// Dashboard Endpoint
app.get('/dashboard', authenticateToken, (req, res) => {
    const summary = {};
    db.get("SELECT SUM(amount) as total_income FROM invoices WHERE status = 'paid' AND user_id = ?", [req.user.id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        summary.income = row.total_income || 0;
        db.get('SELECT SUM(amount) as total_expenses FROM expenses WHERE user_id = ?', [req.user.id], (err, row) => {
            if (err) return res.status(500).json({ error: err.message });
            summary.expenses = row.total_expenses || 0;
            db.get('SELECT COUNT(*) as property_count FROM properties WHERE user_id = ?', [req.user.id], (err, row) => {
                if (err) return res.status(500).json({ error: err.message });
                summary.totalProperties = row.property_count;
                db.get('SELECT COUNT(*) as tenant_count FROM tenants WHERE user_id = ?', [req.user.id], (err, row) => {
                    if (err) return res.status(500).json({ error: err.message });
                    summary.totalTenants = row.tenant_count;
                    const chartQuery = `
                        SELECT
                            strftime('%Y-%m', date) as month,
                            SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END) as total_expenses,
                            SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) as total_income
                        FROM (
                            SELECT paid_date as date, amount, 'income' as type FROM invoices WHERE status = 'paid' AND user_id = ?
                            UNION ALL
                            SELECT date, amount, 'expense' as type FROM expenses WHERE user_id = ?
                        )
                        GROUP BY month
                        ORDER BY month;
                    `;
                    db.all(chartQuery, [req.user.id, req.user.id], (err, rows) => {
                        if (err) {
                            return res.status(500).json({ error: err.message });
                        }
                        const labels = rows.map(row => row.month);
                        const incomeData = rows.map(row => row.total_income);
                        const expensesData = rows.map(row => row.total_expenses);
                        summary.chartData = {
                            labels: labels,
                            income: incomeData,
                            expenses: expensesData,
                        };
                        const recentActivities = [];
                        db.all("SELECT 'expense' as type, description as title, amount, date FROM expenses WHERE user_id = ? ORDER BY date DESC LIMIT 5", [req.user.id], (err, expenses) => {
                            if (err) {
                                console.error('Error fetching recent expenses:', err.message);
                                return res.status(500).json({ error: 'Failed to fetch recent expenses' });
                            }
                            recentActivities.push(...expenses.map(exp => ({ ...exp, date: new Date(exp.date).toISOString().split('T')[0] })));
                            db.all("SELECT 'invoice' as type, 'Invoice for ' || t.full_name as title, i.amount, i.paid_date as date FROM invoices i JOIN tenants t ON i.tenant_id = t.id WHERE i.status = 'paid' AND i.user_id = ? ORDER BY i.paid_date DESC LIMIT 5", [req.user.id], (err, invoices) => {
                                if (err) {
                                    console.error('Error fetching recent invoices:', err.message);
                                    return res.status(500).json({ error: 'Failed to fetch recent invoices' });
                                }
                                recentActivities.push(...invoices.map(inv => ({ ...inv, date: inv.date ? new Date(inv.date).toISOString().split('T')[0] : null })));
                                recentActivities.sort((a, b) => new Date(b.date) - new Date(a.date));
                                summary.recentActivity = recentActivities.slice(0, 5);
                                res.json({ summary });
                            });
                        });
                    });
                });
            });
        });
    });
});

// 5. Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});