// app.js
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const port = 3008;

// Middleware
app.use(express.json());

// MySQL Database Connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) throw err;
  console.log('Connected to MySQL database!');
});

// Helper function to send email
const sendEmail = (to, subject, text) => {
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject,
    text,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log(error);
    } else {
      console.log('Email sent: ' + info.response);
    }
  });
};

// Register route
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).send('All fields are required');
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
  db.query(query, [username, email, hashedPassword], (err, result) => {
    if (err) {
      return res.status(500).send('Error registering user');
    }
    res.status(201).send('User registered successfully');
  });
});

// Login route
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send('Email and password are required');
  }

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(401).send('Invalid credentials');
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).send('Invalid credentials');
    }

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRATION });
    res.json({ token });
  });
});

// Password reset request route
app.post('/reset-password-request', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).send('Email is required');
  }

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).send('User not found');
    }

    const user = results[0];
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    const resetTokenExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour expiry
    db.query('UPDATE users SET reset_token = ?, token_expiry = ? WHERE email = ?', [token, resetTokenExpiry, email], (err, result) => {
      if (err) {
        return res.status(500).send('Error updating reset token');
      }

      sendEmail(
        email,
        'Password Reset Request',
        `Click the link to reset your password: http://localhost:3000/reset-password?token=${token}`
      );

      res.status(200).send('Password reset link sent');
    });
  });
});

// Password reset route
app.post('/reset-password', (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).send('Token and new password are required');
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const query = 'SELECT * FROM users WHERE id = ? AND reset_token = ? AND token_expiry > NOW()';
    db.query(query, [decoded.id, token], async (err, results) => {
      if (err || results.length === 0) {
        return res.status(400).send('Invalid or expired token');
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      db.query('UPDATE users SET password = ?, reset_token = NULL, token_expiry = NULL WHERE id = ?', [hashedPassword, decoded.id], (err, result) => {
        if (err) {
          return res.status(500).send('Error resetting password');
        }
        res.status(200).send('Password successfully reset');
      });
    });
  } catch (err) {
    return res.status(400).send('Invalid or expired token');
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
