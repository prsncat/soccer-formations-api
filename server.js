require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { Resend } = require('resend');

const app = express();

// Required when running behind Railway/Vercel/proxy infrastructure.
// This allows express-rate-limit to correctly understand forwarded IPs.
app.set('trust proxy', 1);

const PORT = process.env.PORT || 4000;

const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:5173';
const ACCESS_COOKIE = 'sf_access';
const REFRESH_COOKIE = 'sf_refresh';
const ACCESS_TOKEN_TTL = '15m';
const REFRESH_TOKEN_TTL = '7d';
const resend = new Resend(process.env.RESEND_API_KEY);
const PASSWORD_REGEX =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%&*?])[A-Za-z\d!@#$%&*?]{8,15}$/;

// Replace this with a real database.
const users = new Map();

app.use(
  cors({
    origin: CLIENT_ORIGIN,
    credentials: true,
  })
);

app.use(express.json());
app.use(cookieParser());

app.use(
  '/api/auth',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

function cookieOptions(maxAgeMs) {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
    path: '/',
    maxAge: maxAgeMs,
  };
}

function createAccessToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
    },
    process.env.JWT_ACCESS_SECRET,
    {
      expiresIn: ACCESS_TOKEN_TTL,
    }
  );
}

function createRefreshToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      tokenVersion: user.tokenVersion,
    },
    process.env.JWT_REFRESH_SECRET,
    {
      expiresIn: REFRESH_TOKEN_TTL,
    }
  );
}

function setAuthCookies(res, user) {
  const accessToken = createAccessToken(user);
  const refreshToken = createRefreshToken(user);

  res.cookie(ACCESS_COOKIE, accessToken, cookieOptions(15 * 60 * 1000));
  res.cookie(REFRESH_COOKIE, refreshToken, cookieOptions(7 * 24 * 60 * 60 * 1000));
}

function clearAuthCookies(res) {
  res.clearCookie(ACCESS_COOKIE, { path: '/' });
  res.clearCookie(REFRESH_COOKIE, { path: '/' });
}

function findUserByEmail(email) {
  return users.get(email.toLowerCase());
}

function findUserById(id) {
  for (const user of users.values()) {
    if (user.id === id) return user;
  }

  return null;
}

function requireAuth(req, res, next) {
  const token = req.cookies[ACCESS_COOKIE];

  if (!token) {
    return res.status(401).json({ message: 'Missing access token.' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    const user = findUserById(payload.sub);

    if (!user) {
      return res.status(401).json({ message: 'User not found.' });
    }

    req.user = user;
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid or expired access token.' });
  }
}

function createEmailVerificationToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      purpose: 'email_verification',
    },
    process.env.EMAIL_VERIFY_SECRET,
    {
      expiresIn: '1d',
    }
  );
}

async function sendVerificationEmail(user, token) {
  const verificationUrl =
    `${CLIENT_ORIGIN}/verify-email?token=` + encodeURIComponent(token);

  const fromAddress = process.env.EMAIL_FROM;

  console.log('Attempting to send verification email...');
  console.log('To:', user.email);
  console.log('From:', fromAddress);
  console.log('Verification URL:', verificationUrl);

  const { data, error } = await resend.emails.send({
    from: fromAddress,
    to: user.email,
    subject: 'Verify Your Soccer Formations Account',
    html: `
      <h2>Welcome to Soccer Formations</h2>

      <p>Please verify your email address by clicking the link below:</p>

      <p>
        ${verificationUrl}
          Verify Email Address
        </a>
      </p>

      <p>If the link does not work, copy and paste this URL into your browser:</p>

      <p>${verificationUrl}</p>
    `,
  });

  if (error) {
    console.error('Resend failed to send verification email:', error);
    throw new Error(error.message || 'Failed to send verification email.');
  }

  console.log('Verification email sent successfully.');
  console.log('Resend response:', data);

  return data;
}

app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body;

  const normalizedEmail = String(email || '').trim().toLowerCase();

  if (!normalizedEmail || !normalizedEmail.includes('@')) {
    return res.status(400).json({ message: 'Valid email is required.' });
  }

  if (!PASSWORD_REGEX.test(password || '')) {
    return res.status(400).json({
      message:
        'Password must be 8–15 characters and include uppercase, lowercase, number, and one of ! @ # $ % & * ?.',
    });
  }

  if (findUserByEmail(normalizedEmail)) {
    return res.status(409).json({ message: 'Account already exists.' });
  }

  const passwordHash = await bcrypt.hash(password, 12);

  const user = {
    id: crypto.randomUUID(),
    email: normalizedEmail,
    passwordHash,
    emailVerified: false,
    tokenVersion: 0,
    createdAt: new Date().toISOString(),
  };

  users.set(normalizedEmail, user);

const emailToken = createEmailVerificationToken(user);
await sendVerificationEmail(user, emailToken);

  return res.status(201).json({
    message: 'Account created. Please verify your email before logging in.',
  });
});

app.get('/api/auth/verify-email', (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).json({ message: 'Missing verification token.' });
  }

  try {
    const payload = jwt.verify(token, process.env.EMAIL_VERIFY_SECRET);

    if (payload.purpose !== 'email_verification') {
      return res.status(400).json({ message: 'Invalid verification token.' });
    }

    const user = findUserById(payload.sub);

    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    user.emailVerified = true;

    return res.json({ message: 'Email verified successfully.' });
  } catch {
    return res.status(400).json({ message: 'Invalid or expired verification token.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  const normalizedEmail = String(email || '').trim().toLowerCase();
  const user = findUserByEmail(normalizedEmail);

  if (!user) {
    return res.status(401).json({ message: 'Invalid email or password.' });
  }

  const passwordMatches = await bcrypt.compare(password || '', user.passwordHash);

  if (!passwordMatches) {
    return res.status(401).json({ message: 'Invalid email or password.' });
  }

  if (!user.emailVerified) {
    return res.status(403).json({
      message: 'Please verify your email before logging in.',
    });
  }

  setAuthCookies(res, user);

  return res.json({
    user: {
      id: user.id,
      email: user.email,
    },
  });
});

app.post('/api/auth/refresh', (req, res) => {
  const token = req.cookies[REFRESH_COOKIE];

  if (!token) {
    return res.status(401).json({ message: 'Missing refresh token.' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    const user = findUserById(payload.sub);

    if (!user || user.tokenVersion !== payload.tokenVersion) {
      clearAuthCookies(res);
      return res.status(401).json({ message: 'Invalid refresh token.' });
    }

    setAuthCookies(res, user);

    return res.json({
      user: {
        id: user.id,
        email: user.email,
      },
    });
  } catch {
    clearAuthCookies(res);
    return res.status(401).json({ message: 'Invalid or expired refresh token.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  try {
    const refreshToken = req.cookies[REFRESH_COOKIE];

    if (refreshToken) {
      try {
        const payload = jwt.verify(
          refreshToken,
          process.env.JWT_REFRESH_SECRET
        );

        const user = findUserById(payload.sub);

        if (user && user.tokenVersion === payload.tokenVersion) {
          user.tokenVersion += 1;
        }
      } catch {
        // Ignore invalid or expired refresh token during logout.
        // Logout should still clear browser cookies.
      }
    }

    clearAuthCookies(res);

    return res.status(204).send();
  } catch (error) {
    console.error('Logout error:', error);

    clearAuthCookies(res);

    return res.status(204).send();
  }
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  return res.json({
    user: {
      id: req.user.id,
      email: req.user.email,
    },
  });
});

app.listen(PORT, () => {
  console.log(`Auth API listening on http://localhost:${PORT}`);
});