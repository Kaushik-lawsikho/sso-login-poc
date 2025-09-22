require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const { initializeOIDC } = require('./config/oidc');
const authRoutes = require('./routes/auth');
const { errorHandler, notFound } = require('./middleware/errorHandler');

const app = express();
const PORT = process.env.PORT || 3000;

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});

app.use(helmet());
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://yourdomain.com'] 
    : ['http://localhost:3000', 'http://localhost:3001'],
  credentials: true
}));
app.use(limiter);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

app.get('/', (req, res) => {
  res.json({
    message: 'SSO Authentication API',
    status: 'running',
    endpoints: {
      login: '/auth/login',
      logout: '/auth/logout',
      profile: '/auth/profile',
      dashboard: '/auth/dashboard'
    }
  });
});

// Signup route (redirects to Auth0 login)
app.get('/signup', (req, res) => {
  res.redirect('/auth/login');
});

// Direct callback route for Auth0
app.get('/callback', require('./controllers/authController').callback);

// Direct dashboard route
app.get('/dashboard', require('./middleware/auth').requireAuth, require('./controllers/authController').getDashboard);

app.use('/auth', authRoutes);

app.use(notFound);
app.use(errorHandler);

const startServer = async () => {
  try {
    await initializeOIDC();
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Environment: ${process.env.NODE_ENV}`);
      console.log(`Auth0 Domain: ${process.env.AUTH0_DOMAIN}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

if (require.main === module) {
  startServer();
}

module.exports = app;
