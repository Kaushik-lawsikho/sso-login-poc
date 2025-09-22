require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const { initializeOIDC } = require('./config/oidc');
const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');
const { errorHandler, notFound } = require('./middleware/errorHandler');
const { checkSessionActivity, initializeSession } = require('./middleware/sessionManager');
const { validateToken } = require('./controllers/authController');
const { requireServiceAuth, checkServiceHealth, generateUserSessionToken } = require('./services/serviceAuth');
const swaggerSpecs = require('./config/swagger');
const swaggerUi = require('swagger-ui-express');

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
    maxAge: 30 * 60 * 1000 // 30 minutes
  }
}));

// Session management middleware
app.use(initializeSession);
app.use(checkSessionActivity);

/**
 * @swagger
 * /:
 *   get:
 *     summary: Get API information
 *     description: Returns basic information about the SSO Authentication API and available endpoints
 *     tags: [Authentication]
 *     responses:
 *       200:
 *         description: API information retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: SSO Authentication API
 *                 status:
 *                   type: string
 *                   example: running
 *                 endpoints:
 *                   type: object
 *                   description: Available API endpoints
 */
app.get('/', (req, res) => {
  res.json({
    message: 'SSO Authentication API',
    status: 'running',
    endpoints: {
      login: '/auth/login',
      logout: '/auth/logout',
      profile: '/auth/profile',
      dashboard: '/auth/dashboard',
      admin: '/auth/admin',
      userManagement: '/auth/user-management',
      adminUsers: '/admin/users',
      promoteUser: '/admin/user/:email/promote',
      demoteUser: '/admin/user/:email/demote',
      apiDocs: '/api-docs'
    }
  });
});

/**
 * @swagger
 * /signup:
 *   get:
 *     summary: User signup
 *     description: |
 *       Redirects to Auth0 login for user registration.
 *       **Note**: This endpoint performs a redirect and may not work properly in Swagger UI.
 *       Use in browser navigation or API clients that can handle redirects.
 *     tags: [Authentication]
 *     responses:
 *       302:
 *         description: Redirect to Auth0 login page
 *         headers:
 *           Location:
 *             description: Auth0 authorization URL
 *             schema:
 *               type: string
 *               example: /auth/login
 */
app.get('/signup', (req, res) => {
  res.redirect('/auth/login');
});

// Direct callback route for Auth0
app.get('/callback', require('./controllers/authController').callback);

// Direct dashboard route
app.get('/dashboard', require('./middleware/auth').requireAuth, require('./controllers/authController').getDashboard);

/**
 * @swagger
 * /health:
 *   get:
 *     summary: Health check endpoint
 *     description: Returns the health status of the authentication service
 *     tags: [Services]
 *     responses:
 *       200:
 *         description: Service is healthy
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ServiceHealth'
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    services: {
      auth: 'running',
      session: 'active'
    }
  });
});

// Service-to-service authentication endpoint
app.get('/auth/verify', requireServiceAuth, (req, res) => {
  res.json({
    valid: true,
    service: req.service.service,
    timestamp: new Date().toISOString()
  });
});

// Generate user session token for other services
app.post('/auth/service-token', require('./middleware/auth').requireAuth, (req, res) => {
  try {
    const { targetService } = req.body;
    if (!targetService) {
      return res.status(400).json({ error: 'targetService is required' });
    }

    const token = generateUserSessionToken(req.session.user, targetService);
    res.json({ token, expiresIn: '30m' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate service token' });
  }
});

// Swagger Documentation
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpecs, {
  customCss: '.swagger-ui .topbar { display: none }',
  customSiteTitle: 'SSO Authentication API Documentation'
}));

app.use('/auth', authRoutes);
app.use('/admin', adminRoutes);

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
