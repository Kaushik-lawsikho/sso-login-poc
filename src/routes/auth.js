const express = require('express');
const router = express.Router();
const { login, callback, logout, getProfile, getDashboard, validateToken } = require('../controllers/authController');
const { requireAuth } = require('../middleware/auth');
const { requireRole, requireAdmin } = require('../middleware/rbac');

/**
 * @swagger
 * /auth/login:
 *   get:
 *     summary: Initiate user login
 *     description: |
 *       Redirects user to Auth0 for authentication. 
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
 *               example: https://your-domain.auth0.com/authorize?response_type=code&client_id=...
 *       500:
 *         description: Login initiation failed
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get('/login', login);

/**
 * @swagger
 * /auth/login-info:
 *   get:
 *     summary: Get login information
 *     description: Returns login URL and configuration without redirecting
 *     tags: [Authentication]
 *     responses:
 *       200:
 *         description: Login information retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 loginUrl:
 *                   type: string
 *                   description: Auth0 login URL
 *                   example: https://your-domain.auth0.com/authorize?response_type=code&client_id=...
 *                 message:
 *                   type: string
 *                   example: Navigate to loginUrl to authenticate
 *       500:
 *         description: Failed to generate login URL
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get('/login-info', (req, res) => {
  try {
    const { getClient } = require('../config/oidc');
    const client = getClient();
    const loginUrl = client.authorizationUrl({
      scope: 'openid profile email',
      response_type: 'code'
    });
    
    res.json({
      loginUrl,
      message: 'Navigate to loginUrl to authenticate'
    });
  } catch (error) {
    console.error('Login info error:', error);
    res.status(500).json({
      error: 'Failed to generate login URL',
      message: 'Unable to get authentication information'
    });
  }
});

/**
 * @swagger
 * /auth/callback:
 *   get:
 *     summary: Handle Auth0 callback
 *     description: |
 *       Processes the callback from Auth0 after user authentication.
 *       **Note**: This endpoint is called by Auth0, not directly by clients.
 *       It redirects to the dashboard on success.
 *     tags: [Authentication]
 *     parameters:
 *       - in: query
 *         name: code
 *         required: true
 *         schema:
 *           type: string
 *         description: Authorization code from Auth0
 *       - in: query
 *         name: state
 *         schema:
 *           type: string
 *         description: State parameter for CSRF protection
 *     responses:
 *       302:
 *         description: Redirect to dashboard on successful authentication
 *         headers:
 *           Location:
 *             description: Dashboard URL
 *             schema:
 *               type: string
 *               example: /dashboard
 *       500:
 *         description: Authentication failed
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get('/callback', callback);

/**
 * @swagger
 * /auth/logout:
 *   get:
 *     summary: Logout user
 *     description: Destroys user session and redirects to home page
 *     tags: [Authentication]
 *     security:
 *       - sessionAuth: []
 *     responses:
 *       302:
 *         description: Redirect to home page after logout
 *       500:
 *         description: Logout failed
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get('/logout', logout);

/**
 * @swagger
 * /auth/profile:
 *   get:
 *     summary: Get user profile
 *     description: Returns the authenticated user's profile information
 *     tags: [Authentication]
 *     security:
 *       - sessionAuth: []
 *     responses:
 *       200:
 *         description: User profile retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 user:
 *                   $ref: '#/components/schemas/User'
 *                 message:
 *                   type: string
 *                   example: Profile retrieved successfully
 *       401:
 *         description: Not authenticated
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get('/profile', requireAuth, validateToken, getProfile);

/**
 * @swagger
 * /auth/dashboard:
 *   get:
 *     summary: Get user dashboard
 *     description: Returns dashboard data for authenticated user
 *     tags: [Authentication]
 *     security:
 *       - sessionAuth: []
 *     responses:
 *       200:
 *         description: Dashboard data retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Welcome to your dashboard!
 *                 user:
 *                   $ref: '#/components/schemas/User'
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *       401:
 *         description: Not authenticated
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get('/dashboard', requireAuth, validateToken, getDashboard);

// Role-based protected routes
/**
 * @swagger
 * /auth/admin:
 *   get:
 *     summary: Admin dashboard
 *     description: Access admin-only dashboard (requires admin role)
 *     tags: [Authorization]
 *     security:
 *       - sessionAuth: []
 *     responses:
 *       200:
 *         description: Admin dashboard accessed successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Admin dashboard
 *                 user:
 *                   $ref: '#/components/schemas/User'
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *       401:
 *         description: Not authenticated
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       403:
 *         description: Admin access required
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get('/admin', requireAuth, validateToken, requireAdmin, (req, res) => {
  res.json({
    message: 'Admin dashboard',
    user: req.session.user,
    timestamp: new Date().toISOString()
  });
});

/**
 * @swagger
 * /auth/user-management:
 *   get:
 *     summary: User management panel
 *     description: Access user management panel (requires admin or moderator role)
 *     tags: [Authorization]
 *     security:
 *       - sessionAuth: []
 *     responses:
 *       200:
 *         description: User management panel accessed successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: User management panel
 *                 user:
 *                   $ref: '#/components/schemas/User'
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *       401:
 *         description: Not authenticated
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       403:
 *         description: Insufficient permissions
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get('/user-management', requireAuth, validateToken, requireRole(['admin', 'moderator']), (req, res) => {
  res.json({
    message: 'User management panel',
    user: req.session.user,
    timestamp: new Date().toISOString()
  });
});

module.exports = router;
