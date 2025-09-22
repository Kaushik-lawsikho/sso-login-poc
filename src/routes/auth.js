const express = require('express');
const router = express.Router();
const { login, callback, logout, getProfile, getDashboard, validateToken } = require('../controllers/authController');
const { requireAuth } = require('../middleware/auth');
const { requireRole, requireAdmin } = require('../middleware/rbac');

router.get('/login', login);
router.get('/callback', callback);
router.get('/logout', logout);
router.get('/profile', requireAuth, validateToken, getProfile);
router.get('/dashboard', requireAuth, validateToken, getDashboard);

// Role-based protected routes
router.get('/admin', requireAuth, validateToken, requireAdmin, (req, res) => {
  res.json({
    message: 'Admin dashboard',
    user: req.session.user,
    timestamp: new Date().toISOString()
  });
});

router.get('/user-management', requireAuth, validateToken, requireRole(['admin', 'moderator']), (req, res) => {
  res.json({
    message: 'User management panel',
    user: req.session.user,
    timestamp: new Date().toISOString()
  });
});

module.exports = router;
