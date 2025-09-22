const express = require('express');
const router = express.Router();
const { login, callback, logout, getProfile, getDashboard } = require('../controllers/authController');
const { requireAuth } = require('../middleware/auth');

router.get('/login', login);
router.get('/callback', callback);
router.get('/logout', logout);
router.get('/profile', requireAuth, getProfile);
router.get('/dashboard', requireAuth, getDashboard);

module.exports = router;
