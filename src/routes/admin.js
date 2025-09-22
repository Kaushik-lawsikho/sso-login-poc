const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { validateToken } = require('../controllers/authController');
const { requireAdmin } = require('../middleware/rbac');
const { 
  getUserRoles, 
  setUserRoles, 
  addUserRole, 
  removeUserRole, 
  hasRole, 
  isAdmin, 
  getUsersWithRole 
} = require('../utils/roleManager');

// All admin routes require authentication and admin role
router.use(requireAuth);
router.use(validateToken);
router.use(requireAdmin);

/**
 * @swagger
 * /admin/users:
 *   get:
 *     summary: Get all admin users
 *     description: Returns a list of all users with admin privileges
 *     tags: [Admin]
 *     security:
 *       - sessionAuth: []
 *     responses:
 *       200:
 *         description: Admin users retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Admin users retrieved successfully
 *                 users:
 *                   type: array
 *                   items:
 *                     type: string
 *                   description: List of admin user emails
 *                 count:
 *                   type: integer
 *                   description: Number of admin users
 *       401:
 *         description: Authentication required
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
 *       500:
 *         description: Failed to retrieve admin users
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get('/users', (req, res) => {
  try {
    const adminUsers = getUsersWithRole('admin');
    res.json({
      message: 'Admin users retrieved successfully',
      users: adminUsers,
      count: adminUsers.length
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Failed to retrieve admin users',
      message: error.message 
    });
  }
});

// Get user roles
router.get('/user/:email/roles', (req, res) => {
  try {
    const { email } = req.params;
    const roles = getUserRoles(email);
    
    res.json({
      email,
      roles,
      isAdmin: isAdmin(email)
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Failed to get user roles',
      message: error.message 
    });
  }
});

// Set user roles
router.post('/user/:email/roles', (req, res) => {
  try {
    const { email } = req.params;
    const { roles } = req.body;
    
    if (!Array.isArray(roles)) {
      return res.status(400).json({ 
        error: 'Invalid roles',
        message: 'Roles must be an array' 
      });
    }
    
    const success = setUserRoles(email, roles);
    if (success) {
      res.json({
        message: 'User roles updated successfully',
        email,
        roles
      });
    } else {
      res.status(500).json({ 
        error: 'Failed to update user roles' 
      });
    }
  } catch (error) {
    res.status(500).json({ 
      error: 'Failed to update user roles',
      message: error.message 
    });
  }
});

// Add role to user
router.post('/user/:email/roles/:role', (req, res) => {
  try {
    const { email, role } = req.params;
    
    const success = addUserRole(email, role);
    if (success) {
      res.json({
        message: 'Role added successfully',
        email,
        role
      });
    } else {
      res.status(500).json({ 
        error: 'Failed to add role' 
      });
    }
  } catch (error) {
    res.status(500).json({ 
      error: 'Failed to add role',
      message: error.message 
    });
  }
});

// Remove role from user
router.delete('/user/:email/roles/:role', (req, res) => {
  try {
    const { email, role } = req.params;
    
    const success = removeUserRole(email, role);
    if (success) {
      res.json({
        message: 'Role removed successfully',
        email,
        role
      });
    } else {
      res.status(500).json({ 
        error: 'Failed to remove role' 
      });
    }
  } catch (error) {
    res.status(500).json({ 
      error: 'Failed to remove role',
      message: error.message 
    });
  }
});

// Promote user to admin
router.post('/user/:email/promote', (req, res) => {
  try {
    const { email } = req.params;
    
    const success = addUserRole(email, 'admin');
    if (success) {
      res.json({
        message: 'User promoted to admin successfully',
        email
      });
    } else {
      res.status(500).json({ 
        error: 'Failed to promote user' 
      });
    }
  } catch (error) {
    res.status(500).json({ 
      error: 'Failed to promote user',
      message: error.message 
    });
  }
});

// Demote admin to user
router.post('/user/:email/demote', (req, res) => {
  try {
    const { email } = req.params;
    
    const success = removeUserRole(email, 'admin');
    if (success) {
      res.json({
        message: 'User demoted from admin successfully',
        email
      });
    } else {
      res.status(500).json({ 
        error: 'Failed to demote user' 
      });
    }
  } catch (error) {
    res.status(500).json({ 
      error: 'Failed to demote user',
      message: error.message 
    });
  }
});

module.exports = router;
