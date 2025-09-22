// Role management utilities
const fs = require('fs');
const path = require('path');

const ROLES_FILE = path.join(__dirname, '../data/user-roles.json');

// Initialize roles file if it doesn't exist
const initializeRolesFile = () => {
  if (!fs.existsSync(ROLES_FILE)) {
    const defaultRoles = {
      "admin@yourdomain.com": ["admin", "user"],
      "superadmin@yourdomain.com": ["admin", "user", "superadmin"]
    };
    
    // Ensure directory exists
    const dir = path.dirname(ROLES_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    fs.writeFileSync(ROLES_FILE, JSON.stringify(defaultRoles, null, 2));
  }
};

// Get user roles from file
const getUserRoles = (email) => {
  try {
    initializeRolesFile();
    const rolesData = JSON.parse(fs.readFileSync(ROLES_FILE, 'utf8'));
    return rolesData[email] || ['user'];
  } catch (error) {
    console.error('Error reading user roles:', error);
    return ['user'];
  }
};

// Set user roles
const setUserRoles = (email, roles) => {
  try {
    initializeRolesFile();
    const rolesData = JSON.parse(fs.readFileSync(ROLES_FILE, 'utf8'));
    rolesData[email] = roles;
    fs.writeFileSync(ROLES_FILE, JSON.stringify(rolesData, null, 2));
    return true;
  } catch (error) {
    console.error('Error setting user roles:', error);
    return false;
  }
};

// Add role to user
const addUserRole = (email, role) => {
  const currentRoles = getUserRoles(email);
  if (!currentRoles.includes(role)) {
    currentRoles.push(role);
    return setUserRoles(email, currentRoles);
  }
  return true;
};

// Remove role from user
const removeUserRole = (email, role) => {
  const currentRoles = getUserRoles(email);
  const updatedRoles = currentRoles.filter(r => r !== role);
  return setUserRoles(email, updatedRoles);
};

// Check if user has role
const hasRole = (email, role) => {
  const roles = getUserRoles(email);
  return roles.includes(role);
};

// Check if user is admin
const isAdmin = (email) => {
  return hasRole(email, 'admin');
};

// Get all users with specific role
const getUsersWithRole = (role) => {
  try {
    initializeRolesFile();
    const rolesData = JSON.parse(fs.readFileSync(ROLES_FILE, 'utf8'));
    return Object.keys(rolesData).filter(email => rolesData[email].includes(role));
  } catch (error) {
    console.error('Error getting users with role:', error);
    return [];
  }
};

module.exports = {
  getUserRoles,
  setUserRoles,
  addUserRole,
  removeUserRole,
  hasRole,
  isAdmin,
  getUsersWithRole
};
