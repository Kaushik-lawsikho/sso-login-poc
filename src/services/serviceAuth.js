// Multi-service authentication and session sharing
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');

// Generate service-to-service JWT token
const generateServiceToken = (serviceName, targetService) => {
  const payload = {
    service: serviceName,
    target: targetService,
    timestamp: Date.now(),
    type: 'service-to-service'
  };

  return jwt.sign(payload, process.env.SERVICE_SECRET || process.env.SESSION_SECRET, {
    expiresIn: '5m'
  });
};

// Verify service-to-service JWT token
const verifyServiceToken = (token) => {
  try {
    return jwt.verify(token, process.env.SERVICE_SECRET || process.env.SESSION_SECRET);
  } catch (error) {
    throw new Error('Invalid service token');
  }
};

// Generate user session token for cross-service sharing
const generateUserSessionToken = (user, targetService) => {
  const payload = {
    userId: user.id,
    email: user.email,
    roles: user.roles,
    isAdmin: user.isAdmin,
    sessionId: user.sessionId,
    targetService: targetService,
    timestamp: Date.now(),
    type: 'user-session'
  };

  return jwt.sign(payload, process.env.SESSION_SECRET, {
    expiresIn: '30m'
  });
};

// Verify user session token from another service
const verifyUserSessionToken = (token) => {
  try {
    const decoded = jwt.verify(token, process.env.SESSION_SECRET);
    if (decoded.type !== 'user-session') {
      throw new Error('Invalid token type');
    }
    return decoded;
  } catch (error) {
    throw new Error('Invalid user session token');
  }
};

// Service discovery and health check
const serviceRegistry = {
  'user-service': {
    url: process.env.USER_SERVICE_URL || 'http://localhost:3001',
    health: '/health',
    auth: '/auth/verify'
  },
  'order-service': {
    url: process.env.ORDER_SERVICE_URL || 'http://localhost:3002',
    health: '/health',
    auth: '/auth/verify'
  }
};

const checkServiceHealth = async (serviceName) => {
  const service = serviceRegistry[serviceName];
  if (!service) {
    console.warn(`Service ${serviceName} not found in registry`);
    return false;
  }

  try {
    const response = await fetch(`${service.url}${service.health}`);
    return response.ok;
  } catch (error) {
    console.error(`Health check failed for ${serviceName}:`, error);
    return false;
  }
};

// Middleware for service-to-service authentication
const requireServiceAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ 
      error: 'Service authentication required',
      message: 'Authorization header with service token required'
    });
  }

  const token = authHeader.substring(7);
  
  try {
    const decoded = verifyServiceToken(token);
    req.service = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ 
      error: 'Invalid service token',
      message: 'Service authentication failed'
    });
  }
};

module.exports = {
  generateServiceToken,
  verifyServiceToken,
  generateUserSessionToken,
  verifyUserSessionToken,
  checkServiceHealth,
  requireServiceAuth,
  serviceRegistry
};
