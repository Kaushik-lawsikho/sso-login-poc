const { getClient } = require('../config/oidc');
const jwt = require('jsonwebtoken');

const refreshTokens = async (req, res, next) => {
  try {
    if (!req.session.user || !req.session.user.refreshToken) {
      return res.status(401).json({ error: 'No refresh token available' });
    }

    const client = getClient();
    const tokenSet = await client.refresh(req.session.user.refreshToken);
    
    req.session.user.accessToken = tokenSet.access_token;
    req.session.user.refreshToken = tokenSet.refresh_token || req.session.user.refreshToken;
    req.session.user.tokenExpiry = Date.now() + (tokenSet.expires_in * 1000);
    
    console.log('Tokens refreshed successfully');
    next();
  } catch (error) {
    console.error('Token refresh failed:', error);
    req.session.destroy();
    return res.status(401).json({ 
      error: 'Token refresh failed',
      message: 'Please log in again'
    });
  }
};

// Token validation middleware
const validateToken = (req, res, next) => {
  if (!req.session.user || !req.session.user.accessToken) {
    return res.status(401).json({ error: 'No access token available' });
  }

  // Check if token is expired or about to expire (within 5 minutes)
  const now = Date.now();
  const tokenExpiry = req.session.user.tokenExpiry || 0;
  const fiveMinutes = 5 * 60 * 1000;

  if (tokenExpiry && (now + fiveMinutes) >= tokenExpiry) {
    console.log('Token needs refresh');
    return refreshTokens(req, res, next);
  }

  next();
};

const login = (req, res) => {
  try {
    const client = getClient();
    const authUrl = client.authorizationUrl({
      scope: 'openid profile email',
      response_type: 'code'
    });
    
    res.redirect(authUrl);
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      error: 'Login failed',
      message: 'Unable to initiate login process'
    });
  }
};

const callback = async (req, res) => {
  try {
    const client = getClient();
    const params = client.callbackParams(req);
    const tokenSet = await client.callback(process.env.AUTH0_CALLBACK_URL, params);
    
    // Extract user roles from Auth0 claims or assign default role
    const claims = tokenSet.claims();
    let userRoles = claims['https://yourdomain.com/roles'] || claims.roles || ['user'];
    
    // Auto-assign admin based on email domain or specific users
    const adminEmails = process.env.ADMIN_EMAILS ? process.env.ADMIN_EMAILS.split(',') : [];
    const adminDomains = process.env.ADMIN_DOMAINS ? process.env.ADMIN_DOMAINS.split(',') : [];
    
    const userEmail = claims.email;
    const isEmailAdmin = adminEmails.includes(userEmail);
    const isDomainAdmin = adminDomains.some(domain => userEmail.endsWith(`@${domain}`));
    
    if (isEmailAdmin || isDomainAdmin) {
      if (!userRoles.includes('admin')) {
        userRoles.push('admin');
      }
    }
    
    const isAdmin = userRoles.includes('admin');
    
    req.session.user = {
      id: tokenSet.claims().sub,
      email: tokenSet.claims().email,
      name: tokenSet.claims().name,
      picture: tokenSet.claims().picture,
      roles: userRoles,
      isAdmin: isAdmin,
      accessToken: tokenSet.access_token,
      refreshToken: tokenSet.refresh_token,
      tokenExpiry: Date.now() + (tokenSet.expires_in * 1000),
      lastActivity: Date.now()
    };
    
    console.log(`User ${req.session.user.email} logged in with roles: ${userRoles.join(', ')}`);
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Callback error:', error);
    res.status(500).json({ 
      error: 'Authentication failed',
      message: 'Unable to complete login process'
    });
  }
};

const logout = (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ 
        error: 'Logout failed',
        message: 'Unable to complete logout'
      });
    }
    
    res.clearCookie('connect.sid');
    res.redirect('/');
  });
};

const getProfile = (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ 
      error: 'Not authenticated',
      message: 'Please log in to view profile'
    });
  }
  
  res.json({
    user: req.session.user,
    message: 'Profile retrieved successfully'
  });
};

const getDashboard = (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  
  res.json({
    message: 'Welcome to your dashboard!',
    user: req.session.user,
    timestamp: new Date().toISOString()
  });
};

module.exports = {
  login,
  callback,
  logout,
  getProfile,
  getDashboard,
  refreshTokens,
  validateToken
};
