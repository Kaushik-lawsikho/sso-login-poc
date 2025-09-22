const { getClient } = require('../config/oidc');

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
    
    req.session.user = {
      id: tokenSet.claims().sub,
      email: tokenSet.claims().email,
      name: tokenSet.claims().name,
      picture: tokenSet.claims().picture,
      accessToken: tokenSet.access_token,
      refreshToken: tokenSet.refresh_token
    };
    
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
  getDashboard
};
