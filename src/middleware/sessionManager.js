// Session management utilities
const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes
const MAX_IDLE_TIME = 15 * 60 * 1000; // 15 minutes

// Check session activity and timeout
const checkSessionActivity = (req, res, next) => {
  if (!req.session || !req.session.user) {
    return next();
  }

  const now = Date.now();
  const lastActivity = req.session.user.lastActivity || now;
  const sessionStart = req.session.user.sessionStart || now;

  // Check if session has exceeded maximum timeout
  if (now - sessionStart > SESSION_TIMEOUT) {
    req.session.destroy();
    return res.status(401).json({ 
      error: 'Session expired',
      message: 'Your session has expired. Please log in again.'
    });
  }

  // Check if user has been idle too long
  if (now - lastActivity > MAX_IDLE_TIME) {
    req.session.destroy();
    return res.status(401).json({ 
      error: 'Session idle timeout',
      message: 'You have been idle too long. Please log in again.'
    });
  }

  // Update last activity
  req.session.user.lastActivity = now;
  next();
};

// Initialize session data
const initializeSession = (req, res, next) => {
  if (req.session && req.session.user && !req.session.user.sessionStart) {
    req.session.user.sessionStart = Date.now();
  }
  next();
};

// Clean up expired sessions (can be called periodically)
const cleanupExpiredSessions = (sessions) => {
  const now = Date.now();
  const expiredSessions = [];

  for (const [sessionId, session] of Object.entries(sessions)) {
    if (session.user) {
      const lastActivity = session.user.lastActivity || 0;
      const sessionStart = session.user.sessionStart || 0;

      if (now - lastActivity > MAX_IDLE_TIME || now - sessionStart > SESSION_TIMEOUT) {
        expiredSessions.push(sessionId);
      }
    }
  }

  expiredSessions.forEach(sessionId => {
    delete sessions[sessionId];
  });

  return expiredSessions.length;
};

// Force logout user
const forceLogout = (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Force logout error:', err);
      return res.status(500).json({ 
        error: 'Logout failed',
        message: 'Unable to complete logout'
      });
    }
    
    res.clearCookie('connect.sid');
    res.json({ 
      message: 'Logged out successfully',
      reason: 'Session terminated by administrator'
    });
  });
};

module.exports = {
  checkSessionActivity,
  initializeSession,
  cleanupExpiredSessions,
  forceLogout
};
