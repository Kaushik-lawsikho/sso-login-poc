const { requireAuth, verifyToken } = require('../middleware/auth');
const { requireRole, requireAdmin, checkPermission } = require('../middleware/rbac');
const { checkSessionActivity, initializeSession, cleanupExpiredSessions } = require('../middleware/sessionManager');
const jwt = require('jsonwebtoken');

jest.mock('jsonwebtoken');

describe('Authentication Middleware', () => {
  let mockReq, mockRes, mockNext;

  beforeEach(() => {
    mockReq = {
      session: {},
      headers: {}
    };
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    mockNext = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('requireAuth', () => {
    test('should pass with valid session', () => {
      mockReq.session.user = { id: 'user-123' };

      requireAuth(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    test('should return 401 without session', () => {
      mockReq.session = null;

      requireAuth(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Authentication required',
        message: 'Please log in to access this resource'
      });
    });

    test('should return 401 without user in session', () => {
      mockReq.session = {};

      requireAuth(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Authentication required',
        message: 'Please log in to access this resource'
      });
    });
  });

  describe('verifyToken', () => {
    test('should pass with valid Bearer token', () => {
      mockReq.headers.authorization = 'Bearer valid-token';
      jwt.verify.mockReturnValue({ userId: 'user-123' });

      verifyToken(mockReq, mockRes, mockNext);

      expect(jwt.verify).toHaveBeenCalledWith('valid-token', process.env.AUTH0_CLIENT_SECRET);
      expect(mockReq.user).toEqual({ userId: 'user-123' });
      expect(mockNext).toHaveBeenCalled();
    });

    test('should return 401 without authorization header', () => {
      mockReq.headers = {};

      verifyToken(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'No token provided',
        message: 'Authorization header with Bearer token required'
      });
    });

    test('should return 401 with invalid token format', () => {
      mockReq.headers.authorization = 'Invalid token';

      verifyToken(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'No token provided',
        message: 'Authorization header with Bearer token required'
      });
    });

    test('should return 401 with invalid token', () => {
      mockReq.headers.authorization = 'Bearer invalid-token';
      jwt.verify.mockImplementation(() => {
        throw new Error('Invalid token');
      });

      verifyToken(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Invalid token',
        message: 'Token verification failed'
      });
    });
  });
});

describe('Role-Based Access Control Middleware', () => {
  let mockReq, mockRes, mockNext;

  beforeEach(() => {
    mockReq = {
      session: {
        user: {
          id: 'user-123',
          roles: ['user']
        }
      }
    };
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    mockNext = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('requireRole', () => {
    test('should pass with required role', () => {
      mockReq.session.user.roles = ['admin', 'user'];

      requireRole(['admin'])(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    test('should return 403 without required role', () => {
      mockReq.session.user.roles = ['user'];

      requireRole(['admin'])(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Insufficient permissions',
        message: 'This resource requires one of the following roles: admin'
      });
    });

    test('should return 401 without session', () => {
      mockReq.session = null;

      requireRole(['admin'])(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Authentication required',
        message: 'Please log in to access this resource'
      });
    });
  });

  describe('requireAdmin', () => {
    test('should pass with admin role', () => {
      mockReq.session.user.isAdmin = true;

      requireAdmin(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    test('should return 403 without admin role', () => {
      mockReq.session.user.isAdmin = false;

      requireAdmin(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Admin access required',
        message: 'This resource requires administrator privileges'
      });
    });
  });

  describe('checkPermission', () => {
    test('should pass with required permission', () => {
      mockReq.session.user.permissions = ['read', 'write'];

      checkPermission('read')(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    test('should return 403 without required permission', () => {
      mockReq.session.user.permissions = ['read'];

      checkPermission('write')(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Permission denied',
        message: "This resource requires the 'write' permission"
      });
    });
  });
});

describe('Session Management Middleware', () => {
  let mockReq, mockRes, mockNext;

  beforeEach(() => {
    mockReq = {
      session: {
        user: {
          lastActivity: Date.now(),
          sessionStart: Date.now()
        }
      }
    };
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    mockNext = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('checkSessionActivity', () => {
    test('should pass with active session', () => {
      checkSessionActivity(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(mockReq.session.user.lastActivity).toBeDefined();
    });

    test('should pass without session', () => {
      mockReq.session = null;

      checkSessionActivity(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    test('should return 401 for expired session', () => {
      mockReq.session.user.sessionStart = Date.now() - (31 * 60 * 1000); // 31 minutes ago
      mockReq.session.destroy = jest.fn();

      checkSessionActivity(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Session expired',
        message: 'Your session has expired. Please log in again.'
      });
    });

    test('should return 401 for idle session', () => {
      mockReq.session.user.lastActivity = Date.now() - (16 * 60 * 1000); // 16 minutes ago
      mockReq.session.destroy = jest.fn();

      checkSessionActivity(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Session idle timeout',
        message: 'You have been idle too long. Please log in again.'
      });
    });
  });

  describe('initializeSession', () => {
    test('should initialize session start time', () => {
      mockReq.session.user.sessionStart = undefined;

      initializeSession(mockReq, mockRes, mockNext);

      expect(mockReq.session.user.sessionStart).toBeDefined();
      expect(mockNext).toHaveBeenCalled();
    });

    test('should pass without session', () => {
      mockReq.session = null;

      initializeSession(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('cleanupExpiredSessions', () => {
    test('should clean up expired sessions', () => {
      const sessions = {
        'session1': {
          user: {
            lastActivity: Date.now() - (20 * 60 * 1000), // 20 minutes ago
            sessionStart: Date.now() - (20 * 60 * 1000)
          }
        },
        'session2': {
          user: {
            lastActivity: Date.now() - (5 * 60 * 1000), // 5 minutes ago
            sessionStart: Date.now() - (5 * 60 * 1000)
          }
        }
      };

      const cleanedCount = cleanupExpiredSessions(sessions);

      expect(cleanedCount).toBe(1);
      expect(sessions['session1']).toBeUndefined();
      expect(sessions['session2']).toBeDefined();
    });
  });
});
