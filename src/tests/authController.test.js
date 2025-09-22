const { login, callback, logout, getProfile, getDashboard, refreshTokens, validateToken } = require('../controllers/authController');
const { getClient } = require('../config/oidc');

// Mock the OIDC client
jest.mock('../config/oidc');
jest.mock('jsonwebtoken');

describe('Auth Controller', () => {
  let mockReq, mockRes, mockNext;

  beforeEach(() => {
    mockReq = {
      session: {},
      body: {},
      headers: {}
    };
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
      redirect: jest.fn(),
      clearCookie: jest.fn()
    };
    mockNext = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('login', () => {
    test('should redirect to Auth0 login URL', () => {
      const mockClient = {
        authorizationUrl: jest.fn().mockReturnValue('https://auth0.com/authorize')
      };
      getClient.mockReturnValue(mockClient);

      login(mockReq, mockRes);

      expect(mockClient.authorizationUrl).toHaveBeenCalledWith({
        scope: 'openid profile email',
        response_type: 'code'
      });
      expect(mockRes.redirect).toHaveBeenCalledWith('https://auth0.com/authorize');
    });

    test('should handle login errors', () => {
      getClient.mockImplementation(() => {
        throw new Error('OIDC client error');
      });

      login(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Login failed',
        message: 'Unable to initiate login process'
      });
    });
  });

  describe('callback', () => {
    test('should process successful callback', async () => {
      const mockClient = {
        callbackParams: jest.fn().mockReturnValue({ code: 'test-code' }),
        callback: jest.fn().mockResolvedValue({
          claims: jest.fn().mockReturnValue({
            sub: 'user-123',
            email: 'test@example.com',
            name: 'Test User',
            picture: 'https://example.com/pic.jpg'
          }),
          access_token: 'access-token',
          refresh_token: 'refresh-token',
          expires_in: 3600
        })
      };
      getClient.mockReturnValue(mockClient);

      await callback(mockReq, mockRes);

      expect(mockReq.session.user).toBeDefined();
      expect(mockReq.session.user.email).toBe('test@example.com');
      expect(mockReq.session.user.roles).toEqual(['user']);
      expect(mockReq.session.user.isAdmin).toBe(false);
      expect(mockRes.redirect).toHaveBeenCalledWith('/dashboard');
    });

    test('should handle callback errors', async () => {
      const mockClient = {
        callbackParams: jest.fn().mockReturnValue({}),
        callback: jest.fn().mockRejectedValue(new Error('Callback error'))
      };
      getClient.mockReturnValue(mockClient);

      await callback(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Authentication failed',
        message: 'Unable to complete login process'
      });
    });
  });

  describe('logout', () => {
    test('should destroy session and redirect', () => {
      mockReq.session.destroy = jest.fn((callback) => callback(null));

      logout(mockReq, mockRes);

      expect(mockReq.session.destroy).toHaveBeenCalled();
      expect(mockRes.clearCookie).toHaveBeenCalledWith('connect.sid');
      expect(mockRes.redirect).toHaveBeenCalledWith('/');
    });

    test('should handle logout errors', () => {
      mockReq.session.destroy = jest.fn((callback) => callback(new Error('Destroy error')));

      logout(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Logout failed',
        message: 'Unable to complete logout'
      });
    });
  });

  describe('getProfile', () => {
    test('should return user profile when authenticated', () => {
      mockReq.session.user = {
        id: 'user-123',
        email: 'test@example.com',
        name: 'Test User'
      };

      getProfile(mockReq, mockRes);

      expect(mockRes.json).toHaveBeenCalledWith({
        user: mockReq.session.user,
        message: 'Profile retrieved successfully'
      });
    });

    test('should return 401 when not authenticated', () => {
      mockReq.session.user = null;

      getProfile(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Not authenticated',
        message: 'Please log in to view profile'
      });
    });
  });

  describe('getDashboard', () => {
    test('should return dashboard data when authenticated', () => {
      mockReq.session.user = {
        id: 'user-123',
        email: 'test@example.com',
        name: 'Test User'
      };

      getDashboard(mockReq, mockRes);

      expect(mockRes.json).toHaveBeenCalledWith({
        message: 'Welcome to your dashboard!',
        user: mockReq.session.user,
        timestamp: expect.any(String)
      });
    });

    test('should redirect to login when not authenticated', () => {
      mockReq.session.user = null;

      getDashboard(mockReq, mockRes);

      expect(mockRes.redirect).toHaveBeenCalledWith('/login');
    });
  });

  describe('refreshTokens', () => {
    test('should refresh tokens successfully', async () => {
      const mockClient = {
        refresh: jest.fn().mockResolvedValue({
          access_token: 'new-access-token',
          refresh_token: 'new-refresh-token',
          expires_in: 3600
        })
      };
      getClient.mockReturnValue(mockClient);
      mockReq.session.user = {
        refreshToken: 'old-refresh-token'
      };

      await refreshTokens(mockReq, mockRes, mockNext);

      expect(mockClient.refresh).toHaveBeenCalledWith('old-refresh-token');
      expect(mockReq.session.user.accessToken).toBe('new-access-token');
      expect(mockReq.session.user.refreshToken).toBe('new-refresh-token');
      expect(mockNext).toHaveBeenCalled();
    });

    test('should handle missing refresh token', async () => {
      mockReq.session.user = {};

      await refreshTokens(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'No refresh token available'
      });
    });

    test('should handle refresh errors', async () => {
      const mockClient = {
        refresh: jest.fn().mockRejectedValue(new Error('Refresh failed'))
      };
      getClient.mockReturnValue(mockClient);
      mockReq.session.user = {
        refreshToken: 'invalid-token'
      };
      mockReq.session.destroy = jest.fn();

      await refreshTokens(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Token refresh failed',
        message: 'Please log in again'
      });
    });
  });

  describe('validateToken', () => {
    test('should pass validation for valid token', () => {
      mockReq.session.user = {
        accessToken: 'valid-token',
        tokenExpiry: Date.now() + 3600000
      };

      validateToken(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    test('should handle missing access token', () => {
      mockReq.session.user = {};

      validateToken(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'No access token available'
      });
    });

    test('should trigger refresh for expiring token', async () => {
      const mockClient = {
        refresh: jest.fn().mockResolvedValue({
          access_token: 'new-token',
          expires_in: 3600
        })
      };
      getClient.mockReturnValue(mockClient);
      mockReq.session.user = {
        accessToken: 'expiring-token',
        tokenExpiry: Date.now() + 1000, // Expires in 1 second
        refreshToken: 'refresh-token'
      };

      await validateToken(mockReq, mockRes, mockNext);

      expect(mockClient.refresh).toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalled();
    });
  });
});
