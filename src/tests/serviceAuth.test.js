const {
  generateServiceToken,
  verifyServiceToken,
  generateUserSessionToken,
  verifyUserSessionToken,
  checkServiceHealth,
  requireServiceAuth
} = require('../services/serviceAuth');
const jwt = require('jsonwebtoken');

jest.mock('jsonwebtoken');
jest.mock('node-fetch');

describe('Service Authentication', () => {
  let mockReq, mockRes, mockNext;

  beforeEach(() => {
    mockReq = {
      headers: {},
      body: {}
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

  describe('generateServiceToken', () => {
    test('should generate valid service token', () => {
      jwt.sign.mockReturnValue('mock-service-token');

      const token = generateServiceToken('auth-service', 'user-service');

      expect(jwt.sign).toHaveBeenCalledWith(
        {
          service: 'auth-service',
          target: 'user-service',
          timestamp: expect.any(Number),
          type: 'service-to-service'
        },
        process.env.SERVICE_SECRET || process.env.SESSION_SECRET,
        { expiresIn: '5m' }
      );
      expect(token).toBe('mock-service-token');
    });
  });

  describe('verifyServiceToken', () => {
    test('should verify valid service token', () => {
      const mockPayload = {
        service: 'auth-service',
        target: 'user-service',
        type: 'service-to-service'
      };
      jwt.verify.mockReturnValue(mockPayload);

      const result = verifyServiceToken('valid-token');

      expect(jwt.verify).toHaveBeenCalledWith(
        'valid-token',
        process.env.SERVICE_SECRET || process.env.SESSION_SECRET
      );
      expect(result).toEqual(mockPayload);
    });

    test('should throw error for invalid token', () => {
      jwt.verify.mockImplementation(() => {
        throw new Error('Invalid token');
      });

      expect(() => {
        verifyServiceToken('invalid-token');
      }).toThrow('Invalid service token');
    });
  });

  describe('generateUserSessionToken', () => {
    test('should generate valid user session token', () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        roles: ['user'],
        isAdmin: false,
        sessionId: 'session-123'
      };
      jwt.sign.mockReturnValue('mock-user-token');

      const token = generateUserSessionToken(mockUser, 'order-service');

      expect(jwt.sign).toHaveBeenCalledWith(
        {
          userId: 'user-123',
          email: 'test@example.com',
          roles: ['user'],
          isAdmin: false,
          sessionId: 'session-123',
          targetService: 'order-service',
          timestamp: expect.any(Number),
          type: 'user-session'
        },
        process.env.SESSION_SECRET,
        { expiresIn: '30m' }
      );
      expect(token).toBe('mock-user-token');
    });
  });

  describe('verifyUserSessionToken', () => {
    test('should verify valid user session token', () => {
      const mockPayload = {
        userId: 'user-123',
        email: 'test@example.com',
        type: 'user-session'
      };
      jwt.verify.mockReturnValue(mockPayload);

      const result = verifyUserSessionToken('valid-token');

      expect(jwt.verify).toHaveBeenCalledWith('valid-token', process.env.SESSION_SECRET);
      expect(result).toEqual(mockPayload);
    });

    test('should throw error for invalid token type', () => {
      const mockPayload = {
        userId: 'user-123',
        type: 'invalid-type'
      };
      jwt.verify.mockReturnValue(mockPayload);

      expect(() => {
        verifyUserSessionToken('invalid-token');
      }).toThrow('Invalid user session token');
    });

    test('should throw error for invalid token', () => {
      jwt.verify.mockImplementation(() => {
        throw new Error('Invalid token');
      });

      expect(() => {
        verifyUserSessionToken('invalid-token');
      }).toThrow('Invalid user session token');
    });
  });

  describe('checkServiceHealth', () => {
    test('should return true for healthy service', async () => {
      const fetch = require('node-fetch');
      fetch.mockResolvedValue({ ok: true });

      const result = await checkServiceHealth('user-service');

      expect(result).toBe(true);
      expect(fetch).toHaveBeenCalledWith('http://localhost:3001/health');
    });

    test('should return false for unhealthy service', async () => {
      const fetch = require('node-fetch');
      fetch.mockResolvedValue({ ok: false });

      const result = await checkServiceHealth('user-service');

      expect(result).toBe(false);
    });

    test('should return false for service not in registry', async () => {
      const result = await checkServiceHealth('unknown-service');

      expect(result).toBe(false);
    });

    test('should handle fetch errors', async () => {
      const fetch = require('node-fetch');
      fetch.mockRejectedValue(new Error('Network error'));

      const result = await checkServiceHealth('user-service');

      expect(result).toBe(false);
    });
  });

  describe('requireServiceAuth', () => {
    test('should pass with valid service token', () => {
      mockReq.headers.authorization = 'Bearer valid-service-token';
      jwt.verify.mockReturnValue({
        service: 'auth-service',
        type: 'service-to-service'
      });

      requireServiceAuth(mockReq, mockRes, mockNext);

      expect(mockReq.service).toBeDefined();
      expect(mockNext).toHaveBeenCalled();
    });

    test('should return 401 without authorization header', () => {
      mockReq.headers = {};

      requireServiceAuth(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Service authentication required',
        message: 'Authorization header with service token required'
      });
    });

    test('should return 401 with invalid token', () => {
      mockReq.headers.authorization = 'Bearer invalid-token';
      jwt.verify.mockImplementation(() => {
        throw new Error('Invalid token');
      });

      requireServiceAuth(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Invalid service token',
        message: 'Service authentication failed'
      });
    });
  });
});
