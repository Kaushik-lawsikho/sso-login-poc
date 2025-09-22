const request = require('supertest');
const app = require('../app');

describe('SSO Authentication Flow', () => {
  let server;

  beforeAll(() => {
    server = app.listen(0);
  });

  afterAll(() => {
    server.close();
  });

  describe('Health Check', () => {
    test('GET /health should return service status', async () => {
      const response = await request(app)
        .get('/health')
        .expect(200);

      expect(response.body).toHaveProperty('status', 'healthy');
      expect(response.body).toHaveProperty('services');
    });
  });

  describe('Authentication Endpoints', () => {
    test('GET / should return API information', async () => {
      const response = await request(app)
        .get('/')
        .expect(200);

      expect(response.body).toHaveProperty('message', 'SSO Authentication API');
      expect(response.body).toHaveProperty('endpoints');
    });

    test('GET /signup should redirect to login', async () => {
      const response = await request(app)
        .get('/signup')
        .expect(302);

      expect(response.headers.location).toBe('/auth/login');
    });
  });

  describe('Protected Routes', () => {
    test('GET /dashboard without auth should redirect to login', async () => {
      const response = await request(app)
        .get('/dashboard')
        .expect(401);

      expect(response.body).toHaveProperty('error', 'Authentication required');
    });

    test('GET /auth/profile without auth should return 401', async () => {
      const response = await request(app)
        .get('/auth/profile')
        .expect(401);

      expect(response.body).toHaveProperty('error', 'Authentication required');
    });

    test('GET /auth/admin without auth should return 401', async () => {
      const response = await request(app)
        .get('/auth/admin')
        .expect(401);

      expect(response.body).toHaveProperty('error', 'Authentication required');
    });
  });

  describe('Role-Based Access Control', () => {
    const mockSession = {
      user: {
        id: 'test-user-123',
        email: 'test@example.com',
        name: 'Test User',
        roles: ['user'],
        isAdmin: false,
        accessToken: 'mock-access-token',
        tokenExpiry: Date.now() + 3600000,
        lastActivity: Date.now()
      }
    };

    test('GET /auth/admin with user role should return 403', async () => {
      const response = await request(app)
        .get('/auth/admin')
        .set('Cookie', `connect.sid=${JSON.stringify(mockSession)}`)
        .expect(403);

      expect(response.body).toHaveProperty('error', 'Admin access required');
    });

    test('GET /auth/user-management with user role should return 403', async () => {
      const response = await request(app)
        .get('/auth/user-management')
        .set('Cookie', `connect.sid=${JSON.stringify(mockSession)}`)
        .expect(403);

      expect(response.body).toHaveProperty('error', 'Insufficient permissions');
    });
  });

  describe('Service Authentication', () => {
    test('GET /auth/verify without service token should return 401', async () => {
      const response = await request(app)
        .get('/auth/verify')
        .expect(401);

      expect(response.body).toHaveProperty('error', 'Service authentication required');
    });

    test('POST /auth/service-token without auth should return 401', async () => {
      const response = await request(app)
        .post('/auth/service-token')
        .send({ targetService: 'test-service' })
        .expect(401);

      expect(response.body).toHaveProperty('error', 'Authentication required');
    });
  });

  describe('Error Handling', () => {
    test('GET /nonexistent should return 404', async () => {
      const response = await request(app)
        .get('/nonexistent')
        .expect(404);

      expect(response.body).toHaveProperty('error', 'Not Found');
    });
  });
});

describe('Token Management', () => {
  test('Token refresh should handle missing refresh token', () => {
    const { refreshTokens } = require('../controllers/authController');
    const mockReq = {
      session: { user: {} }
    };
    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };

    refreshTokens(mockReq, mockRes, jest.fn());
    expect(mockRes.status).toHaveBeenCalledWith(401);
  });

  test('Token validation should handle missing access token', () => {
    const { validateToken } = require('../controllers/authController');
    const mockReq = {
      session: { user: {} }
    };
    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };

    validateToken(mockReq, mockRes, jest.fn());
    expect(mockRes.status).toHaveBeenCalledWith(401);
  });
});

describe('Session Management', () => {
  test('Session activity check should handle missing session', () => {
    const { checkSessionActivity } = require('../middleware/sessionManager');
    const mockReq = {};
    const mockRes = {};
    const mockNext = jest.fn();

    checkSessionActivity(mockReq, mockRes, mockNext);
    expect(mockNext).toHaveBeenCalled();
  });
});
