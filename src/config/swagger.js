const swaggerJsdoc = require('swagger-jsdoc');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'SSO Authentication API',
      version: '1.0.0',
      description: 'A comprehensive Single Sign-On authentication system with Auth0, OpenID Connect, role-based access control, and multi-service integration.',
      contact: {
        name: 'API Support',
        email: 'support@example.com'
      },
      license: {
        name: 'MIT',
        url: 'https://opensource.org/licenses/MIT'
      }
    },
    servers: [
      {
        url: 'http://localhost:3000',
        description: 'Development server'
      },
      {
        url: 'https://yourdomain.com',
        description: 'Production server'
      }
    ],
    components: {
      securitySchemes: {
        sessionAuth: {
          type: 'apiKey',
          in: 'cookie',
          name: 'connect.sid',
          description: 'Session-based authentication'
        },
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'JWT token authentication'
        },
        serviceAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'Service-to-service JWT authentication'
        }
      },
      schemas: {
        User: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Unique user identifier'
            },
            email: {
              type: 'string',
              format: 'email',
              description: 'User email address'
            },
            name: {
              type: 'string',
              description: 'User full name'
            },
            picture: {
              type: 'string',
              format: 'uri',
              description: 'User profile picture URL'
            },
            roles: {
              type: 'array',
              items: {
                type: 'string'
              },
              description: 'User roles'
            },
            isAdmin: {
              type: 'boolean',
              description: 'Whether user has admin privileges'
            },
            accessToken: {
              type: 'string',
              description: 'OAuth access token'
            },
            tokenExpiry: {
              type: 'integer',
              format: 'int64',
              description: 'Token expiration timestamp'
            },
            lastActivity: {
              type: 'integer',
              format: 'int64',
              description: 'Last activity timestamp'
            }
          }
        },
        Error: {
          type: 'object',
          properties: {
            error: {
              type: 'string',
              description: 'Error type'
            },
            message: {
              type: 'string',
              description: 'Error message'
            }
          }
        },
        ServiceToken: {
          type: 'object',
          properties: {
            token: {
              type: 'string',
              description: 'Generated service token'
            },
            expiresIn: {
              type: 'string',
              description: 'Token expiration time'
            }
          }
        },
        ServiceHealth: {
          type: 'object',
          properties: {
            status: {
              type: 'string',
              enum: ['healthy', 'unhealthy'],
              description: 'Service health status'
            },
            timestamp: {
              type: 'string',
              format: 'date-time',
              description: 'Health check timestamp'
            },
            services: {
              type: 'object',
              description: 'Individual service statuses'
            }
          }
        }
      }
    },
    tags: [
      {
        name: 'Authentication',
        description: 'User authentication and session management'
      },
      {
        name: 'Authorization',
        description: 'Role-based access control and permissions'
      },
      {
        name: 'Services',
        description: 'Multi-service integration and health monitoring'
      },
      {
        name: 'Admin',
        description: 'Administrative functions and user management'
      }
    ]
  },
  apis: ['./src/routes/*.js', './src/app.js']
};

const specs = swaggerJsdoc(options);

module.exports = specs;
