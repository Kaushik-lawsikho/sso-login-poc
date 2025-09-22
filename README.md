# SSO Login System

A complete Single Sign-On authentication system with React frontend and Node.js backend using Auth0 and OpenID Connect.

## 🚀 Quick Start

### Option 1: Run Everything Together
```bash
npm run dev:full
```
This starts both backend (port 3000) and frontend (port 3001) automatically.

### Option 2: Run Separately

**Backend:**
```bash
npm run dev
```

**Frontend (in new terminal):**
```bash
cd frontend
npm start
```

## 🔧 Setup

1. **Install dependencies:**
   ```bash
   npm install
   cd frontend && npm install
   ```

2. **Configure Auth0:**
   - Create Auth0 account
   - Create new application (Regular Web App)
   - Add callback URL: `http://localhost:3000/callback`
   - Add logout URL: `http://localhost:3001`
   - Copy credentials to `.env`

3. **Create `.env` file:**
   ```bash
   cp env.example .env
   ```

## 📡 API Endpoints

### Public Routes
- `GET /` - API information
- `GET /auth/login` - Start authentication
- `GET /signup` - Sign up (redirects to login)
- `GET /callback` - Auth0 callback

### Protected Routes
- `GET /auth/profile` - Get user profile
- `GET /dashboard` - Dashboard data
- `GET /auth/logout` - Logout user

## 🎯 Frontend Features

- **Authentication Status**: Automatically detects if user is logged in
- **Profile Display**: Shows user info from Auth0
- **API Testing**: Buttons to test all endpoints
- **Responsive Design**: Works on mobile and desktop
- **Real-time Updates**: Automatically refreshes auth status

## 🔐 Security Features

- **CORS Protection**: Configured for frontend-backend communication
- **Session Management**: Secure session cookies
- **Rate Limiting**: 100 requests per 15 minutes
- **Security Headers**: Helmet.js protection
- **JWT Verification**: Token validation

## 🧪 Testing the Flow

1. **Visit**: `http://localhost:3001`
2. **Click "Login"** or **"Sign Up"**
3. **Complete Auth0 authentication**
4. **View your profile** and **test dashboard**
5. **Logout** when done

## 📁 Project Structure

```
sso-login/
├── src/                    # Backend source
│   ├── config/            # OIDC configuration
│   ├── controllers/       # Route handlers
│   ├── middleware/        # Auth & error handling
│   ├── routes/           # API routes
│   └── app.js            # Express server
├── frontend/              # React frontend
│   ├── src/
│   │   ├── App.tsx       # Main React component
│   │   └── App.css       # Styling
│   └── public/
└── package.json
```

## 🛠 Tech Stack

**Backend:**
- Node.js + Express.js
- OpenID Connect (OIDC)
- Auth0 Identity Provider
- express-session
- jsonwebtoken

**Frontend:**
- React + TypeScript
- Modern CSS with gradients
- Responsive design
- API integration

## 🔍 Troubleshooting

**CORS Issues:**
- Make sure frontend runs on port 3001
- Check CORS configuration in `src/app.js`

**Auth0 Issues:**
- Verify callback URL: `http://localhost:3000/callback`
- Check environment variables in `.env`
- Ensure Auth0 application is configured correctly

**Session Issues:**
- Check if cookies are enabled
- Verify SESSION_SECRET is set
- Clear browser cookies if needed