const { Issuer } = require('openid-client');

let client = null;

const initializeOIDC = async () => {
  try {
    const auth0Issuer = await Issuer.discover(`https://${process.env.AUTH0_DOMAIN}`);
    
    client = new auth0Issuer.Client({
      client_id: process.env.AUTH0_CLIENT_ID,
      client_secret: process.env.AUTH0_CLIENT_SECRET,
      redirect_uris: [process.env.AUTH0_CALLBACK_URL],
      response_types: ['code']
    });

    console.log('OIDC client initialized successfully');
    return client;
  } catch (error) {
    console.error('Failed to initialize OIDC client:', error);
    throw error;
  }
};

const getClient = () => {
  if (!client) {
    throw new Error('OIDC client not initialized');
  }
  return client;
};

module.exports = {
  initializeOIDC,
  getClient
};
