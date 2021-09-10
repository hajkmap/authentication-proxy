export default {
  auth: {
    clientId: process.env.MSAL_CLIENT_ID,
    authority: process.env.MSAL_AUTHORITY,
    clientSecret: process.env.MSAL_CLIENT_SECRET,
  },
  authCodeUrlParameters: {
    scopes: ["User.Read"],
    redirectUri: process.env.MSAL_REDIRECT_URL,
  },
};
