export default {
  authCodeUrlParameters: {
    scopes: ["User.Read"],
    redirectUri: process.env.MSAL_REDIRECT_URL,
  },
  // Depending on value of MSAL_TYPE, the 'auth' object
  // must contain different properties. We don't want
  // to duplicate 'auth' though, hence the conditional
  // property literal.
  ...(process.env.MSAL_TYPE === "client"
    ? {
        auth: {
          clientId: process.env.MSAL_CLIENT_ID,
          authority: process.env.MSAL_AUTHORITY,
          clientSecret: process.env.MSAL_CLIENT_SECRET,
        },
      }
    : {}),
  ...(process.env.MSAL_TYPE === "cert"
    ? {
        auth: {
          clientId: process.env.MSAL_CLIENT_ID,
          authority: process.env.MSAL_AUTHORITY,
          clientCertificate: {
            thumbprint: process.env.MSAL_CERT_THUMBPRINT, // a 40-digit hexadecimal string
            privateKey: process.env.MSAL_CERT_PRIVATE_KEY,
          },
        },
      }
    : {}),
};
