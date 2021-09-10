import jwt from "jsonwebtoken";

class UserService {
  constructor() {
    console.log("Initiating user service...");
  }

  getUserFromToken(req) {
    const token =
      req.body.token ||
      req.query.token ||
      req.headers["x-access-token"] ||
      req.cookies.access_token;
    if (token) {
      return jwt.verify(
        token,
        process.env.ACCESS_TOKEN_SECRET,
        (err, decoded) => {
          if (err) {
            return null;
          }
          return decoded;
        }
      );
    } else {
      return null;
    }
  }

  getUserFromRefreshToken(req) {
    //const token = req.body.refreshToken;
    const token = req.cookies.refreshToken;
    if (token) {
      return jwt.verify(
        token,
        process.env.REFRESH_TOKEN_SECRET,
        (err, decoded) => {
          if (err) {
            return null;
          }
          return decoded;
        }
      );
    } else {
      return null;
    }
  }

  getTokens(user) {
    // If the user object has a fresh token present, we make sure
    // to delete it. Otherwise we will be creating bigger and bigger tokens
    // every time a user logs in. (Since there will be more characters to encode).
    if (user.refreshToken) {
      delete user.refreshToken;
    }
    const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
      expiresIn: parseInt(process.env.ACCESS_TOKEN_LIFETIME),
    });
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, {
      expiresIn: parseInt(process.env.REFRESH_TOKEN_LIFETIME),
    });
    return {
      status: "Success",
      token: token,
      refreshToken: refreshToken,
    };
  }
}

export default new UserService();
