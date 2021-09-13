import jwt from "jsonwebtoken";
import UserService from "../services/user.service";
import UsersRepository from "../repositories/users.repository";

export default (req, res, next) => {
  // We'll only look for access-tokens in the cookies for now.
  const token =
    req.body.token ||
    req.query.token ||
    req.headers["x-access-token"] ||
    req.cookies.token;

  if (token) {
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
      // If the verification fails, the access-token might have expired.
      // Let's check if the provided refresh-token is still valid,
      // and if it is, we can use this to authenticate the request,
      // and update the tokens.
      if (err) {
        // First, we must get the user connected to the provided refresh-token
        const user = UserService.getUserFromRefreshToken(req);

        // If we can't find a matching user from the refresh-token,
        // we'll redirect the user to the login-page.
        if (!user) {
          return res.redirect(`/login/?path=${encodeURIComponent(req.path)}`);
        }

        // If a user is returned, the refresh is valid. However,
        // we still have to make sure that the refresh token is still in the database,
        // otherwise, we have no way to force a user to login again.

        // Let's get the user corresponding to the provided email...
        const dbUser = UsersRepository.getUserByEmail(user.email) ?? {};

        // ...and make sure the refresh token in the database matches the supplied one.
        // If they don't match, we redirect the user to the login screen.
        if (dbUser.refreshToken !== req.cookies?.refreshToken) {
          return res.redirect(`/login/?path=${encodeURIComponent(req.path)}`);
        }
        // If they do match, we can update the refresh token in the database
        // and provide new tokens to the user.
        const tokens = UserService.getTokens(dbUser);

        // Set new token in the database.
        UsersRepository.updateRefreshToken(dbUser, tokens.refreshToken);

        // Set new tokens in cookies
        res
          .cookie("token", tokens.token, {
            httpOnly: true,
          })
          .cookie("refreshToken", tokens.refreshToken, {
            httpOnly: true,
          });

        // And return next!
        return next();
      }
      // If the access-token is verified without issues, we just return next
      return next();
    });
    // If no token is supplied at all, we redirect to the login-page
  } else {
    return res.redirect(`/login/?path=${encodeURIComponent(req.path)}`);
  }
};
