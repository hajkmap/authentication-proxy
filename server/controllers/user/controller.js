import bcrypt from "bcrypt";
import UserService from "../../services/user.service";
import UsersRepository from "../../repositories/users.repository";
import msalConfig from "../../config/msal";

const msal = require("@azure/msal-node");
const cca = new msal.ConfidentialClientApplication(msalConfig);
class Controller {
  // Handles user logins
  login(req, res) {
    // Get the user from database
    const user = UsersRepository.getUserByEmail(req.body.email);
    // If the provided email does not return a user, the email
    // cannot be valid.
    if (!user) {
      return res.status(401).json({ status: "Login failed" });
    }
    // Compare the hashed password against the supplied password
    if (bcrypt.compareSync(req.body.password, user.password)) {
      // If they match, the login was successful, and we return
      // an access-token as well as a new refresh token.
      const tokens = UserService.getTokens(user);
      // We have to make sure to update the refresh token in the database as well.
      UsersRepository.updateRefreshToken(user, tokens.refreshToken);
      //return res.status(200).json(tokens);
      return res
        .cookie("token", tokens.token, {
          httpOnly: true,
        })
        .cookie("refreshToken", tokens.refreshToken, {
          httpOnly: true,
        })
        .status(200)
        .json({ status: "Success" });
    } else {
      // If the password does not match, the password cannot be valid.
      return res.status(401).json({ status: "Login failed" });
    }
  }

  // Handles user registrations. The user registration mode can be set
  // on three different levels:
  // - "ON": Anyone can register
  // - "ADMIN_ONLY": Only users with the admin-role can register users
  // - "OFF": No one can register users
  // If the key is missing, anyone can register.
  register(req, res) {
    // If the registration mode is set to off, return right away.
    if (process.env.USER_REGISTRATION_MODE === "OFF") {
      return res
        .status(401)
        .json({ message: "New registrations are not accepted" });
      // If the user registration mode is set to admin only, get user from
      // token, and check if they have the admin role.
    } else if (process.env.USER_REGISTRATION_MODE === "ADMIN_ONLY") {
      const user = UserService.getUserFromToken(req);
      // If no token is provided, or the provided token returns a user
      // without the admin role, return.
      if (!user || user.role !== "admin") {
        return res
          .status(401)
          .json({ message: "New registrations only accepted from admin" });
      }
    }
    // Otherwise, we check if the provided email already exists in the database.
    // If it does, return.
    if (UsersRepository.getUserByEmail(req.body.email)) {
      return res.status(409).json({ message: "Email already exists" });
    }
    // Hash the provided password so that we can save it in the database.
    const hash = bcrypt.hashSync(req.body.password, 10);

    // Create the user object...
    const user = {
      firstName: req.body.firstName ?? "",
      lastName: req.body.lastName ?? "",
      email: req.body.email ?? "",
      password: hash,
      role: process.env.DEFAULT_USER_ROLE,
    };

    // let's create access-token and refresh token.
    const tokens = UserService.getTokens(user);

    // Add the refresh token to the user so that we can save it in the db
    user.refreshToken = tokens.refreshToken;

    // ...and save it to the database.
    UsersRepository.create(user);

    // Finally, send the tokens to the user.
    return res.status(200).json(tokens);
  }

  // Expects a refresh token in the body, and if the refresh token is still
  // valid we provide a new refresh and access token to the user.
  refreshToken(req, res) {
    // Let's make sure the token is still valid by verifying it
    const user = UserService.getUserFromRefreshToken(req);
    if (!user) {
      return res
        .status(401)
        .json({ message: "Refresh token is no longer valid" });
    }
    // If a user is returned, the refresh is valid. However,
    // we still have to make sure that the refresh token is still in the database,
    // otherwise, we have no way to force a user to login again.

    // Let's get the user corresponding to the provided email...
    const dbUser = UsersRepository.getUserByEmail(user.email) ?? {};

    // ...and make sure the refresh token in the database matches the supplied one.
    if (dbUser.refreshToken === req.cookies?.refreshToken) {
      // If they match, we can update the refresh token in the database
      // and provide new tokens to the user.
      const tokens = UserService.getTokens(dbUser);
      UsersRepository.updateRefreshToken(dbUser, tokens.refreshToken);
      //return res.status(200).json(tokens);
      return res
        .cookie("token", tokens.token, {
          httpOnly: true,
        })
        .cookie("refreshToken", tokens.refreshToken, {
          httpOnly: true,
        })
        .redirect(`${decodeURIComponent(req.query.path)}`);
    }
    // If they for some reason doesn't match (an admin might have removed their token
    // from the database) they will have to login again.
    return res.redirect(`/login/?path=${req.query.path}`);
  }

  msal(req, res) {
    cca
      .getAuthCodeUrl(msalConfig.authCodeUrlParameters)
      .then((response) => {
        res.redirect(response);
      })
      .catch((error) => {
        return res.status(401).json({ status: "Login failed" });
      });
  }

  msalRedirect(req, res) {
    const tokenRequest = {
      code: req.query.code,
      redirectUri: process.env.MSAL_REDIRECT_URL,
      scopes: ["User.Read"],
    };

    cca
      .acquireTokenByCode(tokenRequest)
      .then((response) => {
        res.redirect("/");
      })
      .catch((error) => {
        return res.status(401).json({ status: "Login failed" });
      });
  }
}
export default new Controller();
