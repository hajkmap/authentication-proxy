import jwt from "jsonwebtoken";

export default (req, res, next) => {
  const token =
    req.body.token ||
    req.query.token ||
    req.headers["x-access-token"] ||
    req.cookies.token;

  if (token) {
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
      if (err) {
        return res.redirect(
          `/user/refreshtoken/?path=${encodeURIComponent(req.path)}`
        );
      }
      return next();
    });
  } else {
    return res.redirect(`/login/?path=${encodeURIComponent(req.path)}`);
  }
};
