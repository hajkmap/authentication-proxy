import * as express from "express";
import controller from "./controller";

export default express
  .Router()
  .post("/login", controller.login)
  .post("/register", controller.register)
  .get("/refreshtoken", controller.refreshToken)
  .get(
    "/msal",
    process.env.MSAL_ACTIVE === "true"
      ? controller.msal
      : controller.notImplemented
  )
  .get(
    "/msal-redirect",
    process.env.MSAL_ACTIVE === "true"
      ? controller.msalRedirect
      : controller.notImplemented
  );
