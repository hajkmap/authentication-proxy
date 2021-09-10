import "./env";
import cors from "cors";
import compression from "compression";
import Express from "express";
import helmet from "helmet";
import * as http from "http";
import * as path from "path";
import { createProxyMiddleware } from "http-proxy-middleware";

const cookieParser = require("cookie-parser");

import authenticate from "./middlewares/authenticate";

const app = new Express();
const exit = process.exit;

// Routes that should be ignored by proxy and authentication
const allowedRoutes = ["\\/user\\/*", "\\/login\\/*"];

export default class ExpressServer {
  constructor() {
    app.use(
      helmet({
        contentSecurityPolicy: false, // If active, we get errors loading inline <script>
        frameguard: false, // If active, other pages can't embed our maps
      })
    );

    app.use(
      cors({
        origin: "*",
        optionsSuccessStatus: 200, // some legacy browsers (IE11, various SmartTVs) choke on 204
      })
    );

    app.use(compression());
    app.use(Express.json());
    app.use(cookieParser());

    this.setupAuthentication();
    this.setupExternalProxy();
    this.setupInternalProxy();
    this.setupStaticViews();
  }

  // Used to ignore internal paths. If req.path matches one of the allowed
  // routes, we simply run next(), and if they are not matching, we run the middleware.
  unless(routes, middleware) {
    return function (req, res, next) {
      const pathCheck = routes.some((route) => {
        return new RegExp(route).test(req.path);
      });
      pathCheck ? next() : middleware(req, res, next);
    };
  }

  setupAuthentication() {
    app.use(this.unless(allowedRoutes, authenticate));
  }

  /**
   * @summary Create proxies for endpoints specified in DOTENV as "PROXY_*".
   * @issue https://github.com/hajkmap/Hajk/issues/824
   * @memberof ExpressServer
   */
  setupExternalProxy() {
    try {
      // Convert the settings from DOTENV to a nice Array of Objects.
      const proxyMap = Object.entries(process.env)
        .filter(([k, v]) => k.startsWith("PROXY_"))
        .map(([k, v]) => {
          // Get rid of the leading "PROXY_" and convert to lower case
          k = k.replace("PROXY_", "").toLowerCase();
          return { context: k, target: v };
        });

      proxyMap.forEach((v) => {
        // Grab context and target from current element
        const context = v.context;
        const target = v.target;

        // Create the proxy itself
        app.use(
          `/proxy/${context}`,
          createProxyMiddleware({
            target: target,
            changeOrigin: true,
            pathRewrite: {
              [`^/proxy/${context}`]: "", // remove base path
            },
          })
        );
      });
    } catch (error) {
      return { error };
    }
  }

  /**
   * @summary Proxies everything against the application defined as "TARGET" in .env".
   * @memberof ExpressServer
   */
  setupInternalProxy() {
    // Hack to make POST, PUT, and DELETE requests to work... Will look into
    // it more later.
    const reStream = (proxyReq, req, res, options) => {
      if (req.body) {
        const bodyData = JSON.stringify(req.body);
        // incase if content-type is application/x-www-form-urlencoded -> we need to change to application/json
        proxyReq.setHeader("Content-Type", "application/json");
        proxyReq.setHeader("Content-Length", Buffer.byteLength(bodyData));
        // stream the content
        proxyReq.write(bodyData);
      }
    };

    app.use(
      this.unless(
        allowedRoutes,
        createProxyMiddleware({
          target: process.env.TARGET,
          changeOrigin: false,
          onProxyReq: reStream,
        })
      )
    );
  }

  setupStaticViews() {
    app.use(
      "/login",
      Express.static(path.join(process.cwd(), "server", "views", "login"))
    );
  }

  router(routes) {
    this.routes = routes;
    routes(app);
    return this;
  }

  listen(port = process.env.PORT) {
    const welcome = (p) => () => {
      console.log(
        `Server startup completed. Launched on port ${p}. (http://localhost:${p})`
      );
    };

    try {
      http.createServer(app).listen(port, welcome(port));
    } catch (e) {
      console.log("Error on startup, ", e);
      exit(1);
    }

    return app;
  }
}
