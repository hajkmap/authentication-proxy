import userRouter from "./controllers/user/router";

export default function routes(app) {
  app.use("/user", userRouter);
}
