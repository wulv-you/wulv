import express, { type NextFunction, type Request, type Response } from "express";
import { z } from "zod";
import { AuthError, AuthService } from "./auth-service.js";
import type { Config } from "./config.js";
import { InMemoryStore } from "./store.js";
import { TokenService } from "./tokens.js";

const credentialsSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(12).max(128)
});
const refreshSchema = z.object({ refreshToken: z.string().min(32).max(256) });

export function createApp(config: Config) {
  const app = express();
  const store = new InMemoryStore();
  const tokens = new TokenService(config);
  const auth = new AuthService(store, tokens, config);

  app.disable("x-powered-by");
  app.use(express.json({ limit: "16kb" }));

  app.post("/auth/register", async (req, res, next) => {
    try {
      const input = credentialsSchema.parse(req.body);
      res.status(201).json(await auth.register(input.email, input.password));
    } catch (error) { next(error); }
  });

  app.post("/auth/login", async (req, res, next) => {
    try {
      const input = credentialsSchema.parse(req.body);
      res.json(await auth.login(input.email, input.password));
    } catch (error) { next(error); }
  });

  app.post("/auth/refresh", async (req, res, next) => {
    try {
      const input = refreshSchema.parse(req.body);
      res.json(await auth.refresh(input.refreshToken));
    } catch (error) { next(error); }
  });

  app.post("/auth/logout", (req, res, next) => {
    try {
      const input = refreshSchema.parse(req.body);
      auth.logout(input.refreshToken);
      res.status(204).end();
    } catch (error) { next(error); }
  });

  app.get("/me", authenticate(tokens), (req, res) => {
    const user = store.findUserById(res.locals.userId as string);
    if (!user) return res.status(404).json({ error: "USER_NOT_FOUND" });
    return res.json({ id: user.id, email: user.email, createdAt: user.createdAt });
  });

  app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (error instanceof z.ZodError) return res.status(400).json({ error: "INVALID_INPUT" });
    if (error instanceof AuthError) {
      const status = error.code === "EMAIL_EXISTS" ? 409 : 401;
      return res.status(status).json({ error: error.code });
    }
    console.error("Unhandled request error", error instanceof Error ? error.message : "unknown");
    return res.status(500).json({ error: "INTERNAL_ERROR" });
  });

  return app;
}

function authenticate(tokens: TokenService) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const [scheme, value] = req.headers.authorization?.split(" ") ?? [];
    if (scheme !== "Bearer" || !value) return res.status(401).json({ error: "UNAUTHORIZED" });
    try {
      res.locals.userId = await tokens.verifyAccessToken(value);
      return next();
    } catch {
      return res.status(401).json({ error: "UNAUTHORIZED" });
    }
  };
}
