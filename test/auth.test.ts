import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import type { Config } from "../src/config.js";

const config: Config = {
  PORT: 3000,
  JWT_SECRET: "test-secret-that-is-at-least-32-characters-long",
  JWT_ISSUER: "test-issuer",
  JWT_AUDIENCE: "test-audience",
  ACCESS_TOKEN_TTL_SECONDS: 900,
  REFRESH_TOKEN_TTL_SECONDS: 604800
};

describe("authentication flow", () => {
  it("registers, accesses a protected route, rotates, and rejects reused refresh tokens", async () => {
    const app = createApp(config);
    const registered = await request(app).post("/auth/register").send({
      email: "Person@Example.com",
      password: "a-strong-test-password"
    });
    expect(registered.status).toBe(201);

    const profile = await request(app)
      .get("/me")
      .set("Authorization", `Bearer ${registered.body.accessToken}`);
    expect(profile.status).toBe(200);
    expect(profile.body.email).toBe("person@example.com");

    const refreshed = await request(app).post("/auth/refresh").send({
      refreshToken: registered.body.refreshToken
    });
    expect(refreshed.status).toBe(200);
    expect(refreshed.body.refreshToken).not.toBe(registered.body.refreshToken);

    const reused = await request(app).post("/auth/refresh").send({
      refreshToken: registered.body.refreshToken
    });
    expect(reused.status).toBe(401);
    expect(reused.body.error).toBe("REFRESH_TOKEN_REUSE");

    const familyRevoked = await request(app).post("/auth/refresh").send({
      refreshToken: refreshed.body.refreshToken
    });
    expect(familyRevoked.status).toBe(401);
  });

  it("does not reveal whether an unknown email or wrong password failed", async () => {
    const app = createApp(config);
    const response = await request(app).post("/auth/login").send({
      email: "missing@example.com",
      password: "a-strong-test-password"
    });
    expect(response.status).toBe(401);
    expect(response.body).toEqual({ error: "INVALID_CREDENTIALS" });
  });
});
