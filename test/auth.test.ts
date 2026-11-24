import request from "supertest";
import assert from "node:assert/strict";
import { describe, it } from "node:test";
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
    assert.equal(registered.status, 201);

    const profile = await request(app)
      .get("/me")
      .set("Authorization", `Bearer ${registered.body.accessToken}`);
    assert.equal(profile.status, 200);
    assert.equal(profile.body.email, "person@example.com");

    const refreshed = await request(app).post("/auth/refresh").send({
      refreshToken: registered.body.refreshToken
    });
    assert.equal(refreshed.status, 200);
    assert.notEqual(refreshed.body.refreshToken, registered.body.refreshToken);

    const reused = await request(app).post("/auth/refresh").send({
      refreshToken: registered.body.refreshToken
    });
    assert.equal(reused.status, 401);
    assert.equal(reused.body.error, "REFRESH_TOKEN_REUSE");

    const familyRevoked = await request(app).post("/auth/refresh").send({
      refreshToken: refreshed.body.refreshToken
    });
    assert.equal(familyRevoked.status, 401);
  });

  it("does not reveal whether an unknown email or wrong password failed", async () => {
    const app = createApp(config);
    const response = await request(app).post("/auth/login").send({
      email: "missing@example.com",
      password: "a-strong-test-password"
    });
    assert.equal(response.status, 401);
    assert.deepEqual(response.body, { error: "INVALID_CREDENTIALS" });
  });
});
