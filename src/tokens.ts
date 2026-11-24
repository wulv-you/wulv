import { SignJWT, jwtVerify } from "jose";
import type { Config } from "./config.js";

export class TokenService {
  private readonly key: Uint8Array;

  constructor(private readonly config: Config) {
    this.key = new TextEncoder().encode(config.JWT_SECRET);
  }

  async signAccessToken(userId: string): Promise<string> {
    return new SignJWT({ scope: "api:read" })
      .setProtectedHeader({ alg: "HS256", typ: "JWT" })
      .setSubject(userId)
      .setIssuer(this.config.JWT_ISSUER)
      .setAudience(this.config.JWT_AUDIENCE)
      .setIssuedAt()
      .setExpirationTime(`${this.config.ACCESS_TOKEN_TTL_SECONDS}s`)
      .sign(this.key);
  }

  async verifyAccessToken(token: string): Promise<string> {
    const { payload } = await jwtVerify(token, this.key, {
      algorithms: ["HS256"],
      issuer: this.config.JWT_ISSUER,
      audience: this.config.JWT_AUDIENCE
    });
    if (!payload.sub) throw new Error("MISSING_SUBJECT");
    return payload.sub;
  }
}
