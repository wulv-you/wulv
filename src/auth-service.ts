import { randomUUID } from "node:crypto";
import type { Config } from "./config.js";
import { hashPassword, hashToken, newRefreshToken, verifyPassword } from "./crypto.js";
import { InMemoryStore } from "./store.js";
import { TokenService } from "./tokens.js";
import type { RefreshSession, User } from "./types.js";

export class AuthError extends Error {
  constructor(public readonly code: string) {
    super(code);
  }
}

export class AuthService {
  constructor(
    private readonly store: InMemoryStore,
    private readonly tokens: TokenService,
    private readonly config: Config
  ) {}

  async register(email: string, password: string) {
    const normalizedEmail = email.trim().toLowerCase();
    const user: User = {
      id: randomUUID(),
      email: normalizedEmail,
      passwordHash: await hashPassword(password),
      createdAt: new Date()
    };
    try {
      this.store.createUser(user);
    } catch {
      throw new AuthError("EMAIL_EXISTS");
    }
    return this.issueTokenPair(user.id);
  }

  async login(email: string, password: string) {
    const user = this.store.findUserByEmail(email.trim().toLowerCase());
    if (!user || !(await verifyPassword(password, user.passwordHash))) {
      throw new AuthError("INVALID_CREDENTIALS");
    }
    return this.issueTokenPair(user.id);
  }

  async refresh(rawToken: string) {
    const current = this.store.findSessionByTokenHash(hashToken(rawToken));
    if (!current) throw new AuthError("INVALID_REFRESH_TOKEN");

    if (current.revokedAt || current.replacedById) {
      this.store.revokeFamily(current.familyId);
      throw new AuthError("REFRESH_TOKEN_REUSE");
    }
    if (current.expiresAt.getTime() <= Date.now()) {
      this.store.revokeFamily(current.familyId);
      throw new AuthError("REFRESH_TOKEN_EXPIRED");
    }

    const next = this.createRefreshSession(current.userId, current.familyId);
    current.replacedById = next.session.id;
    this.store.saveSession(next.session);
    return {
      accessToken: await this.tokens.signAccessToken(current.userId),
      refreshToken: next.rawToken,
      tokenType: "Bearer",
      expiresIn: this.config.ACCESS_TOKEN_TTL_SECONDS
    };
  }

  logout(rawToken: string): void {
    const session = this.store.findSessionByTokenHash(hashToken(rawToken));
    if (session) this.store.revokeFamily(session.familyId);
  }

  private async issueTokenPair(userId: string) {
    const refresh = this.createRefreshSession(userId, randomUUID());
    this.store.saveSession(refresh.session);
    return {
      accessToken: await this.tokens.signAccessToken(userId),
      refreshToken: refresh.rawToken,
      tokenType: "Bearer",
      expiresIn: this.config.ACCESS_TOKEN_TTL_SECONDS
    };
  }

  private createRefreshSession(userId: string, familyId: string) {
    const rawToken = newRefreshToken();
    const session: RefreshSession = {
      id: randomUUID(),
      familyId,
      userId,
      tokenHash: hashToken(rawToken),
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + this.config.REFRESH_TOKEN_TTL_SECONDS * 1000)
    };
    return { rawToken, session };
  }
}
