import type { RefreshSession, User } from "./types.js";

export class InMemoryStore {
  private readonly usersById = new Map<string, User>();
  private readonly userIdsByEmail = new Map<string, string>();
  private readonly sessionsByHash = new Map<string, RefreshSession>();
  private readonly sessionsById = new Map<string, RefreshSession>();

  createUser(user: User): void {
    if (this.userIdsByEmail.has(user.email)) throw new Error("EMAIL_EXISTS");
    this.usersById.set(user.id, user);
    this.userIdsByEmail.set(user.email, user.id);
  }

  findUserByEmail(email: string): User | undefined {
    const id = this.userIdsByEmail.get(email);
    return id ? this.usersById.get(id) : undefined;
  }

  findUserById(id: string): User | undefined {
    return this.usersById.get(id);
  }

  saveSession(session: RefreshSession): void {
    this.sessionsByHash.set(session.tokenHash, session);
    this.sessionsById.set(session.id, session);
  }

  findSessionByTokenHash(hash: string): RefreshSession | undefined {
    return this.sessionsByHash.get(hash);
  }

  revokeFamily(familyId: string, at = new Date()): void {
    for (const session of this.sessionsById.values()) {
      if (session.familyId === familyId && !session.revokedAt) session.revokedAt = at;
    }
  }
}
