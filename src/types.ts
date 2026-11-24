export type User = {
  id: string;
  email: string;
  passwordHash: string;
  createdAt: Date;
};

export type RefreshSession = {
  id: string;
  familyId: string;
  userId: string;
  tokenHash: string;
  expiresAt: Date;
  createdAt: Date;
  replacedById?: string;
  revokedAt?: Date;
};
