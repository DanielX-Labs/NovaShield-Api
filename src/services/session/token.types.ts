// Access tokens carry identifiers and credential version, never profile secrets.
export interface AccessTokenPayload {
  sub: string;
  sid: string;
  type: "access";
  ver: number;
}

// The complete refresh token exists only in memory and the browser's cookie.
export interface RefreshTokenParts {
  tokenId: string;
  secret: string;
  rawToken: string;
}
