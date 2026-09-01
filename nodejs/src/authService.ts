import * as crypto from 'crypto';

export interface UserSession {
  userId: number;
  username: string;
  roles: string[];
  issuedAt: number;
  expiresAt: number;
}

export interface SecurityToken {
  tokenValue: string;
  expiresInSeconds: number;
}

export class AuthService {
  private readonly secretKey: Buffer;

  constructor() {
    const rawSecret = process.env.SESSION_SECRET_KEY;
    if (!rawSecret || rawSecret.length < 32) {
      // Fallback to runtime secure random bytes if environment key is missing
      this.secretKey = crypto.randomBytes(32);
    } else {
      this.secretKey = Buffer.from(rawSecret, 'utf-8');
    }
  }

  /**
   * Generates a cryptographically secure random session token.
   */
  public generateSessionToken(byteLength: number = 32): SecurityToken {
    const validLength = Math.max(16, Math.min(byteLength, 64));
    const tokenValue = crypto.randomBytes(validLength).toString('hex');

    return {
      tokenValue,
      expiresInSeconds: 3600,
    };
  }

  /**
   * Performs constant-time comparison between two security tokens to prevent timing attacks.
   */
  public verifyTokenEquals(expectedToken: string, providedToken: string): boolean {
    if (!expectedToken || !providedToken) {
      return false;
    }

    const bufExpected = Buffer.from(expectedToken, 'utf-8');
    const bufProvided = Buffer.from(providedToken, 'utf-8');

    if (bufExpected.length !== bufProvided.length) {
      return false;
    }

    return crypto.timingSafeEqual(bufExpected, bufProvided);
  }

  /**
   * Validates target redirect URL against an allowed domain list.
   * Prevents Open Redirect / SSRF vulnerabilities.
   */
  public isSafeRedirectUrl(targetUrl: string, allowedHostnames: string[]): boolean {
    try {
      const parsedUrl = new URL(targetUrl);
      if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
        return false;
      }
      return allowedHostnames.includes(parsedUrl.hostname);
    } catch {
      return false;
    }
  }
}
