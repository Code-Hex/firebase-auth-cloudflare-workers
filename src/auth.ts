import type { EmulatorEnv } from './emulator';
import { useEmulator } from './emulator';
import type { KeyStorer } from './key-store';
import type { FirebaseIdToken, FirebaseTokenVerifier } from './token-verifier';
import { createIdTokenVerifier, createSessionCookieVerifier } from './token-verifier';

export class BaseAuth {
  /** @internal */
  protected readonly idTokenVerifier: FirebaseTokenVerifier;
  protected readonly sessionCookieVerifier: FirebaseTokenVerifier;

  constructor(projectId: string, keyStore: KeyStorer) {
    this.idTokenVerifier = createIdTokenVerifier(projectId, keyStore);
    this.sessionCookieVerifier = createSessionCookieVerifier(projectId, keyStore);
  }

  /**
   * Verifies a Firebase ID token (JWT). If the token is valid, the promise is
   * fulfilled with the token's decoded claims; otherwise, the promise is
   * rejected.
   *
   * See {@link https://firebase.google.com/docs/auth/admin/verify-id-tokens | Verify ID Tokens}
   * for code samples and detailed documentation.
   *
   * @returns A promise fulfilled with the
   *   token's decoded claims if the ID token is valid; otherwise, a rejected
   *   promise.
   */
  public verifyIdToken(idToken: string, env?: EmulatorEnv): Promise<FirebaseIdToken> {
    const isEmulator = useEmulator(env);
    return this.idTokenVerifier.verifyJWT(idToken, isEmulator);
  }

  /**
   * Verifies a Firebase session cookie. Returns a Promise with the cookie claims.
   * Rejects the promise if the cookie could not be verified.
   *
   * If `checkRevoked` is set to true, first verifies whether the corresponding
   * user is disabled: If yes, an `auth/user-disabled` error is thrown. If no,
   * verifies if the session corresponding to the session cookie was revoked.
   * If the corresponding user's session was invalidated, an
   * `auth/session-cookie-revoked` error is thrown. If not specified the check
   * is not performed.
   *
   * See {@link https://firebase.google.com/docs/auth/admin/manage-cookies#verify_session_cookie_and_check_permissions |
   * Verify Session Cookies}
   * for code samples and detailed documentation
   *
   * @param sessionCookie - The session cookie to verify.
   *
   * @returns A promise fulfilled with the
   *   session cookie's decoded claims if the session cookie is valid; otherwise,
   *   a rejected promise.
   */
  public verifySessionCookie(sessionCookie: string, env?: EmulatorEnv): Promise<FirebaseIdToken> {
    const isEmulator = useEmulator(env);
    return this.sessionCookieVerifier.verifyJWT(sessionCookie, isEmulator);
  }
}
