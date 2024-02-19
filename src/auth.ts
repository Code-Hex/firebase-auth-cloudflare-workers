import { AuthApiClient } from './auth-api-requests';
import type { Credential } from './credential';
import type { EmulatorEnv } from './emulator';
import { useEmulator } from './emulator';
import { AppErrorCodes, AuthClientErrorCode, FirebaseAppError, FirebaseAuthError } from './errors';
import type { KeyStorer } from './key-store';
import type { FirebaseIdToken, FirebaseTokenVerifier } from './token-verifier';
import { createIdTokenVerifier, createSessionCookieVerifier } from './token-verifier';
import { isNonNullObject, isNumber } from './validator';

export class BaseAuth {
  /** @internal */
  protected readonly idTokenVerifier: FirebaseTokenVerifier;
  protected readonly sessionCookieVerifier: FirebaseTokenVerifier;
  private readonly _authApiClient?: AuthApiClient;

  constructor(projectId: string, keyStore: KeyStorer, credential?: Credential) {
    this.idTokenVerifier = createIdTokenVerifier(projectId, keyStore);
    this.sessionCookieVerifier = createSessionCookieVerifier(projectId, keyStore);

    if (credential) {
      this._authApiClient = new AuthApiClient(projectId, credential);
    }
  }

  private get authApiClient(): AuthApiClient {
    if (this._authApiClient) {
      return this._authApiClient;
    }
    throw new FirebaseAppError(AppErrorCodes.INVALID_CREDENTIAL, 'Service account must be required in initialization.');
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
   * Creates a new Firebase session cookie with the specified options. The created
   * JWT string can be set as a server-side session cookie with a custom cookie
   * policy, and be used for session management. The session cookie JWT will have
   * the same payload claims as the provided ID token.
   *
   * See {@link https://firebase.google.com/docs/auth/admin/manage-cookies | Manage Session Cookies}
   * for code samples and detailed documentation.
   *
   * @param idToken - The Firebase ID token to exchange for a session
   *   cookie.
   * @param sessionCookieOptions - The session
   *   cookie options which includes custom session duration.
   * @param env - An optional parameter specifying the environment in which the function is running.
   *   If the function is running in an emulator environment, this should be set to `EmulatorEnv`.
   *   If not specified, the function will assume it is running in a production environment.
   *
   * @returns A promise that resolves on success with the
   *   created session cookie.
   */
  public async createSessionCookie(
    idToken: string,
    sessionCookieOptions: SessionCookieOptions,
    env?: EmulatorEnv
  ): Promise<string> {
    // Return rejected promise if expiresIn is not available.
    if (!isNonNullObject(sessionCookieOptions) || !isNumber(sessionCookieOptions.expiresIn)) {
      throw new FirebaseAuthError(AuthClientErrorCode.INVALID_SESSION_COOKIE_DURATION);
    }
    return await this.authApiClient.createSessionCookie(idToken, sessionCookieOptions.expiresIn, env);
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
   * @param env - An optional parameter specifying the environment in which the function is running.
   *   If the function is running in an emulator environment, this should be set to `EmulatorEnv`.
   *   If not specified, the function will assume it is running in a production environment.
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

/**
 * Interface representing the session cookie options needed for the
 * {@link BaseAuth.createSessionCookie} method.
 */
export interface SessionCookieOptions {
  /**
   * The session cookie custom expiration in milliseconds. The minimum allowed is
   * 5 minutes and the maxium allowed is 2 weeks.
   */
  expiresIn: number;
}
