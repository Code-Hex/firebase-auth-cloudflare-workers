import { ApiSettings } from './api-requests';
import { BaseClient } from './client';
import type { EmulatorEnv } from './emulator';
import { AuthClientErrorCode, FirebaseAuthError } from './errors';
import { isNonEmptyString, isNumber } from './validator';

/** Minimum allowed session cookie duration in seconds (5 minutes). */
const MIN_SESSION_COOKIE_DURATION_SECS = 5 * 60;

/** Maximum allowed session cookie duration in seconds (2 weeks). */
const MAX_SESSION_COOKIE_DURATION_SECS = 14 * 24 * 60 * 60;

/**
 * Instantiates the createSessionCookie endpoint settings.
 *
 * @internal
 */
export const FIREBASE_AUTH_CREATE_SESSION_COOKIE = new ApiSettings('v1', ':createSessionCookie', 'POST')
  // Set request validator.
  .setRequestValidator((request: any) => {
    // Validate the ID token is a non-empty string.
    if (!isNonEmptyString(request.idToken)) {
      throw new FirebaseAuthError(AuthClientErrorCode.INVALID_ID_TOKEN);
    }
    // Validate the custom session cookie duration.
    if (
      !isNumber(request.validDuration) ||
      request.validDuration < MIN_SESSION_COOKIE_DURATION_SECS ||
      request.validDuration > MAX_SESSION_COOKIE_DURATION_SECS
    ) {
      throw new FirebaseAuthError(AuthClientErrorCode.INVALID_SESSION_COOKIE_DURATION);
    }
  })
  // Set response validator.
  .setResponseValidator((response: any) => {
    // Response should always contain the session cookie.
    if (!isNonEmptyString(response.sessionCookie)) {
      throw new FirebaseAuthError(AuthClientErrorCode.INTERNAL_ERROR);
    }
  });

export class AuthApiClient extends BaseClient {
  /**
   * Creates a new Firebase session cookie with the specified duration that can be used for
   * session management (set as a server side session cookie with custom cookie policy).
   * The session cookie JWT will have the same payload claims as the provided ID token.
   *
   * @param idToken - The Firebase ID token to exchange for a session cookie.
   * @param expiresIn - The session cookie duration in milliseconds.
   * @param - An optional parameter specifying the environment in which the function is running.
   *   If the function is running in an emulator environment, this should be set to `EmulatorEnv`.
   *   If not specified, the function will assume it is running in a production environment.
   *
   * @returns A promise that resolves on success with the created session cookie.
   */
  public async createSessionCookie(idToken: string, expiresIn: number, env?: EmulatorEnv): Promise<string> {
    const request = {
      idToken,
      // Convert to seconds.
      validDuration: expiresIn / 1000,
    };
    return await this.fetch(FIREBASE_AUTH_CREATE_SESSION_COOKIE, request, env);
  }
}
