import { useEmulator } from "./emulator";
import {
  createIdTokenVerifier,
  FirebaseIdToken,
  FirebaseTokenVerifier,
} from "./token-verifier";

export class Auth {
  /** @internal */
  protected readonly idTokenVerifier: FirebaseTokenVerifier;

  constructor(
    projectId: string,
    cacheKey: string,
    cfPublicKeyCacheNamespace: KVNamespace
  ) {
    this.idTokenVerifier = createIdTokenVerifier(
      projectId,
      cacheKey,
      cfPublicKeyCacheNamespace
    );
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
  public verifyIdToken(idToken: string): Promise<FirebaseIdToken> {
    const isEmulator = useEmulator();
    return this.idTokenVerifier.verifyJWT(idToken, isEmulator);
  }
}
