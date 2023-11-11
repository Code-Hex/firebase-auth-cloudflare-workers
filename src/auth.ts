import type { EmulatorEnv } from './emulator'
import { useEmulator } from './emulator'
import type { KeyStorer } from './key-store'
import type { FirebaseIdToken, FirebaseTokenVerifier } from './token-verifier'
import { createIdTokenVerifier } from './token-verifier'

export class BaseAuth {
  /** @internal */
  protected readonly idTokenVerifier: FirebaseTokenVerifier

  constructor(projectId: string, keyStore: KeyStorer) {
    this.idTokenVerifier = createIdTokenVerifier(projectId, keyStore)
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
    const isEmulator = useEmulator(env)
    return this.idTokenVerifier.verifyJWT(idToken, isEmulator)
  }
}
