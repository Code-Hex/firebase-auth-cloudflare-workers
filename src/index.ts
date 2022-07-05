import { BaseAuth } from "./auth"


export {
  emulatorHost,
  useEmulator
} from "./emulator"
export type { Env } from './emulator'

export class Auth extends BaseAuth {
  private static instance?: Auth;

  private constructor(
    projectId: string,
    cacheKey: string,
    cfPublicKeyCacheNamespace: KVNamespace
  ) {
    super(projectId, cacheKey, cfPublicKeyCacheNamespace)
  }

  static getOrInitialize(
    projectId: string,
    cacheKey: string,
    cfPublicKeyCacheNamespace: KVNamespace
  ): Auth {
    if (!Auth.instance) {
      Auth.instance = new Auth(
        projectId,
        cacheKey,
        cfPublicKeyCacheNamespace,
      )
    }
    return Auth.instance
  }
}
