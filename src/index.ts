import { BaseAuth } from './auth';
import type { Credential } from './credential';
import type { KeyStorer } from './key-store';
import { WorkersKVStore } from './key-store';

export { type Credential, ServiceAccountCredential } from './credential';
export { emulatorHost, useEmulator } from './emulator';
export type { KeyStorer };
export type { EmulatorEnv } from './emulator';
export type { FirebaseIdToken } from './token-verifier';

export class Auth extends BaseAuth {
  private static instance?: Auth;

  private constructor(projectId: string, keyStore: KeyStorer, credential?: Credential) {
    super(projectId, keyStore, credential);
  }

  static getOrInitialize(projectId: string, keyStore: KeyStorer, credential?: Credential): Auth {
    if (!Auth.instance) {
      Auth.instance = new Auth(projectId, keyStore, credential);
    }
    return Auth.instance;
  }
}

export class WorkersKVStoreSingle extends WorkersKVStore {
  private static instance?: WorkersKVStoreSingle;

  private constructor(cacheKey: string, cfKVNamespace: KVNamespace) {
    super(cacheKey, cfKVNamespace);
  }

  static getOrInitialize(cacheKey: string, cfKVNamespace: KVNamespace): WorkersKVStoreSingle {
    if (!WorkersKVStoreSingle.instance) {
      WorkersKVStoreSingle.instance = new WorkersKVStoreSingle(cacheKey, cfKVNamespace);
    }
    return WorkersKVStoreSingle.instance;
  }
}
