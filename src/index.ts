import { BaseAuth } from './auth';
import { AuthApiClient } from './auth-api-requests';
import type { RetryConfig } from './client';
import type { Credential } from './credential';
import type { KeyStorer } from './key-store';
import { WorkersKVStore } from './key-store';

export { type Credential, ServiceAccountCredential } from './credential';
export { emulatorHost, useEmulator } from './emulator';
export type { KeyStorer };
export type { EmulatorEnv } from './emulator';
export type { FirebaseIdToken } from './token-verifier';
export type { RetryConfig };

export class Auth extends BaseAuth {
  private static instance?: Auth;
  private static withCredential?: Auth;

  private constructor(projectId: string, keyStore: KeyStorer, credential?: Credential) {
    super(projectId, keyStore, credential);
  }

  static getOrInitialize(projectId: string, keyStore: KeyStorer, credential?: Credential): Auth {
    if (!Auth.withCredential && credential !== undefined) {
      Auth.withCredential = new Auth(projectId, keyStore, credential);
    }
    if (Auth.withCredential) {
      return Auth.withCredential;
    }
    if (!Auth.instance) {
      Auth.instance = new Auth(projectId, keyStore);
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

export class AdminAuthApiClient extends AuthApiClient {
  private static instance?: AdminAuthApiClient;

  private constructor(projectId: string, credential: Credential, retryConfig?: RetryConfig) {
    super(projectId, credential, retryConfig);
  }

  static getOrInitialize(projectId: string, credential: Credential, retryConfig?: RetryConfig) {
    if (!AdminAuthApiClient.instance) {
      AdminAuthApiClient.instance = new AdminAuthApiClient(projectId, credential, retryConfig);
    }
    return AdminAuthApiClient.instance;
  }
}
