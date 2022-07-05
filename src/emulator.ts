export interface Env {
  FIREBASE_AUTH_EMULATOR_HOST: string | undefined
}

export function emulatorHost(env?: Env): string | undefined {
  return env?.FIREBASE_AUTH_EMULATOR_HOST;
}

/**
 * When true the SDK should communicate with the Auth Emulator for all API
 * calls and also produce unsigned tokens.
 */
export const useEmulator = (env?: Env): boolean => {
  return !!emulatorHost(env);
};
