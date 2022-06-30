declare global {
  // Please set FIREBASE_AUTH_EMULATOR_HOST environment variable in your wrangler.toml.
  // see: https://developers.cloudflare.com/workers/platform/environment-variables/#environment-variables-via-wrangler
  //
  // Example for wrangler.toml
  // [vars]
  // FIREBASE_AUTH_EMULATOR_HOST = "localhost:8080"
  //
  // # Override values for `--env production` usage
  // [env.production.vars]
  // FIREBASE_AUTH_EMULATOR_HOST = ""
  const FIREBASE_AUTH_EMULATOR_HOST: string | undefined;
}

function emulatorHost(): string | undefined {
  return FIREBASE_AUTH_EMULATOR_HOST;
}

/**
 * When true the SDK should communicate with the Auth Emulator for all API
 * calls and also produce unsigned tokens.
 */
export const useEmulator = (): boolean => {
  return !!emulatorHost();
};
