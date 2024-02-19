# firebase-auth-cloudflare-workers

**Zero-dependencies** firebase auth library for Cloudflare Workers.

- Implemented by only Web Standard API.
- Supported UTF-8.
- Supported Firebase Auth Emulator.

## Synopsis

```ts
import type { EmulatorEnv } from "firebase-auth-cloudflare-workers";
import { Auth, WorkersKVStoreSingle } from "firebase-auth-cloudflare-workers";

interface Bindings extends EmulatorEnv {
  PROJECT_ID: string
  PUBLIC_JWK_CACHE_KEY: string
  PUBLIC_JWK_CACHE_KV: KVNamespace
  FIREBASE_AUTH_EMULATOR_HOST: string
}

const verifyJWT = async (req: Request, env: Bindings): Promise<Response> => {
  const authorization = req.headers.get('Authorization')
  if (authorization === null) {
    return new Response(null, {
      status: 400,
    })
  }
  const jwt = authorization.replace(/Bearer\s+/i, "")
  const auth = Auth.getOrInitialize(
    env.PROJECT_ID,
    WorkersKVStoreSingle.getOrInitialize(env.PUBLIC_JWK_CACHE_KEY, env.PUBLIC_JWK_CACHE_KV)
  )
  const firebaseToken = await auth.verifyIdToken(jwt, env)

  return new Response(JSON.stringify(firebaseToken), {
    headers: {
      "Content-Type": "application/json"
    }
  })
}
```

### wrangler.toml

```toml
name = "firebase-auth-example"
compatibility_date = "2022-07-05"
workers_dev = true

[vars]
FIREBASE_AUTH_EMULATOR_HOST = "127.0.0.1:9099"
PROJECT_ID = "example-project12345"

# Specify cache key to store and get public jwk.
PUBLIC_JWK_CACHE_KEY = "public-jwk-cache-key"

[[kv_namespaces]]
binding = "PUBLIC_JWK_CACHE_KV"
id = ""
preview_id = "testingId"
```

### Module Worker syntax

```ts
export async function fetch(req: Request, env: Bindings) {
  return await verifyJWT(req, env)
}

export default { fetch };
```

### Service Worker syntax

```ts
declare global {
  const PROJECT_ID: string
  const PUBLIC_JWK_CACHE_KEY: string
  const PUBLIC_JWK_CACHE_KV: KVNamespace
  const FIREBASE_AUTH_EMULATOR_HOST: string
}

addEventListener('fetch', (event: FetchEvent) => {
  // Create env object for verifyIdToken API.
  const bindings: EmulatorEnv = {
    PROJECT_ID,
    PUBLIC_JWK_CACHE_KEY,
    PUBLIC_JWK_CACHE_KV,
    FIREBASE_AUTH_EMULATOR_HOST,
  }
  event.respondWith(verifyJWT(event.request, bindings))
})
```

## Install

You can install from npm registry.

```
$ npm i firebase-auth-cloudflare-workers
```

## Docs

- [API](#api)
- [Type](#type)
- [Run example code](#run-example-code)
- [Todo](#todo)

## API

### `Auth.getOrInitialize(projectId: string, keyStore: KeyStorer): Auth`

Auth is created as a singleton object. This is because the Module Worker syntax only use environment variables at the time of request.

- `projectId` specifies the ID of the project for which firebase auth is used.
- `keyStore` is used to cache the public key used to validate the Firebase ID token (JWT).

See official document for project ID: https://firebase.google.com/docs/projects/learn-more#project-identifiers

### `authObj.verifyIdToken(idToken: string, env?: EmulatorEnv): Promise<FirebaseIdToken>`

Verifies a Firebase ID token (JWT). If the token is valid, the promise is fulfilled with the token's decoded claims; otherwise, the promise is rejected.

See the [ID Token section of the OpenID Connect spec](http://openid.net/specs/openid-connect-core-1_0.html#IDToken) for more information about the specific properties below.

- `env` is an optional parameter. but this is using to detect should use emulator or not.

### `WorkersKVStoreSingle.getOrInitialize(cacheKey: string, cfKVNamespace: KVNamespace): WorkersKVStoreSingle`

WorkersKVStoreSingle is created as a singleton object. This is because the Module Worker syntax only use environment variables at the time of request.

This caches the public key used to verify the Firebase ID token in the [Workers KV](https://developers.cloudflare.com/workers/runtime-apis/kv/).

This is implemented `KeyStorer` interface.

- `cacheKey` specifies the key of the public key cache.
- `cfKVNamespace` specifies the KV namespace which is bound your workers.

### `emulatorHost(env?: EmulatorEnv): string | undefined`

Returns the host of your Firebase Auth Emulator. For example, this case returns `"127.0.0.1:9099"` if you configured like below.

`wrangler.toml`

```toml
[vars]
FIREBASE_AUTH_EMULATOR_HOST = "127.0.0.1:9099"
```

### `useEmulator(env?: EmulatorEnv): boolean`

This is a wrapper `emulatorHost` function.

When true the SDK should communicate with the Auth Emulator for all API calls and also produce unsigned tokens.

## Type

### `KeyStorer`

This is an interface to cache the public key used to verify the Firebase ID token. By creating a class that implemented this interface, you can cache it in any storage of your choice.

```ts
interface KeyStorer {
  get<ExpectedValue = unknown>(): Promise<ExpectedValue | null>;
  put(value: string, expirationTtl: number): Promise<void>;
}
```

### `EmulatorEnv`

```ts
interface EmulatorEnv {
  FIREBASE_AUTH_EMULATOR_HOST: string | undefined
}
```

### `FirebaseIdToken`

Interface representing a decoded Firebase ID token, returned from the `authObj.verifyIdToken` method.

## Run example code

I put an [example](https://github.com/Code-Hex/firebase-auth-cloudflare-workers/tree/master/example) directory as Module Worker Syntax. this is explanation how to run the code.

1. Clone this repository and change your directory to it.
2. Install dev dependencies as `pnpm` command.
3. Run firebase auth emulator by `$ pnpm start-firebase-emulator`
4. Access to Emulator UI in your favorite browser.
5. Create a new user on Emulator UI. (email: `test@example.com` password: `test1234`)
6. Run example code on local (may serve as `localhost:8787`) by `$ pnpm start-example`
7. Get jwt for created user by `$ curl -s http://localhost:8787/get-jwt | jq .idToken -r`
8. Try authorization with user jwt `$ curl http://localhost:8787/ -H 'Authorization: Bearer PASTE-JWT-HERE'`

## Todo

### Non-required service account key.

- [x] IDToken verification

### Required service account key.

- [ ] Check authorized user is deleted (revoked)
