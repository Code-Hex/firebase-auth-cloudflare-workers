import { Auth, emulatorHost, EmulatorEnv, WorkersKVStoreSingle } from "../src";

interface Bindings extends EmulatorEnv {
  EMAIL_ADDRESS: string
  PASSWORD: string
  FIREBASE_AUTH_EMULATOR_HOST: string
  PUBLIC_JWK_CACHE_KV: KVNamespace
  PROJECT_ID: string
  PUBLIC_JWK_CACHE_KEY: string
}

const signInPath = "/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=test1234"

export async function handleRequest(req: Request, env: Bindings) {
  const url = new URL(req.url)
  const firebaseEmuHost = emulatorHost(env)
  if (url.pathname === "/get-jwt" && !!firebaseEmuHost) {
    const firebaseEmulatorSignInUrl = "http://" + firebaseEmuHost + signInPath
    const resp = await fetch(firebaseEmulatorSignInUrl, {
      method: "POST",
      body: JSON.stringify({
        email: env.EMAIL_ADDRESS,
        password: env.PASSWORD,
        returnSecureToken: true,
      }),
      headers: {
        "Content-Type": "application/json"
      }
    })
    return resp
  }

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

export default { fetch: handleRequest };