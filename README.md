# firebase-auth-cloudflare-workers

**Zero-dependencies** firebase auth verification library for Cloudflare Workers.

- Implemented by only Web Standard API.
- Supported Firebase Auth Emulator.

```ts
export async function fetch(req: Request, env: Bindings) {
  const authorization = req.headers.get('Authorization')
  if (authorization === null) {
    return new Response(null, {
      status: 400,
    })
  }
  const jwt = authorization.replace(/Bearer\s+/i, "")
  const auth = Auth.getOrInitialize(
    env.PROJECT_ID,
    env.PUBLIC_JWK_CACHE_KEY,
    env.PUBLIC_JWK_CACHE_KV
  )
  const firebaseToken = await auth.verifyIdToken(jwt, env)

  return new Response(JSON.stringify(firebaseToken), {
    headers: {
      "Content-Type": "application/json"
    }
  })
}

export default { fetch };
```

## Running example code

I put an [example](https://github.com/Code-Hex/firebase-auth-cloudflare-workers/tree/master/example) directory as Module Worker Syntax. this is explanation how to run the code.

1. Clone this repository and change your directory to it.
2. Install dev dependencies as `yarn` command.
3. Run firebase auth emulator by `$ yarn start-firebase-emulator`
4. Access to Emulator UI in your favorite browser.
5. Create a new user on Emulator UI. (email: `test@example.com` password: `test1234`)
6. Run example code on local (may serve as `localhost:8787`) by `$ yarn start-example`
7. Get jwt for created user by `$ curl -s http://localhost:8787/get-jwt | jq .idToken -r`
8. Try authorization with user jwt `$ curl http://localhost:8787/ -H 'Authorization: Bearer PASTE-JWT-HERE'`