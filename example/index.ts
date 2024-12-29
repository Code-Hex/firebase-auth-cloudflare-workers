import { Hono } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import { csrf } from 'hono/csrf';
import { html } from 'hono/html';
import { Auth, ServiceAccountCredential, emulatorHost, WorkersKVStoreSingle, AdminAuthApiClient } from '../src';

type Env = {
  EMAIL_ADDRESS: string;
  PASSWORD: string;
  PUBLIC_JWK_CACHE_KV: KVNamespace;
  PROJECT_ID: string;
  PUBLIC_JWK_CACHE_KEY: string;

  FIREBASE_AUTH_EMULATOR_HOST: string; // satisfied EmulatorEnv
  // Set JSON as string.
  // See: https://cloud.google.com/iam/docs/keys-create-delete
  SERVICE_ACCOUNT_JSON: string;
};

const app = new Hono<{ Bindings: Env }>();

const signInPath = '/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=test1234';

app.get('/get-jwt', async c => {
  const firebaseEmuHost = emulatorHost(c.env);
  const firebaseEmulatorSignInUrl = 'http://' + firebaseEmuHost + signInPath;
  return await fetch(firebaseEmulatorSignInUrl, {
    method: 'POST',
    body: JSON.stringify({
      email: c.env.EMAIL_ADDRESS,
      password: c.env.PASSWORD,
      returnSecureToken: true,
    }),
    headers: {
      'Content-Type': 'application/json',
    },
  });
});

app.post('/verify-header', async c => {
  const authorization = c.req.raw.headers.get('Authorization');
  if (authorization === null) {
    return new Response(null, {
      status: 400,
    });
  }
  const jwt = authorization.replace(/Bearer\s+/i, '');
  const auth = Auth.getOrInitialize(
    c.env.PROJECT_ID,
    WorkersKVStoreSingle.getOrInitialize(c.env.PUBLIC_JWK_CACHE_KEY, c.env.PUBLIC_JWK_CACHE_KV)
  );
  const firebaseToken = await auth.verifyIdToken(jwt, false, c.env);

  return new Response(JSON.stringify(firebaseToken), {
    headers: {
      'Content-Type': 'application/json',
    },
  });
});

app.use('/admin/*', csrf());

app.get('/admin/login', async c => {
  const content = await html`<html>
    <head>
      <meta charset="UTF-8" />
      <title>Login</title>
    </head>
    <body>
      <h1>Login Page</h1>
      <button id="sign-in" type="button">Sign-In</button>
      <script type="module">
        // See https://firebase.google.com/docs/auth/admin/manage-cookies
        //
        import { initializeApp } from 'https://www.gstatic.com/firebasejs/11.0.2/firebase-app.js';
        import $ from 'https://cdn.skypack.dev/jquery';
        // Add Firebase products that you want to use
        import {
          getAuth,
          signInWithEmailAndPassword,
          onAuthStateChanged,
          connectAuthEmulator,
          signOut,
          setPersistence,
          inMemoryPersistence,
        } from 'https://www.gstatic.com/firebasejs/11.0.2/firebase-auth.js';
        const app = initializeApp({
          apiKey: 'test1234',
          authDomain: 'test',
          projectId: 'project12345',
        });
        const auth = getAuth(app);
        connectAuthEmulator(auth, 'http://127.0.0.1:9099');
        setPersistence(auth, inMemoryPersistence);

        /**
         * @param {string} name The cookie name.
         * @return {?string} The corresponding cookie value to lookup.
         */
        function getCookie(name) {
          const v = document.cookie.match('(^|;) ?' + name + '=([^;]*)(;|$)');
          return v ? v[2] : null;
        }

        /**
         * @param {string} url The session login endpoint.
         * @param {string} idToken The ID token to post to backend.
         * @return {any} A jQuery promise that resolves on completion.
         */
        function postIdTokenToSessionLogin(url, idToken) {
          // POST to session login endpoint.
          return $.ajax({
            type: 'POST',
            url: url,
            data: JSON.stringify({ idToken: idToken }),
            contentType: 'application/json',
          });
        }

        $('#sign-in').on('click', function () {
          console.log('clicked');

          signInWithEmailAndPassword(auth, 'test@example.com', 'test1234')
            .then(({ user }) => {
              // Get the user's ID token as it is needed to exchange for a session cookie.
              const idToken = user.accessToken;
              // Session login endpoint is queried and the session cookie is set.
              // CSRF protection should be taken into account.
              // ...
              const csrfToken = getCookie('csrfToken');
              return postIdTokenToSessionLogin('/admin/login_session', idToken, csrfToken);
            })
            .then(() => {
              // A page redirect would suffice as the persistence is set to NONE.
              return signOut(auth);
            })
            .then(() => {
              window.location.assign('/admin/profile');
            });
        });
      </script>
    </body>
  </html>`;
  return c.html(content);
});

app.post('/admin/login_session', async c => {
  const json = await c.req.json();
  const idToken = json.idToken;
  if (!idToken || typeof idToken !== 'string') {
    return c.json({ message: 'invalid idToken' }, 400);
  }
  // Set session expiration to 5 days.
  const expiresIn = 60 * 60 * 24 * 5;
  // Create the session cookie. This will also verify the ID token in the process.
  // The session cookie will have the same claims as the ID token.
  // To only allow session cookie setting on recent sign-in, auth_time in ID token
  // can be checked to ensure user was recently signed in before creating a session cookie.
  const auth = AdminAuthApiClient.getOrInitialize(
    c.env.PROJECT_ID,
    new ServiceAccountCredential(c.env.SERVICE_ACCOUNT_JSON)
  );
  const sessionCookie = await auth.createSessionCookie(
    idToken,
    expiresIn,
    c.env // This valus must be removed in real world
  );
  setCookie(c, 'session', sessionCookie, {
    maxAge: expiresIn,
    httpOnly: true,
    // secure: true // set this in real world
  });
  return c.json({ message: 'success' });
});

app.get('/admin/profile', async c => {
  const session = getCookie(c, 'session') ?? '';

  const auth = Auth.getOrInitialize(
    c.env.PROJECT_ID,
    WorkersKVStoreSingle.getOrInitialize(c.env.PUBLIC_JWK_CACHE_KEY, c.env.PUBLIC_JWK_CACHE_KV)
  );

  try {
    const decodedToken = await auth.verifySessionCookie(
      session,
      false,
      c.env // This valus must be removed in real world
    );
    return c.json(decodedToken);
  } catch (err) {
    return c.redirect('/admin/login');
  }
});

export default app;
