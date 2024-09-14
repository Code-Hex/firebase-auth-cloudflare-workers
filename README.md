# firebase-auth-cloudflare-workers-x509

A fork of <https://github.com/Code-Hex/firebase-auth-cloudflare-workers>

- Use X.509 certificate endpoints instead of JWK endpoints, as the original firebase-admin also uses X.509. The JWK endpoint presents issues due to the `no-cache` on the public key response for session cookies.
- Remove the checks that verify `iat` and `auth_time` are not in the future, aligning with the original firebase-admin behavior and preventing errors caused by slight clock skew.

This library uses [PKI.js](https://github.com/PeculiarVentures/PKI.js) for X.509 certificate parsing.
