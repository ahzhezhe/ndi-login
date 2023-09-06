# **ndi-login**
[![npm package](https://img.shields.io/npm/v/ndi-login)](https://www.npmjs.com/package/ndi-login)
[![npm downloads](https://img.shields.io/npm/dt/ndi-login)](https://www.npmjs.com/package/ndi-login)
[![GitHub issues](https://img.shields.io/github/issues/ahzhezhe/ndi-login)](https://github.com/ahzhezhe/ndi-login/issues)
[![GitHub license](https://img.shields.io/github/license/ahzhezhe/ndi-login)](https://github.com/ahzhezhe/ndi-login/blob/master/LICENSE)

Helper library for using Singapore NDI Singpass/Corpass login.

[API Documentation](https://ahzhezhe.github.io/docs/ndi-login-v2/index.html)

<br />

## **Install via NPM**
```
npm install ndi-login
```

<br />

## **Import**
```typescript
import { NdiLogin } from 'ndi-login';
```
or
```typescript
const { NdiLogin } = require('ndi-login');
```

<br />

## **Create instance**
```typescript
const ndiLogin = new NdiLogin({
  issuer: 'https://stg-id.singpass.gov.sg',
  clientId: 'YOUR_CLIENT_ID',
  clientAssertionJwk: {
    // JWK for signing/verifying client assertion in JSON format
  },
  idTokenJwk: {
    // JWK for encrypting/decrypting ID token in JSON format
  },
});
```

<br />

## **Generate authorization URI**
```typescript
const uri = await ndiLogin.generateAuthorizationUri({ redirectUri, codeChallenge, state, nonce })
```

<br />

## **Exchange for ID token with authorization code**
```typescript
const clientAssertion = await ndiLogin.generateClientAssertion();
const { idToken } = await ndiLogin.getTokens({ clientAssertion, code, redirectUri, codeVerifier });
const { sub } = await ndiLogin.getIdTokenClaims(idToken);
const { uin } = NdiLogin.parseIdTokenSub(sub);
```

<br />

## **Get your (relying party) JWKS to expose to NDI**
```typescript
const jwks = await ndiLogin.getRpJwks();
```

<br />

## **Utility method to generate a new pair of JWK for you (relying party)**
```typescript
const { clientAssertionJwk, idTokenJwk } = await NdiLogin.generateRpJwks();
```

<br />

## **Utility methods for PKCE**
```typescript
const codeVerifier = NdiLogin.generateCodeVerifier();
const codeChallenge = NdiLogin.generateCodeChallege(codeVerifier);
```

<br />

## **Utility methods for random values**
```typescript
const state = NdiLogin.generateState();
const nonce = NdiLogin.generateNonce();
```
