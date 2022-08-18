# **ndi-login**
[![npm package](https://img.shields.io/npm/v/ndi-login)](https://www.npmjs.com/package/ndi-login)
[![npm downloads](https://img.shields.io/npm/dt/ndi-login)](https://www.npmjs.com/package/ndi-login)
[![GitHub issues](https://img.shields.io/github/issues/ahzhezhe/ndi-login)](https://github.com/ahzhezhe/ndi-login/issues)
[![GitHub license](https://img.shields.io/github/license/ahzhezhe/ndi-login)](https://github.com/ahzhezhe/ndi-login/blob/master/LICENSE)

Helper library for using Singapore NDI Singpass/Corpass login.

[API Documentation](https://ahzhezhe.github.io/docs/ndi-login-v1/index.html)

<br />

## **Install via NPM**
```
npm install ndi-login
```

<br />

## **Import**
```javascript
import { NdiLogin } from 'ndi-login';
```
or
```javascript
const { NdiLogin } = require('ndi-login');
```

<br />

## **Usage**

### **Create instance**
```javascript
const ndiLogin = new NdiLoginService({
  openidDiscoveryUri: 'https://stg-id.singpass.gov.sg/.well-known/openid-configuration',
  clientId: 'YOUR_CLIENT_ID',
  clientAssertionJwk: {
    // JWK for signing/verifying client assertion in JSON format
  },
  idTokenJwk: {
    // JWK for encrypting/decrypting ID token in JSON format
  },
});
```

### **Generate authorization URI**
```javascript
const uri = await ndiLogin.generateAuthorizationUri(redirectUri, state, nonce)
```

### **Validate authorization code**
```javascript
const clientAssertion = await ndiLogin.generateClientAssertion();
const idToken = await ndiLogin.getIdToken({ code, redirectUri, clientAssertion });
const { sub } = await ndiLogin.decryptIdToken(idToken);
const { nricFin } = ndiLogin.parseIdTokenSub(sub);
```

### **Get your (relying party) JWKS to expose to NDI**
```javascript
const jwks = await ndiLogin.getRpJwks();
```

### **Utility function to generate a new pair of JWK for you (relying party)**
```javascript
const { clientAssertionJwk, idTokenJwk } = await NdiLogin.generateRpJwks();
```
