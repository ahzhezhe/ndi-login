import crypto from 'crypto';
import axios from 'axios';
import { JWK, JWE, JWS } from 'node-jose';

export interface GenerateRpJwksOptions {
  /**
   * For signing/verifying client assertion.
   */
  clientAssertion: {
    /**
     * Key ID.
     */
    kid: string;
    /**
     * Curve, default = P-256.
     */
    crv?: 'P-256' | 'P-384' | 'P-521';
  };
  /**
   * For encrypting/decrypting ID token.
   */
  idToken: {
    /**
     * Key ID.
     */
    kid: string;
    /**
     * Curve, default = P-256.
     */
    crv?: 'P-256' | 'P-384' | 'P-521';
    /**
     * Encryption algorithm, default = ECDH-ES+A256KW
     */
    alg?: 'ECDH-ES+A128KW' | 'ECDH-ES+A192KW' | 'ECDH-ES+A256KW';
  };
}

export interface GenerateAuthorizationUriOptions {
  /**
   * The URL that NDI will eventually redirect the user to after the user completes the login process using the Singpass App.
   * The value will be validated against the list of redirect URIs that were pre-registered with NDI during onboarding.
   */
  redirectUri: string;
  /**
   * A session-based, unique, and non-guessable value that the RP should generate per auth session.
   * This parameter should ideally be generated and set by the RP’s backend and passed to the frontend.
   * As part of threat modelling, NDI is requesting for the nonce parameter so as to mitigate MITM replay
   * attacks against the ASP Service’s Token Endpoint and its resulting ID Token.
   *
   * Maximum of 255 characters. Must be alphanumeric.
   */
  nonce: string;
  /**
   * A session-based, unique, and non-guessable value that the RP should generate per auth session.
   * This parameter should ideally be generated and set by the RP’s backend and passed to the frontend.
   * As part of threat modelling, NDI is requesting for the state parameter so as to mitigate replay attacks
   * against the RP’s redirection endpoint.
   *
   * Maximum of 255 characters. Must match regexp pattern of `[a-zA-Z0-9/+_\-=.]+`
   */
  state: string;
  /**
   * The hash of a code verifier generated using the S256 hash method.
   * This is to enable Proof Key for Code Exchange (PKCE).
   * This is an extension to the authorization code flow to prevent CSRF and authorization code injection attacks.
   *
   * Code verifier must match regexp pattern of `[a-zA-Z0-9_\-]{43,128}`
   */
  codeChallenge?: string;
  /**
   * The language which the Singpass login page should be displayed in.
   */
  uiLocale?: 'en' | 'ms' | 'ta' | 'zh-SG';
  /**
   * Required if the redirect URI uses is an app-claimed HTTPS URL.
   * This value is ignored if the redirect URI has a custom scheme.
   */
  redirectUriHttpsType?: 'standard_https' | 'app_claimed_https';
  /**
   * Intended for iOS mobile apps which use QR authentication via redirect auth.
   * This adds the possibility for the user to be redirected back to the provided App Link
   * after they successfully authorize themselves on the Singpass App.
   * The value passed here should be the App Link registered with Apple’s App Store and/or Google’s Play Store.
   * In the future, the provided value will be validated according to the list of app launch URLs which the RP
   * has pre-registered with NDI.
   */
  appLaunchUrl?: string;
}

export interface GenerateClientAssertionOptions {
  /**
   * Expires in how many seconds, default = 60.
   */
  expiresIn?: number;
}

export interface GetTokensOptions {
  /**
   * The code issued earlier in the auth session.
   */
  code: string;
  /**
   * The redirect URI being used in this auth session.
   */
  redirectUri: string;
  /**
   * A JWT identifying the client.
   */
  clientAssertion: string;
  /**
   * Required if code challenge parameter was passed to authorization endpoint.
   * This is the session-based, unique, and non-guessable value that the RP had used to generate the code challenge.
   */
  codeVerifier?: string;
}

export interface Tokens {
  /**
   * ID token.
   */
  idToken: string;
  /**
   * Access token.
   * It can be used for MyInfo. Usage of this token is out of scope of this library.
   */
  accessToken: string;
}

export interface DecryptIdTokenOptions {
  /**
   * Ignore if ID token has expired, default = `false`.
   */
  ignoreExpiration?: boolean;
}

export interface IdTokenPayload {
  /**
   * The subject of the JWT.
   */
  sub: string;
  /**
   * The client identifier of the relying party.
   */
  aud: string;
  /**
   * Issuer of the JWT.
   */
  iss: string;
  /**
   * The time at which the JWT was issued.
   */
  iat: number;
  /**
   * The expiration time on or after which the JWT must not be accepted for processing.
   */
  exp: number;
  /**
   * A string that uniquely identifies the authentication.
   * Relying party should verify that this value matches with the `nonce` used when generating the authorization URI.
   */
  nonce: string;
}

export interface ParsedIdTokenSub {
  /**
   * Unique identification number of the authenticated user.
   */
  uin: string;
}

export interface OpenidConfiguration {
  issuer: string;
  authorizationUri: string;
  jwksUri: string;
  tokenUri: string;
  fetchedAt: number;
}

export interface NdiLoginOptions {
  /**
   * NDI's OpenID discovery URI.
   */
  openidDiscoveryUri: string;
  /**
   * Cache OpenID configuration for how many minutes, default = 60.
   */
  openidConfigurationCacheDuration?: number;
  /**
   * Client identifier assigned to the relying party during its onboarding with NDI.
   */
  clientId: string;
  /**
   * JWK for signing/verifying client assertion in JSON format.
   */
  clientAssertionJwk: object;
  /**
   * JWK for encrypting/decrypting ID token in JSON format.
   */
  idTokenJwk: object;
  /**
   * Proxy.
   */
  proxy?: {
    protocol: string;
    host: string;
    port: number;
  };
  /**
   * Logger.
   */
  logger?: {
    debug?: (message: string) => void;
    error?: (message: string) => void;
  };
}

export class NdiLogin {

  readonly #options: NdiLoginOptions & { openidConfigurationCacheDuration: number };

  #openidConfiguration?: OpenidConfiguration;

  #jwks?: JWK.KeyStore;

  constructor(options: NdiLoginOptions) {
    this.#options = {
      ...options,
      openidConfigurationCacheDuration: options.openidConfigurationCacheDuration || 60
    };
  }

  #debug(message: string): void {
    this.#options.logger?.debug?.(message);
  }

  #error(message: string): void {
    this.#options.logger?.error?.(message);
  }

  #urlSearchParams(params: Record<string, any>) {
    Object.entries(params).map(([key, value]) => {
      if (value == null) {
        delete params[key];
      }
    });
    return new URLSearchParams(params);
  }

  /**
   * Invalidate cached OpenID configuration.
   */
  invalidateOpenidConfiguration(): void {
    this.#openidConfiguration = undefined;
  }

  /**
   * Invalidate cached JWKS.
   */
  invalidateJwks(): void {
    this.#jwks = undefined;
  }

  /**
   * Get OpenID configuration from OpenID discovery endpoint.
   */
  async getOpenidConfiguration(): Promise<OpenidConfiguration> {
    if (this.#openidConfiguration &&
      (this.#openidConfiguration.fetchedAt - new Date().getTime()) / 1000 / 60 <= this.#options.openidConfigurationCacheDuration) {
      return this.#openidConfiguration;
    }

    try {
      const { data } = await axios(this.#options.openidDiscoveryUri, {
        method: 'GET',
        proxy: this.#options.proxy
      });

      this.#debug(JSON.stringify(data));

      this.#openidConfiguration = {
        issuer: data.issuer,
        authorizationUri: data.authorization_endpoint,
        jwksUri: data.jwks_uri,
        tokenUri: data.token_endpoint,
        fetchedAt: new Date().getTime()
      };
      return this.#openidConfiguration!;

    } catch (err) {
      if (err.response) {
        this.#error(JSON.stringify(err.response.data));
      }
      this.#error(`Failed to get OpenID configuration: ${err.message}`);
      throw err;
    }
  }

  /**
   * Get relying party's JWKS, including those for verifying client assertion and encrypting ID token.
   * Relying party is required to expose it through their JWKS endpoint.
   */
  async getRpJwks(): Promise<JWK.KeyStore> {
    const clientAssertionJwk = await JWK.asKey(this.#options.clientAssertionJwk);
    const idTokenJwk = await JWK.asKey(this.#options.idTokenJwk);

    const jwks = JWK.createKeyStore();
    await jwks.add(clientAssertionJwk);
    await jwks.add(idTokenJwk);

    return jwks;
  }

  /**
   * Get JWKS from JWKS endpoint.
   *
   * @param options If `options` is specified and the required JWK is not found in cache, JWKS will be refetched.
   */
  async getJwks(options?: JWK.KeyStoreGetOptions): Promise<JWK.KeyStore> {
    if (this.#jwks && (options == null || this.#jwks.get(options))) {
      return this.#jwks;
    }

    try {
      const { jwksUri } = await this.getOpenidConfiguration();

      const { data } = await axios(jwksUri, {
        method: 'GET',
        proxy: this.#options.proxy
      });

      this.#debug(JSON.stringify(data));

      try {
        this.#jwks = await JWK.asKeyStore(data);
        return this.#jwks;

      } catch (err) {
        this.#error(JSON.stringify(data));
        throw err;
      }

    } catch (err) {
      if (err.response) {
        this.#error(JSON.stringify(err.response.data));
      }
      this.#error(`Failed to get JWKS: ${err.message}`);
      throw err;
    }
  }

  /**
   * Generate an authorization URI.
   */
  async generateAuthorizationUri(options: GenerateAuthorizationUriOptions): Promise<string> {
    const { redirectUri, nonce, state, codeChallenge, uiLocale, redirectUriHttpsType, appLaunchUrl } = options;
    const { authorizationUri } = await this.getOpenidConfiguration();

    return `${authorizationUri}?${this.#urlSearchParams({
      ['scope']: 'openid',
      ['response_type']: 'code',
      ['client_id']: this.#options.clientId,
      ['redirect_uri']: redirectUri,
      ['nonce']: nonce,
      ['state']: state,
      ['code_challenge']: codeChallenge,
      ['code_challenge_method']: codeChallenge ? 'S256' : undefined,
      ['ui_locale']: uiLocale,
      ['redirect_uri_https_type']: redirectUriHttpsType,
      ['app_launch_url']: appLaunchUrl
    })}`;
  }

  /**
   * Generate a client assertion for calling token endpoint.
   */
  async generateClientAssertion(options?: GenerateClientAssertionOptions): Promise<string> {
    const { expiresIn = 60 } = options || {};
    const { issuer } = await this.getOpenidConfiguration();

    const jwk = await JWK.asKey(this.#options.clientAssertionJwk);
    const signer = JWS.createSign({ fields: { typ: 'JWT' }, format: 'compact' }, jwk);

    const issuedAt = Math.ceil(new Date().getTime() / 1000);

    const clientAssertion = await signer.update(JSON.stringify({
      iss: this.#options.clientId,
      sub: this.#options.clientId,
      aud: issuer,
      iat: issuedAt,
      exp: issuedAt + expiresIn
    })).final();

    return clientAssertion as any;
  }

  /**
   * Get ID token and access token from token endpoint.
   * Before getting tokens, relying party should have already verified that the `state` given upon successful login
   * matches with the `state` used when generating the authorization URI.
   */
  async getTokens(options: GetTokensOptions): Promise<Tokens> {
    const { code, redirectUri, clientAssertion, codeVerifier } = options;
    const { tokenUri } = await this.getOpenidConfiguration();

    try {
      const { data } = await axios(tokenUri, {
        method: 'POST',
        proxy: this.#options.proxy,
        headers: {
          ['Content-Type']: 'application/x-www-form-urlencoded'
        },
        data: this.#urlSearchParams({
          ['client_id']: this.#options.clientId,
          ['redirect_uri']: redirectUri,
          ['grant_type']: 'authorization_code',
          ['code']: code,
          ['scope']: 'openid',
          ['client_assertion_type']: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          ['client_assertion']: clientAssertion,
          ['code_verifier']: codeVerifier
        })
      });

      this.#debug(JSON.stringify(data));

      try {
        const idToken = data.id_token;
        const accessToken = data.access_token;

        if (!idToken) {
          throw new Error('Missing id_token.');
        }

        return {
          idToken,
          accessToken
        };

      } catch (err) {
        this.#error(JSON.stringify(data));
        throw err;
      }

    } catch (err) {
      if (err.response) {
        this.#error(JSON.stringify(err.response.data));
      }
      this.#error(`Failed to get ID token: ${err.message}`);
      throw err;
    }
  }

  /**
   * Decrypt ID token.
   * Relying party should verify that the `nonce` in the ID token matches with the `nonce` used when generating the authorization URI.
   */
  async decryptIdToken(idToken: string, options?: DecryptIdTokenOptions): Promise<IdTokenPayload> {
    const decryptionJwk = await JWK.asKey(this.#options.idTokenJwk);
    const decryptor = JWE.createDecrypt(decryptionJwk);
    const jws = await decryptor.decrypt(idToken);

    const jwks = await this.getJwks({ kid: jws.header['kid'], use: 'sig' });
    const verifier = JWS.createVerify(jwks);
    const result = await verifier.verify(jws.payload.toString());

    const payload: IdTokenPayload = JSON.parse(result.payload.toString());

    this.#debug(JSON.stringify(payload));

    // Validate payload
    const { ignoreExpiration = false } = options || {};
    const { issuer } = await this.getOpenidConfiguration();

    try {
      if (payload.iss !== issuer) {
        throw new Error('Invalid iss.');
      }
      if (payload.aud !== this.#options.clientId) {
        throw new Error('Invalid aud.');
      }
      if (!ignoreExpiration && payload.exp && payload.exp * 1000 <= new Date().getTime()) {
        throw new Error('Token has expired.');
      }
      if (!payload.sub) {
        throw new Error('Missing sub.');
      }
    } catch (err) {
      this.#error(JSON.stringify(payload));
      throw err;
    }

    return payload;
  }

  /**
   * Parse ID token sub.
   */
  parseIdTokenSub(sub: string): ParsedIdTokenSub {
    const uin = sub.split(',')[0].substring(2);
    return { uin };
  }

  /**
   * Generate a new set of JWKS for signing/verifying client assertion and encrypting/decrypting ID token for relying party.
   * They are represented in JSON format.
   */
  static async generateRpJwks(options: GenerateRpJwksOptions) {
    const { clientAssertion, idToken } = options;

    const clientAssertionJwk = await JWK.createKey('EC', clientAssertion.crv || 'P-256', {
      kid: clientAssertion.kid,
      use: 'sig'
    });

    const idTokenJwk = await JWK.createKey('EC', idToken.crv || 'P-256', {
      kid: idToken.kid,
      use: 'enc',
      alg: idToken.alg || 'ECDH-ES+A256KW'
    });

    return {
      clientAssertionJwk: clientAssertionJwk.toJSON(true),
      idTokenJwk: idTokenJwk.toJSON(true)
    };
  }

  static #generateRandomValue(chars: string, length: number) {
    chars = `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789${chars}`;
    let value = '';
    for (let i = 0; i < length; i++) {
      value += chars[crypto.randomInt(0, chars.length)];
    }
    return value;
  }

  /**
   * Generate nonce.
   *
   * @param length nonce length, maximum length is 255
   * @returns nonce
   */
  static generateNonce(length = 50) {
    return this.#generateRandomValue('', length);
  }

  /**
   * Generate state.
   *
   * @param length state length, maximum length is 255
   * @returns state
   */
  static generateState(length = 50) {
    return this.#generateRandomValue('/+_-=.', length);
  }

  /**
   * Generate code verifier.
   *
   * @param length code verifier length, should be between 43 and 128
   * @returns code verifier
   */
  static generateCodeVerifier(length = 50) {
    return this.#generateRandomValue('_-', length);
  }

  /**
   * Generate code challenge.
   *
   * @param codeVerifier code verifier
   * @returns code challenge
   */
  static generateCodeChallege(codeVerifier: string) {
    return crypto.createHash('sha256').update(codeVerifier).digest().toString('base64url');
  }

}
