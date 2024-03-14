import axios from 'axios';
import { JWK, JWE, JWS } from 'node-jose';
import { NdiLoginUtil } from './NdiLoginUtil';
import { GenerateAuthorizationUriOptions, GenerateClientAssertionOptions, GetIdTokenClaimsOptions, GetTokensOptions, IdTokenClaims, NdiLoginOptions, OpenidConfiguration, Proxy, Tokens } from './types';

export class NdiLogin extends NdiLoginUtil {

  readonly #options: NdiLoginOptions & {
    proxy?: Proxy;
    openidConfigurationCacheDuration: number;
  };

  #openidConfiguration?: OpenidConfiguration;

  #jwks?: JWK.KeyStore;

  constructor(options: NdiLoginOptions) {
    super();

    let proxy: Proxy | undefined;
    if (typeof options.proxy === 'string') {
      const url = new URL(options.proxy);
      const protocol = url.protocol.substring(0, url.protocol.length - 1);
      const host = url.host.replaceAll(`:${url.port}`, '');
      const port = Number(url.port);
      proxy = { protocol, host, port };

    } else {
      proxy = options.proxy;
    }

    this.#options = {
      ...options,
      proxy,
      openidConfigurationCacheDuration: options.openidConfigurationCacheDuration ?? 60
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
      const { data } = await axios(`${this.#options.issuer}/.well-known/openid-configuration`, {
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
    const { redirectUri, codeChallenge, state, nonce, uiLocale, redirectUriHttpsType, appLaunchUrl } = options;
    const { authorizationUri } = await this.getOpenidConfiguration();

    return `${authorizationUri}?${this.#urlSearchParams({
      ['response_type']: 'code',
      ['scope']: 'openid',
      ['client_id']: this.#options.clientId,
      ['redirect_uri']: redirectUri,
      ['code_challenge']: codeChallenge,
      ['code_challenge_method']: 'S256',
      ['state']: state,
      ['nonce']: nonce,
      ['ui_locale']: uiLocale,
      ['redirect_uri_https_type']: redirectUriHttpsType,
      ['app_launch_url']: appLaunchUrl
    })}`;
  }

  /**
   * Generate a client assertion for calling token endpoint.
   */
  async generateClientAssertion(options?: GenerateClientAssertionOptions): Promise<string> {
    const { expiresIn = 60 } = options ?? {};
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
    const { clientAssertion, code, redirectUri, codeVerifier } = options;
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
          ['client_assertion_type']: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          ['client_assertion']: clientAssertion,
          ['grant_type']: 'authorization_code',
          ['code']: code,
          ['redirect_uri']: redirectUri,
          ['code_verifier']: codeVerifier,
          ['scope']: 'openid'
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
   * Decrypt & verify ID token and return its claims.
   * Relying party should verify that the `nonce` in the ID token matches with the `nonce` used when generating the authorization URI.
   */
  async getIdTokenClaims(idToken: string, options?: GetIdTokenClaimsOptions): Promise<IdTokenClaims> {
    const decryptionJwk = await JWK.asKey(this.#options.idTokenJwk);
    const decryptor = JWE.createDecrypt(decryptionJwk);
    const jws = await decryptor.decrypt(idToken);

    const jwks = await this.getJwks({ kid: jws.header['kid'], use: 'sig' });
    const verifier = JWS.createVerify(jwks);
    const result = await verifier.verify(jws.payload.toString());

    const claims: IdTokenClaims = JSON.parse(result.payload.toString());

    this.#debug(JSON.stringify(claims));

    // Validate claims
    const { ignoreExpiration = false } = options ?? {};
    const { issuer } = await this.getOpenidConfiguration();

    try {
      if (claims.iss !== issuer) {
        throw new Error('Invalid iss.');
      }
      if (claims.aud !== this.#options.clientId) {
        throw new Error('Invalid aud.');
      }
      if (!ignoreExpiration && claims.exp && claims.exp * 1000 <= new Date().getTime()) {
        throw new Error('Token has expired.');
      }
      if (!claims.sub) {
        throw new Error('Missing sub.');
      }
    } catch (err) {
      this.#error(JSON.stringify(claims));
      throw err;
    }

    return claims;
  }

}
