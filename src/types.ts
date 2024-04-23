export interface Proxy {
  protocol: string;
  host: string;
  port: number;
}

export interface NdiLoginOptions {
  /**
   * Issuer.
   *
   * Singpass staging: https://stg-id.singpass.gov.sg
   *
   * Singpass production: https://id.singpass.gov.sg
   *
   * Corppass staging: https://stg-id.corppass.gov.sg
   *
   * Corppass production: https://id.corppass.gov.sg
   */
  issuer: string;
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
  proxy?: string | Proxy;
  /**
   * Logger.
   */
  logger?: {
    debug?: (message: string) => void;
    error?: (message: string) => void;
  };
}

export interface OpenidConfiguration {
  issuer: string;
  authorizationUri: string;
  backchannelAuthenticationUri: string;
  jwksUri: string;
  tokenUri: string;
  fetchedAt: number;
}

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
   * The hash of a code verifier generated using the S256 hash method.
   * This is to enable Proof Key for Code Exchange (PKCE).
   * This is an extension to the authorization code flow to prevent CSRF and authorization code injection attacks.
   *
   * Code verifier must match regexp pattern of `[a-zA-Z0-9_\-]{43,128}`
   */
  codeChallenge: string;
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
   * A session-based, unique, and non-guessable value that the RP should generate per auth session.
   * This parameter should ideally be generated and set by the RP’s backend and passed to the frontend.
   * As part of threat modelling, NDI is requesting for the nonce parameter so as to mitigate MITM replay
   * attacks against the ASP Service’s Token Endpoint and its resulting ID Token.
   *
   * Maximum of 255 characters. Must be alphanumeric.
   */
  nonce: string;
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

export interface BackchannelAuthenticateOptions {
  /**
   * A JWT identifying the client.
   */
  clientAssertion: string;
  /**
   * Unique identification number of user.
   */
  uin: string;
}

export interface BackchannelAuthenticateResponse {
  /**
   * A JWT identifying the client.
   */
  clientAssertion: string;
  /**
   * Authentication request ID.
   */
  authReqId: string;
}

interface GetTokensOptions {
  /**
   * A JWT identifying the client.
   */
  clientAssertion: string;
}

export interface GetTokensByAuthorizationCodeOptions extends GetTokensOptions {
  /**
   * The code issued earlier in the auth session.
   */
  code: string;
  /**
   * The redirect URI being used in this auth session.
   */
  redirectUri: string;
  /**
   * Required if code challenge parameter was passed to authorization endpoint.
   * This is the session-based, unique, and non-guessable value that the RP had used to generate the code challenge.
   */
  codeVerifier: string;
}

export interface GetTokensByAuthReqIdOptions extends GetTokensOptions {
  /**
   * The backchannel authentication request ID issued earlier in the auth session.
   */
  authReqId: string;
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

export interface GetIdTokenClaimsOptions {
  /**
   * Ignore if ID token has expired, default = `false`.
   */
  ignoreExpiration?: boolean;
}

export interface IdTokenClaims {
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
