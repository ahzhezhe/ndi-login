import crypto from 'crypto';
import { JWK } from 'node-jose';
import { GenerateRpJwksOptions, ParsedIdTokenSub } from './types';

export class NdiLoginUtil {

  /**
   * Parse ID token sub.
   */
  static parseIdTokenSub(sub: string): ParsedIdTokenSub {
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
