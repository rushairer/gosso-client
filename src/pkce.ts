import { bufferToBase64URL } from './utils';

export async function generateCodeChallenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  const cryptoObj = (typeof window !== 'undefined' ? window.crypto : null) || (typeof globalThis !== 'undefined' ? globalThis.crypto : null);
  if (!cryptoObj?.subtle) {
    throw new Error('Web Crypto API (crypto.subtle) is required for PKCE code challenge generation');
  }
  const digest = await cryptoObj.subtle.digest('SHA-256', data);
  return bufferToBase64URL(digest);
}
