import type { ApiEnvelope, RefreshLock, UserProfile } from './types.js';
import { GossoError } from './errors.js';

export function normalizeBaseUrl(url: string): string {
  return url.replace(/\/+$/, '');
}

export function generateRandomString(length: number): string {
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  let text = '';
  const cryptoObj = (typeof window !== 'undefined' ? window.crypto : null) || (typeof globalThis !== 'undefined' ? globalThis.crypto : null);
  if (cryptoObj && cryptoObj.getRandomValues) {
    const array = new Uint8Array(length);
    cryptoObj.getRandomValues(array);
    for (let i = 0; i < length; i += 1) {
      text += possible.charAt(array[i] % possible.length);
    }
  } else {
    // Fallback for environments lacking CSPRNG
    for (let i = 0; i < length; i += 1) {
      text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
  }
  return text;
}

export function bufferToBase64URL(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64URLToBuffer(base64URLString: string): ArrayBuffer {
  const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function cookieSecureAttribute(): string {
  return typeof location !== 'undefined' && location.protocol === 'https:' ? '; Secure' : '';
}

export function getCookieName(baseName: string): string {
  return typeof location !== 'undefined' && location.protocol === 'https:' ? `__Secure-${baseName}` : baseName;
}

export function readCookie(name: string): string | null {
  if (typeof document === 'undefined') return null;
  for (const raw of document.cookie.split(';')) {
    const [cookieName, ...value] = raw.trim().split('=');
    if (cookieName === name) return decodeURIComponent(value.join('='));
  }
  return null;
}

export class CookieSessionRefreshError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = 'CookieSessionRefreshError';
  }
}

export function readClaimsFromAccessToken(accessToken: string): Record<string, unknown> | null {
  try {
    const payloadBase64 = accessToken.split('.')[1];
    const base64 = payloadBase64.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
    return JSON.parse(decodeURIComponent(escape(atob(padded))));
  } catch {
    return null;
  }
}

export function readRolesFromAccessToken(accessToken: string): string[] | undefined {
  const payload = readClaimsFromAccessToken(accessToken);
  return Array.isArray(payload?.roles) ? (payload.roles as string[]) : undefined;
}

export function readScopeFromAccessToken(accessToken: string): string | undefined {
  const payload = readClaimsFromAccessToken(accessToken);
  return typeof payload?.scope === 'string' ? payload.scope : undefined;
}

export function hasAdminAccess(profile: UserProfile | null, accessToken: string | null): boolean {
  const hasAdminRole = profile?.roles?.includes('admin') || false;
  const scope = accessToken ? readScopeFromAccessToken(accessToken) : profile?.scope;
  return hasAdminRole && Boolean(scope?.split(/\s+/).includes('admin'));
}

export function parseRefreshLock(raw: string | null): RefreshLock | null {
  if (!raw) return null;
  try {
    const lock = JSON.parse(raw) as Partial<RefreshLock>;
    if (typeof lock.owner !== 'string' || typeof lock.expiresAt !== 'number') {
      return null;
    }
    return { owner: lock.owner, expiresAt: lock.expiresAt };
  } catch {
    return null;
  }
}

export function generateRefreshOwner(): string {
  if (typeof window !== 'undefined' && window.crypto?.randomUUID) {
    return window.crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export async function parseJsonEnvelope<T>(response: Response, fallbackMessage: string): Promise<T> {
  const body = (await response.json()) as ApiEnvelope<T>;
  if (!response.ok) {
    throw new GossoError(body.message || fallbackMessage, 'API_ERROR');
  }
  return body.data as T;
}
