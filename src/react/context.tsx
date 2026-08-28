import React, {
  createContext,
  useContext,
  useEffect,
  useState,
  useSyncExternalStore,
} from "react";
import type { GossoClient } from "../client.js";
import type { SessionSnapshot, UserProfile } from "../types.js";

interface GossoContextValue {
  client: GossoClient<any>;
}

const GossoContext = createContext<GossoContextValue | null>(null);
const sessionInitializations = new WeakMap<object, Promise<unknown>>();

function initializeClientSession<TProfile>(client: GossoClient<TProfile>) {
  const existing = sessionInitializations.get(client);
  if (existing) return existing;
  const pending = client.initializeSession();
  sessionInitializations.set(client, pending);
  void pending.catch(() => {
    if (sessionInitializations.get(client) === pending) {
      sessionInitializations.delete(client);
    }
  });
  return pending;
}

export interface GossoProviderProps<TProfile = UserProfile> {
  client: GossoClient<TProfile>;
  children: React.ReactNode;
  /** Restore an existing Cookie Session before mounting authentication guards. */
  initializeSession?: boolean;
  /** Rendered while an opted-in session initialization is in progress. */
  fallback?: React.ReactNode;
  /** Receives unexpected initialization failures such as upstream outages. */
  onInitializationError?: (error: unknown) => void;
}

/**
 * Root provider to supply a GossoClient instance to React component trees.
 */
export function GossoProvider<TProfile = UserProfile>({
  client,
  children,
  initializeSession = false,
  fallback = null,
  onInitializationError,
}: GossoProviderProps<TProfile>) {
  const [initialized, setInitialized] = useState(!initializeSession);

  useEffect(() => {
    if (!initializeSession) {
      setInitialized(true);
      return;
    }
    let active = true;
    void initializeClientSession(client).then(
      () => {
        if (active) setInitialized(true);
      },
      (error: unknown) => {
        onInitializationError?.(error);
        if (active) setInitialized(true);
      },
    );
    return () => {
      active = false;
    };
  }, [client, initializeSession, onInitializationError]);

  if (!initialized) return <>{fallback}</>;

  return (
    <GossoContext.Provider value={{ client }}>{children}</GossoContext.Provider>
  );
}

/**
 * Access the underlying GossoClient instance from context.
 */
export function useGossoClient<
  TProfile = UserProfile,
>(): GossoClient<TProfile> {
  const context = useContext(GossoContext);
  if (!context) {
    throw new Error("useGossoClient must be used within a <GossoProvider>");
  }
  return context.client as GossoClient<TProfile>;
}

/**
 * Reactive hook that observes Gosso session state without tearing.
 * Uses React 18+ useSyncExternalStore for concurrent safety.
 */
export function useSession<
  TProfile = UserProfile,
>(): SessionSnapshot<TProfile> {
  const client = useGossoClient<TProfile>();
  return useSyncExternalStore(
    client.subscribe,
    client.getSnapshot,
    client.getSnapshot,
  );
}

/**
 * Returns the current authenticated UserProfile or null.
 */
export function useUserProfile<TProfile = UserProfile>(): TProfile | null {
  return useSession<TProfile>().profile;
}

/**
 * Returns whether the current user is authenticated.
 */
export function useIsAuthenticated(): boolean {
  return useSession().loggedIn;
}

/**
 * Returns whether the current user has administrative permissions.
 */
export function useIsAdmin(): boolean {
  return useSession().isAdmin;
}
