import React, { createContext, useContext, useSyncExternalStore } from "react";
import type { GossoClient } from "../client.js";
import type { SessionSnapshot, UserProfile } from "../types.js";

interface GossoContextValue {
  client: GossoClient<any>;
}

const GossoContext = createContext<GossoContextValue | null>(null);

export interface GossoProviderProps<TProfile = UserProfile> {
  client: GossoClient<TProfile>;
  children: React.ReactNode;
}

/**
 * Root provider to supply a GossoClient instance to React component trees.
 */
export function GossoProvider<TProfile = UserProfile>({
  client,
  children,
}: GossoProviderProps<TProfile>) {
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
