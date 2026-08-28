import React, { useEffect } from "react";
import { useGossoClient, useSession } from "./context.js";
import type { SessionSnapshot, UserProfile } from "../types.js";

export interface RequireAuthOptions<TProfile = UserProfile> {
  redirectTo?: string;
  roles?: string[];
  permissions?: string[];
  predicate?: (
    profile: TProfile | null,
    session: SessionSnapshot<TProfile>,
  ) => boolean;
}

/**
 * Headless hook to enforce authentication and role/permission requirements.
 * Automatically triggers redirectToAuthorize when user is unauthenticated.
 */
export function useRequireAuth<TProfile = UserProfile>(
  options: RequireAuthOptions<TProfile> = {},
) {
  const client = useGossoClient<TProfile>();
  const session = useSession<TProfile>();
  const { loggedIn, profile } = session;

  const rawProfile = profile as unknown as Record<string, unknown> | null;

  const rolesSatisfied =
    !options.roles ||
    (Array.isArray(rawProfile?.roles) &&
      options.roles.some((r) => (rawProfile.roles as string[]).includes(r)));

  const permissionsSatisfied =
    !options.permissions ||
    (Array.isArray(rawProfile?.permissions) &&
      options.permissions.some((p) =>
        (rawProfile.permissions as string[]).includes(p),
      ));

  const predicateSatisfied =
    !options.predicate || options.predicate(profile, session);

  const hasAccess =
    loggedIn && rolesSatisfied && permissionsSatisfied && predicateSatisfied;

  useEffect(() => {
    if (!loggedIn) {
      const returnTo =
        options.redirectTo ??
        `${window.location.pathname}${window.location.search}${window.location.hash}`;
      void client.redirectToAuthorize(returnTo);
    }
  }, [client, loggedIn, options.redirectTo]);

  return {
    ...session,
    hasAccess,
    rolesSatisfied,
    permissionsSatisfied,
    predicateSatisfied,
    loading: !loggedIn,
  };
}

export interface RequireAuthProps<TProfile = UserProfile> {
  children: React.ReactNode;
  roles?: string[];
  permissions?: string[];
  predicate?: (
    profile: TProfile | null,
    session: SessionSnapshot<TProfile>,
  ) => boolean;
  redirectTo?: string;
  fallback?: React.ReactNode;
  unauthorized?: React.ReactNode;
}

/**
 * Declarative component guard ensuring the user is logged in (and optionally possesses specified roles/permissions).
 */
export function RequireAuth<TProfile = UserProfile>({
  children,
  roles,
  permissions,
  predicate,
  redirectTo,
  fallback = null,
  unauthorized = null,
}: RequireAuthProps<TProfile>) {
  const { loggedIn, hasAccess } = useRequireAuth<TProfile>({
    roles,
    permissions,
    predicate,
    redirectTo,
  });

  if (!loggedIn) {
    return <>{fallback}</>;
  }

  if (!hasAccess) {
    return <>{unauthorized}</>;
  }

  return <>{children}</>;
}

export interface RequireAdminProps {
  children: React.ReactNode;
  redirectTo?: string;
  fallback?: React.ReactNode;
  unauthorized?: React.ReactNode;
}

/**
 * Declarative component guard ensuring the user is logged in with administrative privileges.
 */
export function RequireAdmin({
  children,
  redirectTo,
  fallback = null,
  unauthorized = null,
}: RequireAdminProps) {
  const { loggedIn, isAdmin } = useRequireAuth({ redirectTo });

  if (!loggedIn) {
    return <>{fallback}</>;
  }

  if (!isAdmin) {
    return <>{unauthorized}</>;
  }

  return <>{children}</>;
}
