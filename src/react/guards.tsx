import React, { useEffect } from "react";
import { useGossoClient, useSession } from "./context.js";

export interface RequireAuthOptions {
  redirectTo?: string;
  roles?: string[];
}

/**
 * Headless hook to enforce authentication and role requirements.
 * Automatically triggers redirectToAuthorize when user is unauthenticated.
 */
export function useRequireAuth(options: RequireAuthOptions = {}) {
  const client = useGossoClient();
  const session = useSession();
  const { loggedIn, profile } = session;

  const rolesSatisfied =
    !options.roles || options.roles.some((r) => profile?.roles?.includes(r));
  const hasAccess = loggedIn && rolesSatisfied;

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
    loading: !loggedIn,
  };
}

export interface RequireAuthProps {
  children: React.ReactNode;
  roles?: string[];
  redirectTo?: string;
  fallback?: React.ReactNode;
  unauthorized?: React.ReactNode;
}

/**
 * Declarative component guard ensuring the user is logged in (and optionally possesses specified roles).
 */
export function RequireAuth({
  children,
  roles,
  redirectTo,
  fallback = null,
  unauthorized = null,
}: RequireAuthProps) {
  const { loggedIn, rolesSatisfied } = useRequireAuth({ roles, redirectTo });

  if (!loggedIn) {
    return <>{fallback}</>;
  }

  if (!rolesSatisfied) {
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
