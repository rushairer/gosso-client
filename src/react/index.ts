export {
  GossoProvider,
  useGossoClient,
  useSession,
  useUserProfile,
  useIsAuthenticated,
  useIsAdmin,
} from "./context.js";
export type { GossoProviderProps } from "./context.js";

export {
  usePasskeys,
  useMfa,
  useSessions,
  useProfileManager,
  useAccountSecurityHub,
  usePermissions,
  useHasPermission,
  useHasAnyPermission,
  useHasRole,
} from "./hooks.js";
export type { AccountSecurityHub } from "./hooks.js";

export { AuthCallback } from "./AuthCallback.js";
export type {
  AuthCallbackProps,
  AuthCallbackErrorDetail,
} from "./AuthCallback.js";

export { RequireAuth, RequireAdmin, useRequireAuth } from "./guards.js";
export type {
  RequireAuthProps,
  RequireAdminProps,
  RequireAuthOptions,
} from "./guards.js";
