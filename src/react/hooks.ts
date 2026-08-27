import { useCallback, useEffect, useState } from "react";
import { useGossoClient } from "./context.js";
import type {
  MfaEnrollment,
  MfaStatus,
  PasskeyInfo,
  SessionInfo,
  UserProfile,
} from "../types.js";

/**
 * Headless hook to manage Passkeys (WebAuthn credentials).
 */
export function usePasskeys() {
  const client = useGossoClient();
  const [passkeys, setPasskeys] = useState<PasskeyInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const items = await client.listPasskeys();
      setPasskeys(items);
      return items;
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to load passkeys";
      setError(message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [client]);

  useEffect(() => {
    void reload().catch(() => {});
  }, [reload]);

  const register = useCallback(
    async (name: string) => {
      setLoading(true);
      setError(null);
      try {
        await client.registerPasskey(name);
        await reload();
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : "Passkey registration failed";
        setError(message);
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [client, reload],
  );

  const remove = useCallback(
    async (id: string) => {
      setLoading(true);
      setError(null);
      try {
        await client.deletePasskey(id);
        await reload();
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : "Failed to remove passkey";
        setError(message);
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [client, reload],
  );

  return {
    passkeys,
    loading,
    error,
    reload,
    register,
    remove,
  };
}

/**
 * Headless hook to manage Multi-Factor Authentication (MFA / TOTP).
 */
export function useMfa() {
  const client = useGossoClient();
  const [status, setStatus] = useState<MfaStatus>({
    enabled: false,
    types: [],
  });
  const [enrollment, setEnrollment] = useState<MfaEnrollment | null>(null);
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await client.getMfaStatus();
      setStatus(res);
      return res;
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to load MFA status";
      setError(message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [client]);

  useEffect(() => {
    void reload().catch(() => {});
  }, [reload]);

  const startEnroll = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await client.enrollMfa();
      setEnrollment(res);
      return res;
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to enroll MFA";
      setError(message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [client]);

  const activate = useCallback(
    async (code: string) => {
      setLoading(true);
      setError(null);
      try {
        const codes = await client.activateMfa(code);
        setEnrollment(null);
        setBackupCodes(codes);
        await reload();
        return codes;
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : "Failed to activate MFA";
        setError(message);
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [client, reload],
  );

  const disable = useCallback(
    async (currentPassword: string) => {
      setLoading(true);
      setError(null);
      try {
        await client.disableMfa(currentPassword);
        setBackupCodes([]);
        await reload();
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : "Failed to disable MFA";
        setError(message);
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [client, reload],
  );

  const regenerateBackupCodes = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const codes = await client.generateBackupCodes();
      setBackupCodes(codes);
      return codes;
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to generate backup codes";
      setError(message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [client]);

  return {
    status,
    enrollment,
    backupCodes,
    loading,
    error,
    reload,
    startEnroll,
    activate,
    disable,
    regenerateBackupCodes,
    cancelEnroll: () => setEnrollment(null),
  };
}

/**
 * Headless hook to manage active user sessions.
 */
export function useSessions() {
  const client = useGossoClient();
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [currentSession, setCurrentSession] = useState<SessionInfo | null>(
    null,
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [list, current] = await Promise.all([
        client.listSessions(),
        client.getCurrentSession().catch(() => null),
      ]);
      setSessions(list);
      setCurrentSession(current);
      return { list, current };
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to load sessions";
      setError(message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [client]);

  useEffect(() => {
    void reload().catch(() => {});
  }, [reload]);

  const revoke = useCallback(
    async (id: string) => {
      setLoading(true);
      setError(null);
      try {
        await client.revokeSession(id);
        await reload();
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : "Failed to revoke session";
        setError(message);
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [client, reload],
  );

  return {
    sessions,
    currentSession,
    loading,
    error,
    reload,
    revoke,
  };
}

/**
 * Headless hook to update user profile (display name, email, password).
 */
export function useProfileManager() {
  const client = useGossoClient();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const updateDisplayName = useCallback(
    async (displayName: string): Promise<UserProfile> => {
      setLoading(true);
      setError(null);
      try {
        return await client.updateProfile(displayName);
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : "Failed to update profile";
        setError(message);
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [client],
  );

  const changePassword = useCallback(
    async (currentPassword: string, newPassword: string): Promise<void> => {
      setLoading(true);
      setError(null);
      try {
        await client.changePassword(currentPassword, newPassword);
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : "Failed to change password";
        setError(message);
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [client],
  );

  const requestEmailChange = useCallback(
    async (newEmail: string, password: string): Promise<void> => {
      setLoading(true);
      setError(null);
      try {
        await client.requestEmailChange(newEmail, password);
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : "Failed to request email change";
        setError(message);
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [client],
  );

  const confirmEmailChange = useCallback(
    async (newEmail: string, code: string): Promise<UserProfile> => {
      setLoading(true);
      setError(null);
      try {
        return await client.confirmEmailChange(newEmail, code);
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : "Failed to confirm email change";
        setError(message);
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [client],
  );

  return {
    loading,
    error,
    updateDisplayName,
    changePassword,
    requestEmailChange,
    confirmEmailChange,
  };
}
