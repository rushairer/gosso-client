import { describe, it, expect, vi } from "vitest";
import React from "react";
import { render, screen, act } from "@testing-library/react";
import {
  GossoProvider,
  useGossoClient,
  useSession,
  useUserProfile,
  useIsAuthenticated,
  useIsAdmin,
  usePasskeys,
  useMfa,
  useSessions,
  useProfileManager,
  AuthCallback,
} from "./index.js";
import { createGossoClient, type GossoClient } from "../client.js";
import type { SessionSnapshot } from "../types.js";

function createMockClient(overrides: Partial<GossoClient> = {}): GossoClient {
  let currentSnapshot: SessionSnapshot = {
    accessToken: "mock-token",
    refreshToken: "mock-refresh",
    profile: {
      sub: "user-123",
      preferred_username: "alice",
      roles: ["admin"],
    },
    loggedIn: true,
    isAdmin: true,
  };

  const listeners = new Set<(s: SessionSnapshot) => void>();

  const defaultMock: Partial<GossoClient> = {
    getSnapshot: vi.fn(() => currentSnapshot),
    getUserProfile: vi.fn(() => currentSnapshot.profile),
    getAccessToken: vi.fn(() => currentSnapshot.accessToken),
    getRefreshToken: vi.fn(() => currentSnapshot.refreshToken),
    isLoggedIn: vi.fn(() => currentSnapshot.loggedIn),
    isAdmin: vi.fn(() => currentSnapshot.isAdmin),
    subscribe: vi.fn((listener) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    }),
    listPasskeys: vi
      .fn()
      .mockResolvedValue([
        { id: "pk-1", name: "MacBook Passkey", created_at: "2026-08-01" },
      ]),
    registerPasskey: vi.fn().mockResolvedValue(undefined),
    deletePasskey: vi.fn().mockResolvedValue(undefined),
    getMfaStatus: vi.fn().mockResolvedValue({ enabled: false, types: [] }),
    enrollMfa: vi.fn().mockResolvedValue({
      secret: "JBSWY3DPEHPK3PXP",
      otpauth_url: "otpauth://totp/gosso:alice?secret=JBSWY3DPEHPK3PXP",
    }),
    activateMfa: vi.fn().mockResolvedValue(["code1", "code2"]),
    disableMfa: vi.fn().mockResolvedValue(undefined),
    generateBackupCodes: vi.fn().mockResolvedValue(["new-code1", "new-code2"]),
    listSessions: vi.fn().mockResolvedValue([
      {
        id: "sess-1",
        ip: "127.0.0.1",
        user_agent: "Chrome",
        created_at: "2026-08-01",
        last_active_at: "2026-08-01",
      },
    ]),
    getCurrentSession: vi.fn().mockResolvedValue({
      id: "sess-1",
      ip: "127.0.0.1",
      user_agent: "Chrome",
      created_at: "2026-08-01",
      last_active_at: "2026-08-01",
    }),
    revokeSession: vi.fn().mockResolvedValue(undefined),
    updateProfile: vi.fn().mockImplementation((name: string) =>
      Promise.resolve({
        sub: "user-123",
        name,
        preferred_username: "alice",
      }),
    ),
    changePassword: vi.fn().mockResolvedValue(undefined),
    requestEmailChange: vi.fn().mockResolvedValue(undefined),
    confirmEmailChange: vi.fn().mockImplementation((email: string) =>
      Promise.resolve({
        sub: "user-123",
        email,
        preferred_username: "alice",
      }),
    ),
    handleRedirectCallback: vi.fn().mockResolvedValue({
      sessionMode: "cookie",
      redirectTo: "/dashboard",
    }),
  };

  return {
    ...defaultMock,
    ...overrides,
  } as unknown as GossoClient;
}

describe("@gosso/client/react", () => {
  it("throws error when useGossoClient is called outside of GossoProvider", () => {
    function Consumer() {
      useGossoClient();
      return null;
    }
    expect(() => render(<Consumer />)).toThrow(
      "useGossoClient must be used within a <GossoProvider>",
    );
  });

  it("provides reactive session state through useSession, useUserProfile, useIsAuthenticated, useIsAdmin", () => {
    const client = createMockClient();

    function Consumer() {
      const session = useSession();
      const profile = useUserProfile();
      const isAuth = useIsAuthenticated();
      const isAdmin = useIsAdmin();

      return (
        <div>
          <span data-testid="username">{profile?.preferred_username}</span>
          <span data-testid="auth">{isAuth ? "yes" : "no"}</span>
          <span data-testid="admin">{isAdmin ? "yes" : "no"}</span>
          <span data-testid="token">{session.accessToken}</span>
        </div>
      );
    }

    render(
      <GossoProvider client={client}>
        <Consumer />
      </GossoProvider>,
    );

    expect(screen.getByTestId("username").textContent).toBe("alice");
    expect(screen.getByTestId("auth").textContent).toBe("yes");
    expect(screen.getByTestId("admin").textContent).toBe("yes");
    expect(screen.getByTestId("token").textContent).toBe("mock-token");
  });

  it("usePasskeys loads, registers, and deletes passkeys", async () => {
    const client = createMockClient();

    function PasskeysConsumer() {
      const { passkeys, loading, register, remove } = usePasskeys();
      if (loading) return <div>Loading passkeys...</div>;
      return (
        <div>
          <ul>
            {passkeys.map((p) => (
              <li key={p.id}>{p.name}</li>
            ))}
          </ul>
          <button onClick={() => register("YubiKey")}>Add Key</button>
          <button onClick={() => remove("pk-1")}>Delete Key</button>
        </div>
      );
    }

    render(
      <GossoProvider client={client}>
        <PasskeysConsumer />
      </GossoProvider>,
    );

    expect(await screen.findByText("MacBook Passkey")).toBeDefined();

    await act(async () => {
      screen.getByText("Add Key").click();
    });
    expect(client.registerPasskey).toHaveBeenCalledWith("YubiKey");

    await act(async () => {
      screen.getByText("Delete Key").click();
    });
    expect(client.deletePasskey).toHaveBeenCalledWith("pk-1");
  });

  it("useMfa handles enroll, activate, disable, and backup codes", async () => {
    const client = createMockClient();

    function MfaConsumer() {
      const {
        status,
        enrollment,
        backupCodes,
        startEnroll,
        activate,
        disable,
        regenerateBackupCodes,
      } = useMfa();
      return (
        <div>
          <span data-testid="status">{status.enabled ? "on" : "off"}</span>
          {enrollment && <span data-testid="secret">{enrollment.secret}</span>}
          {backupCodes.map((c) => (
            <span key={c} data-testid="code">
              {c}
            </span>
          ))}
          <button onClick={() => startEnroll()}>Enroll</button>
          <button onClick={() => activate("123456")}>Activate</button>
          <button onClick={() => disable("password")}>Disable</button>
          <button onClick={() => regenerateBackupCodes()}>Regenerate</button>
        </div>
      );
    }

    render(
      <GossoProvider client={client}>
        <MfaConsumer />
      </GossoProvider>,
    );

    expect(await screen.findByTestId("status")).toBeDefined();

    await act(async () => {
      screen.getByText("Enroll").click();
    });
    expect(client.enrollMfa).toHaveBeenCalled();
    expect(await screen.findByTestId("secret")).toBeDefined();

    await act(async () => {
      screen.getByText("Activate").click();
    });
    expect(client.activateMfa).toHaveBeenCalledWith("123456");

    await act(async () => {
      screen.getByText("Disable").click();
    });
    expect(client.disableMfa).toHaveBeenCalledWith("password");

    await act(async () => {
      screen.getByText("Regenerate").click();
    });
    expect(client.generateBackupCodes).toHaveBeenCalled();
  });

  it("useSessions handles session listing and revocation", async () => {
    const client = createMockClient();

    function SessionsConsumer() {
      const { sessions, currentSession, revoke } = useSessions();
      return (
        <div>
          <span data-testid="current">{currentSession?.id}</span>
          <ul>
            {sessions.map((s) => (
              <li key={s.id}>{s.ip}</li>
            ))}
          </ul>
          <button onClick={() => revoke("sess-1")}>Revoke</button>
        </div>
      );
    }

    render(
      <GossoProvider client={client}>
        <SessionsConsumer />
      </GossoProvider>,
    );

    expect(await screen.findByTestId("current")).toBeDefined();
    expect(screen.getByTestId("current").textContent).toBe("sess-1");

    await act(async () => {
      screen.getByText("Revoke").click();
    });
    expect(client.revokeSession).toHaveBeenCalledWith("sess-1");
  });

  it("useProfileManager handles profile updates, password change, email change", async () => {
    const client = createMockClient();

    function ProfileConsumer() {
      const {
        updateDisplayName,
        changePassword,
        requestEmailChange,
        confirmEmailChange,
      } = useProfileManager();
      return (
        <div>
          <button onClick={() => updateDisplayName("Bob")}>Update Name</button>
          <button onClick={() => changePassword("old", "new")}>
            Change Pwd
          </button>
          <button onClick={() => requestEmailChange("bob@example.com", "pwd")}>
            Req Email
          </button>
          <button
            onClick={() => confirmEmailChange("bob@example.com", "123456")}
          >
            Confirm Email
          </button>
        </div>
      );
    }

    render(
      <GossoProvider client={client}>
        <ProfileConsumer />
      </GossoProvider>,
    );

    await act(async () => {
      screen.getByText("Update Name").click();
    });
    expect(client.updateProfile).toHaveBeenCalledWith("Bob");

    await act(async () => {
      screen.getByText("Change Pwd").click();
    });
    expect(client.changePassword).toHaveBeenCalledWith("old", "new");

    await act(async () => {
      screen.getByText("Req Email").click();
    });
    expect(client.requestEmailChange).toHaveBeenCalledWith(
      "bob@example.com",
      "pwd",
    );

    await act(async () => {
      screen.getByText("Confirm Email").click();
    });
    expect(client.confirmEmailChange).toHaveBeenCalledWith(
      "bob@example.com",
      "123456",
    );
  });

  it("AuthCallback exchanges code and redirects on success", async () => {
    const client = createMockClient();
    const onSuccess = vi.fn();

    // Mock search params
    const originalLocation = window.location;
    delete (window as any).location;
    window.location = new URL(
      "http://localhost:3000/callback?code=auth-code-123&state=state-456",
    ) as any;

    try {
      render(
        <GossoProvider client={client}>
          <AuthCallback
            onSuccess={onSuccess}
            renderLoading={() => <div>Loading callback...</div>}
          />
        </GossoProvider>,
      );

      expect(screen.getByText("Loading callback...")).toBeDefined();

      await act(async () => {
        await Promise.resolve();
      });

      expect(client.handleRedirectCallback).toHaveBeenCalledWith(
        "auth-code-123",
        "state-456",
      );
      expect(onSuccess).toHaveBeenCalledWith("/dashboard");
    } finally {
      window.location = originalLocation;
    }
  });

  it("AuthCallback renders error on failure or missing params", async () => {
    const client = createMockClient();
    const onSuccess = vi.fn();

    const originalLocation = window.location;
    delete (window as any).location;
    window.location = new URL("http://localhost:3000/callback") as any;

    try {
      render(
        <GossoProvider client={client}>
          <AuthCallback
            onSuccess={onSuccess}
            renderError={(err) => <div>Custom Error: {err}</div>}
          />
        </GossoProvider>,
      );

      expect(
        await screen.findByText(
          "Custom Error: Missing authorization code or state parameter",
        ),
      ).toBeDefined();
      expect(onSuccess).not.toHaveBeenCalled();
    } finally {
      window.location = originalLocation;
    }
  });

  it("AuthCallback renders default error and loading states when no custom renderers are provided", async () => {
    const client = createMockClient({
      handleRedirectCallback: vi
        .fn()
        .mockRejectedValue(new Error("Exchange failed")),
    });
    const onSuccess = vi.fn();

    const originalLocation = window.location;
    delete (window as any).location;
    window.location = new URL(
      "http://localhost:3000/callback?code=abc&state=xyz",
    ) as any;

    try {
      render(
        <GossoProvider client={client}>
          <AuthCallback onSuccess={onSuccess} />
        </GossoProvider>,
      );

      expect(screen.getByText("Completing sign-in…")).toBeDefined();
      expect(await screen.findByText("Exchange failed")).toBeDefined();
    } finally {
      window.location = originalLocation;
    }
  });

  it("handles error branches across usePasskeys, useMfa, useSessions, useProfileManager", async () => {
    const errorClient = createMockClient({
      listPasskeys: vi
        .fn()
        .mockRejectedValue(new Error("List passkeys failed")),
      registerPasskey: vi
        .fn()
        .mockRejectedValue(new Error("Register passkey failed")),
      deletePasskey: vi
        .fn()
        .mockRejectedValue(new Error("Delete passkey failed")),
      getMfaStatus: vi.fn().mockRejectedValue(new Error("Get MFA failed")),
      enrollMfa: vi.fn().mockRejectedValue(new Error("Enroll MFA failed")),
      activateMfa: vi.fn().mockRejectedValue(new Error("Activate MFA failed")),
      disableMfa: vi.fn().mockRejectedValue(new Error("Disable MFA failed")),
      generateBackupCodes: vi
        .fn()
        .mockRejectedValue(new Error("Backup codes failed")),
      listSessions: vi
        .fn()
        .mockRejectedValue(new Error("List sessions failed")),
      revokeSession: vi
        .fn()
        .mockRejectedValue(new Error("Revoke session failed")),
      updateProfile: vi
        .fn()
        .mockRejectedValue(new Error("Update profile failed")),
      changePassword: vi
        .fn()
        .mockRejectedValue(new Error("Change password failed")),
      requestEmailChange: vi
        .fn()
        .mockRejectedValue(new Error("Request email failed")),
      confirmEmailChange: vi
        .fn()
        .mockRejectedValue(new Error("Confirm email failed")),
    });

    function ErrorConsumer() {
      const passkeys = usePasskeys();
      const mfa = useMfa();
      const sessions = useSessions();
      const profile = useProfileManager();

      return (
        <div>
          <button onClick={() => passkeys.register("bad").catch(() => {})}>
            Err PK Reg
          </button>
          <button onClick={() => passkeys.remove("bad").catch(() => {})}>
            Err PK Del
          </button>
          <button onClick={() => mfa.startEnroll().catch(() => {})}>
            Err MFA Enroll
          </button>
          <button onClick={() => mfa.activate("000").catch(() => {})}>
            Err MFA Act
          </button>
          <button onClick={() => mfa.disable("bad").catch(() => {})}>
            Err MFA Dis
          </button>
          <button onClick={() => mfa.regenerateBackupCodes().catch(() => {})}>
            Err MFA Codes
          </button>
          <button onClick={() => mfa.cancelEnroll()}>Cancel MFA</button>
          <button onClick={() => sessions.revoke("bad").catch(() => {})}>
            Err Sess Revoke
          </button>
          <button
            onClick={() => profile.updateDisplayName("bad").catch(() => {})}
          >
            Err Prof Upd
          </button>
          <button
            onClick={() => profile.changePassword("a", "b").catch(() => {})}
          >
            Err Pwd
          </button>
          <button
            onClick={() =>
              profile.requestEmailChange("a@b.com", "c").catch(() => {})
            }
          >
            Err Req Email
          </button>
          <button
            onClick={() =>
              profile.confirmEmailChange("a@b.com", "123").catch(() => {})
            }
          >
            Err Conf Email
          </button>
        </div>
      );
    }

    render(
      <GossoProvider client={errorClient}>
        <ErrorConsumer />
      </GossoProvider>,
    );

    await act(async () => {
      screen.getByText("Err PK Reg").click();
      screen.getByText("Err PK Del").click();
      screen.getByText("Err MFA Enroll").click();
      screen.getByText("Err MFA Act").click();
      screen.getByText("Err MFA Dis").click();
      screen.getByText("Err MFA Codes").click();
      screen.getByText("Cancel MFA").click();
      screen.getByText("Err Sess Revoke").click();
      screen.getByText("Err Prof Upd").click();
      screen.getByText("Err Pwd").click();
      screen.getByText("Err Req Email").click();
      screen.getByText("Err Conf Email").click();
    });

    expect(errorClient.registerPasskey).toHaveBeenCalled();
  });

  it("renders with a real createGossoClient instance without triggering render loops", () => {
    const realClient = createGossoClient({
      issuer: "http://localhost:8088",
      clientId: "test-app",
    });

    let renderCount = 0;
    function RealConsumer() {
      const session = useSession();
      renderCount++;
      return <div>LoggedIn: {session.loggedIn ? "yes" : "no"}</div>;
    }

    render(
      <GossoProvider client={realClient}>
        <RealConsumer />
      </GossoProvider>,
    );

    expect(screen.getByText("LoggedIn: no")).toBeDefined();
    expect(renderCount).toBeLessThan(3);
  });
});
