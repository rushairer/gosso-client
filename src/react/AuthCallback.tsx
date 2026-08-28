import React, { useEffect, useState } from "react";
import { useGossoClient } from "./context.js";
import type { AuthCallbackResult } from "../types.js";
import { AuthenticationError, GossoError } from "../errors.js";

export interface AuthCallbackErrorDetail {
  code: string;
  message: string;
  cause?: unknown;
}

export interface AuthCallbackProps {
  /**
   * Called with the validated post-login redirect path after successful code exchange.
   */
  onSuccess: (redirectTo: string) => void;
  /**
   * Optional custom loading component renderer.
   */
  renderLoading?: () => React.ReactNode;
  /**
   * Optional custom error component renderer.
   */
  renderError?: (
    error: string,
    detail?: AuthCallbackErrorDetail,
  ) => React.ReactNode;
}

/**
 * Standard OAuth/OIDC authorization code callback handler component.
 * Automatically extracts code and state from window.location.search,
 * exchanges tokens via GossoClient, and triggers onSuccess or renderError.
 */
export function AuthCallback({
  onSuccess,
  renderLoading,
  renderError,
}: AuthCallbackProps) {
  const client = useGossoClient();
  const [error, setError] = useState<AuthCallbackErrorDetail | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");

    if (!code || !state) {
      const callbackError = new AuthenticationError(
        "Missing authorization code or state parameter",
        "CALLBACK_PARAMS_MISSING",
      );
      setError(callbackError);
      return;
    }

    let active = true;
    client
      .handleRedirectCallback(code, state)
      .then((res: AuthCallbackResult) => {
        if (active) {
          onSuccess(res.redirectTo);
        }
      })
      .catch((err: unknown) => {
        if (active) {
          if (err instanceof GossoError) {
            setError(err);
          } else {
            setError({
              code: "AUTH_CALLBACK_FAILED",
              message:
                err instanceof Error ? err.message : "Authentication failed",
              cause: err,
            });
          }
        }
      });

    return () => {
      active = false;
    };
  }, [client, onSuccess]);

  if (error) {
    return renderError ? (
      <>{renderError(error.message, error)}</>
    ) : (
      <div role="alert" style={{ textAlign: "center", padding: "2rem" }}>
        <h2>Authentication Error</h2>
        <p>{error.message}</p>
      </div>
    );
  }

  return renderLoading ? (
    <>{renderLoading()}</>
  ) : (
    <div role="status" style={{ textAlign: "center", padding: "2rem" }}>
      <p>Completing sign-in…</p>
    </div>
  );
}
