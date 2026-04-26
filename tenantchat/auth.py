"""MSAL PKCE authentication — OS keychain token storage, BYOA support."""

from __future__ import annotations

import json
import os

import keyring
from msal import PublicClientApplication, SerializableTokenCache

from tenantchat.models import AuthState

_KEYCHAIN_SERVICE = "tenantchat"
_CACHE_KEY        = "msal_token_cache"
_STATE_KEY        = "auth_state"

SCOPES = [
    "https://graph.microsoft.com/User.Read.All",
    "https://graph.microsoft.com/UserAuthenticationMethod.Read.All",
    "https://graph.microsoft.com/Policy.Read.All",
    "https://graph.microsoft.com/DeviceManagementManagedDevices.Read.All",
    "https://graph.microsoft.com/DeviceManagementConfiguration.Read.All",
    "https://graph.microsoft.com/SecurityEvents.Read.All",
    "https://graph.microsoft.com/AuditLog.Read.All",
    "https://graph.microsoft.com/Reports.Read.All",
    "https://graph.microsoft.com/Directory.Read.All",
]

_AUTHORITY = "https://login.microsoftonline.com/{tenant_id}"


class AuthManager:
    """MSAL PKCE auth with OS keychain token persistence."""

    def __init__(
        self,
        client_id:  str | None = None,
        tenant_id:  str | None = None,
    ) -> None:
        self.client_id = (
            client_id
            or os.environ.get("TENANTCHAT_CLIENT_ID", "")
        )
        self.tenant_id = (
            tenant_id
            or os.environ.get("TENANTCHAT_TENANT_ID", "organizations")
        )
        self._cache = self._load_cache()

    def login(self, scopes: list[str] | None = None) -> AuthState:
        """Interactive PKCE login — opens browser."""
        if not self.client_id:
            raise RuntimeError(
                "No client ID found.\n"
                "Set TENANTCHAT_CLIENT_ID environment variable\n"
                "or run: tenantchat auth login --client-id <your-app-id>"
            )
        app    = self._build_app()
        result = app.acquire_token_interactive(scopes=scopes or SCOPES)

        if "error" in result:
            raise RuntimeError(
                f"Authentication failed: {result.get('error_description')}"
            )

        self._persist_cache(app)
        state = self._extract_state(result)
        self._save_state(state)
        return state

    def get_token(self, scopes: list[str] | None = None) -> str | None:
        """Return a valid access token, refreshing silently if possible."""
        if not self.client_id:
            return None
        app      = self._build_app()
        accounts = app.get_accounts()
        if not accounts:
            return None
        result = app.acquire_token_silent(
            scopes=scopes or SCOPES,
            account=accounts[0],
        )
        if result and "access_token" in result:
            self._persist_cache(app)
            return result["access_token"]
        return None

    def logout(self) -> None:
        """Remove all stored credentials from OS keychain."""
        try:
            keyring.delete_password(_KEYCHAIN_SERVICE, _CACHE_KEY)
            keyring.delete_password(_KEYCHAIN_SERVICE, _STATE_KEY)
        except Exception:
            pass

    def status(self) -> AuthState:
        """Return persisted AuthState or unauthenticated default."""
        return self._load_state() or AuthState()

    def _build_app(self) -> PublicClientApplication:
        return PublicClientApplication(
            client_id=self.client_id,
            authority=_AUTHORITY.format(tenant_id=self.tenant_id),
            token_cache=self._cache,
        )

    def _load_cache(self) -> SerializableTokenCache:
        cache = SerializableTokenCache()
        raw   = keyring.get_password(_KEYCHAIN_SERVICE, _CACHE_KEY)
        if raw:
            cache.deserialize(raw)
        return cache

    def _persist_cache(self, app: PublicClientApplication) -> None:
        if self._cache.has_state_changed:
            keyring.set_password(
                _KEYCHAIN_SERVICE, _CACHE_KEY, self._cache.serialize()
            )

    def _extract_state(self, result: dict) -> AuthState:
        claims = result.get("id_token_claims", {})
        return AuthState(
            tenant_id=claims.get("tid", self.tenant_id),
            client_id=self.client_id,
            account=claims.get(
                "preferred_username", claims.get("upn", "")
            ),
            scopes=result.get("scope", "").split(),
            authenticated=True,
        )

    def _save_state(self, state: AuthState) -> None:
        keyring.set_password(
            _KEYCHAIN_SERVICE, _STATE_KEY,
            json.dumps(state.__dict__)
        )

    def _load_state(self) -> AuthState | None:
        raw = keyring.get_password(_KEYCHAIN_SERVICE, _STATE_KEY)
        if not raw:
            return None
        try:
            return AuthState(**json.loads(raw))
        except Exception:
            return None
