"""Tenant state collection via Graph API and Microsoft Enterprise MCP Server."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx
from rich.console import Console

from tenantchat.auth import AuthManager
from tenantchat.models import TenantState

console = Console()

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"


class Collector:
    """Collects exact configuration state from a Microsoft 365 tenant."""

    def __init__(self, auth: AuthManager) -> None:
        self.auth = auth
        self._token: str | None = None

    async def collect(self) -> TenantState:
        """Run full tenant state collection across all domains."""
        self._token = self.auth.get_token()
        if not self._token:
            raise RuntimeError(
                "Not authenticated. Run: tenantchat auth login"
            )

        console.print("[bold cyan]Collecting tenant state...[/bold cyan]")

        async with httpx.AsyncClient(
            headers=self._headers(),
            timeout=30,
            follow_redirects=True,
        ) as client:
            # Run collections concurrently where safe
            (
                tenant_info,
                ca_policies,
                users,
                mfa_registration,
                managed_devices,
                compliance_policies,
                config_profiles,
                secure_score,
                alerts,
                auth_policies,
                domains,
                roles,
                service_principals,
            ) = await asyncio.gather(
                self._get(client, "/organization"),
                self._get(client, "/identity/conditionalAccess/policies"),
                self._get(client, "/users",
                    params={"$select": "id,displayName,userPrincipalName,"
                                       "accountEnabled,userType,createdDateTime,"
                                       "assignedLicenses,signInActivity",
                            "$top": "999"}),
                self._get(client,
                    "/reports/authenticationMethods/userRegistrationDetails",
                    params={"$select": "userPrincipalName,isMfaRegistered,"
                                       "isMfaCapable,defaultMfaMethod,"
                                       "isSsprRegistered",
                            "$top": "999"}),
                self._get(client, "/deviceManagement/managedDevices",
                    params={"$select": "id,deviceName,userPrincipalName,"
                                       "complianceState,lastSyncDateTime,"
                                       "operatingSystem,osVersion,"
                                       "managementAgent,enrolledDateTime",
                            "$top": "999"}),
                self._get(client,
                    "/deviceManagement/deviceCompliancePolicies",
                    params={"$select": "id,displayName,lastModifiedDateTime"}),
                self._get(client, "/deviceManagement/deviceConfigurations",
                    params={"$select": "id,displayName,lastModifiedDateTime"}),
                self._get(client, "/security/secureScores",
                    params={"$top": "1"}),
                self._get(client, "/security/alerts_v2",
                    params={"$filter": "status eq 'new'",
                            "$select": "id,title,severity,status,"
                                       "createdDateTime",
                            "$top": "50"}),
                self._get(client, "/policies/authenticationMethodsPolicy"),
                self._get(client, "/domains",
                    params={"$select": "id,isDefault,isVerified,"
                                       "passwordValidityPeriodInDays"}),
                self._get(client, "/directoryRoles",
                    params={"$expand": "members"}),
                self._get(client, "/servicePrincipals",
                    params={"$select": "id,displayName,appId,"
                                       "accountEnabled,keyCredentials,"
                                       "passwordCredentials",
                            "$top": "999"}),
                return_exceptions=True,
            )

        # Extract tenant info
        org_list = self._safe_list(tenant_info)
        org = org_list[0] if org_list else {}
        tenant_id     = org.get("id", "")
        tenant_domain = org.get("verifiedDomains", [{}])[0].get(
            "name", "unknown"
        )

        # Extract guest users from full user list
        all_users  = self._safe_list(users)
        guests     = [u for u in all_users
                      if u.get("userType") == "Guest"]
        real_users = [u for u in all_users
                      if u.get("userType") != "Guest"]

        # Extract Global Admins from roles
        all_roles = self._safe_list(roles)
        ga_role   = next(
            (r for r in all_roles
             if r.get("displayName") == "Global Administrator"),
            {}
        )
        admins = ga_role.get("members", [])

        # Extract secure score
        ss_list = self._safe_list(secure_score)
        ss      = ss_list[0] if ss_list else {}

        console.print("[green]Collection complete.[/green]")

        return TenantState(
            tenant_id=tenant_id,
            tenant_domain=tenant_domain,
            collected_at=datetime.now(tz=timezone.utc),
            ca_policies=self._safe_list(ca_policies),
            users=real_users,
            guests=guests,
            admins=admins,
            mfa_registration=self._safe_list(mfa_registration),
            managed_devices=self._safe_list(managed_devices),
            compliance_policies=self._safe_list(compliance_policies),
            config_profiles=self._safe_list(config_profiles),
            secure_score=ss,
            alerts=self._safe_list(alerts),
            auth_policies=auth_policies if isinstance(
                auth_policies, dict) else {},
            domains=self._safe_list(domains),
            roles=all_roles,
            service_principals=self._safe_list(service_principals),
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type":  "application/json",
        }

    async def _get(
        self,
        client: httpx.AsyncClient,
        path: str,
        params: dict | None = None,
        beta: bool = False,
    ) -> Any:
        """GET a Graph API endpoint, handling pagination."""
        base = GRAPH_BETA if beta else GRAPH_BASE
        url  = f"{base}{path}"
        items: list[dict] = []

        try:
            while url:
                resp = await client.get(url, params=params)
                resp.raise_for_status()
                data   = resp.json()
                params = None  # only on first request

                if "value" in data:
                    items.extend(data["value"])
                    url = data.get("@odata.nextLink")
                else:
                    return data  # single object response

            return items

        except httpx.HTTPStatusError as e:
            console.print(
                f"[yellow]Warning:[/yellow] {path} returned "
                f"{e.response.status_code} — skipping"
            )
            return []
        except Exception as e:
            console.print(
                f"[yellow]Warning:[/yellow] {path} failed: {e} — skipping"
            )
            return []

    def _safe_list(self, result: Any) -> list[dict]:
        """Safely extract a list from a Graph result."""
        if isinstance(result, list):
            return result
        if isinstance(result, Exception):
            return []
        return []
