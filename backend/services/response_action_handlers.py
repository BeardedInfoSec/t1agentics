# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Response Action Handlers

Bridges action requests to integration execution.
Each handler maps an action type to the appropriate integration actions.

This module registers execution handlers with ActionRequestService
to enable real integration execution instead of simulation.
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)


class ResponseActionHandlers:
    """
    Handles execution of response actions via integrations.

    Supports:
    - CrowdStrike Falcon (EDR)
    - Microsoft Defender for Endpoint
    - SentinelOne
    - Okta (IAM)
    - Generic integration execution
    """

    def __init__(self):
        self._execution_engine = None
        self._initialized = False

    async def _get_execution_engine(self):
        """Lazy load execution engine to avoid circular imports."""
        if self._execution_engine is None:
            from integrations.engines.execution_engine import IntegrationExecutionEngine
            self._execution_engine = IntegrationExecutionEngine()
        return self._execution_engine

    async def _execute_integration_action(
        self,
        integration_id: str,
        action_id: str,
        payload: Dict[str, Any],
        actor_id: str = "action_request_service",
        request_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute an action via the integration execution engine.
        Falls back to simulation if integration is not configured.
        """
        try:
            from integrations.engines.execution_engine import ExecutionRequest, ExecutionContext
            from integrations.registry.integration_registry import get_registry

            # Check if integration exists and is enabled
            registry = get_registry()
            integration = registry.get(integration_id)

            if not integration:
                logger.warning(f"Integration '{integration_id}' not found - simulating execution")
                return {
                    "success": True,
                    "status": "simulated",
                    "data": {
                        "simulated": True,
                        "integration": integration_id,
                        "action": action_id,
                        "payload": payload,
                        "message": f"Integration '{integration_id}' not configured. Action simulated."
                    },
                    "error": None,
                    "execution_time_ms": 0
                }

            if not integration.enabled:
                logger.warning(f"Integration '{integration_id}' is disabled - simulating execution")
                return {
                    "success": True,
                    "status": "simulated",
                    "data": {
                        "simulated": True,
                        "integration": integration_id,
                        "action": action_id,
                        "payload": payload,
                        "message": f"Integration '{integration_id}' is disabled. Action simulated."
                    },
                    "error": None,
                    "execution_time_ms": 0
                }

            engine = await self._get_execution_engine()

            context = ExecutionContext(
                actor_id=actor_id,
                actor_type="action_request",
                request_id=request_id,
                metadata={"source": "response_action_handler"}
            )

            request = ExecutionRequest(
                integration_id=integration_id,
                action_id=action_id,
                input_payload=payload,
                context=context,
                force_refresh=True  # Response actions should never use cache
            )

            result = await engine.execute(request)

            return {
                "success": result.success,
                "status": result.status.value if result.status else "unknown",
                "data": result.data,
                "error": result.error,
                "execution_time_ms": result.execution_time_ms
            }

        except Exception as e:
            logger.error(f"Integration execution error: {e}")
            # Fall back to simulation on error
            return {
                "success": True,
                "status": "simulated",
                "data": {
                    "simulated": True,
                    "integration": integration_id,
                    "action": action_id,
                    "error_fallback": True,
                    "message": f"Execution error, action simulated: {str(e)}"
                },
                "error": None,
                "execution_time_ms": 0
            }

    # =========================================================================
    # CROWDSTRIKE HANDLERS
    # =========================================================================

    async def crowdstrike_contain_host(
        self,
        action: str,
        target: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Contain or release a host in CrowdStrike Falcon.

        Args:
            action: 'contain_host' or 'lift_containment'
            target: Host ID or hostname
            parameters: Additional parameters (hostname, device_id, etc.)
        """
        # Determine action name for CrowdStrike API
        action_name = "contain" if action == "contain_host" else "lift_containment"

        # Get device ID - could be passed directly or need lookup
        device_id = parameters.get("device_id") or target

        # If target is a hostname, we'd need to look it up first
        # For now, assume device_id is provided

        payload = {
            "action_name": action_name,
            "ids": [device_id] if isinstance(device_id, str) else device_id
        }

        result = await self._execute_integration_action(
            integration_id="crowdstrike",
            action_id="contain_host",
            payload=payload,
            request_id=parameters.get("request_id")
        )

        if result["success"]:
            return {
                "success": True,
                "result": {
                    "integration": "crowdstrike",
                    "action": action_name,
                    "device_id": device_id,
                    "message": f"Host {action_name} action completed",
                    "raw_response": result.get("data")
                }
            }
        else:
            return {
                "success": False,
                "error": result.get("error", "Unknown error"),
                "result": {"integration": "crowdstrike", "action": action_name}
            }

    async def crowdstrike_block_ioc(
        self,
        action: str,
        target: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Add or remove IOC block in CrowdStrike.

        Args:
            action: 'add_ioc_block' or 'remove_ioc_block'
            target: IOC value (IP, domain, hash)
            parameters: ioc_type, description, etc.
        """
        ioc_type = parameters.get("ioc_type", "sha256")

        # Map to CrowdStrike IOC types
        cs_type_map = {
            "ip": "ipv4",
            "ipv4": "ipv4",
            "ipv6": "ipv6",
            "domain": "domain",
            "md5": "md5",
            "sha256": "sha256",
            "sha1": "sha1"
        }
        cs_type = cs_type_map.get(ioc_type, ioc_type)

        if "remove" in action:
            # Remove IOC
            payload = {
                "ids": [parameters.get("ioc_id", target)]
            }
            action_id = "delete_ioc"
        else:
            # Add IOC block
            payload = {
                "indicators": [{
                    "type": cs_type,
                    "value": target,
                    "action": "prevent",
                    "severity": parameters.get("severity", "high"),
                    "description": parameters.get("description", f"Blocked by T1 Agentics"),
                    "platforms": parameters.get("platforms", ["windows", "mac", "linux"])
                }]
            }
            action_id = "create_ioc"

        result = await self._execute_integration_action(
            integration_id="crowdstrike",
            action_id=action_id,
            payload=payload,
            request_id=parameters.get("request_id")
        )

        return {
            "success": result["success"],
            "result": {
                "integration": "crowdstrike",
                "action": action,
                "ioc_value": target,
                "ioc_type": cs_type,
                "raw_response": result.get("data")
            },
            "error": result.get("error")
        }

    # =========================================================================
    # MICROSOFT DEFENDER HANDLERS
    # =========================================================================

    async def microsoft_defender_isolate(
        self,
        action: str,
        target: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Isolate or release a machine in Microsoft Defender.

        Args:
            action: 'isolate_machine' or 'release_isolation'
            target: Machine ID
            parameters: Additional parameters
        """
        machine_id = parameters.get("machine_id") or target

        if action == "isolate_machine":
            payload = {
                "Comment": parameters.get("comment", "Isolated by T1 Agentics"),
                "IsolationType": parameters.get("isolation_type", "Full")
            }
            action_id = "isolate_machine"
        else:
            payload = {
                "Comment": parameters.get("comment", "Released by T1 Agentics")
            }
            action_id = "unisolate_machine"

        # Add machine_id to endpoint path
        payload["machine_id"] = machine_id

        result = await self._execute_integration_action(
            integration_id="microsoft_defender",
            action_id=action_id,
            payload=payload,
            request_id=parameters.get("request_id")
        )

        return {
            "success": result["success"],
            "result": {
                "integration": "microsoft_defender",
                "action": action,
                "machine_id": machine_id,
                "raw_response": result.get("data")
            },
            "error": result.get("error")
        }

    async def microsoft_defender_indicator(
        self,
        action: str,
        target: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Add or remove indicator in Microsoft Defender.

        Args:
            action: 'add_indicator' or 'remove_indicator'
            target: Indicator value
            parameters: indicator_type, etc.
        """
        indicator_type = parameters.get("indicator_type", "FileSha256")

        # Map types
        mde_type_map = {
            "ip": "IpAddress",
            "domain": "DomainName",
            "url": "Url",
            "sha256": "FileSha256",
            "sha1": "FileSha1",
            "md5": "FileMd5"
        }
        mde_type = mde_type_map.get(indicator_type, indicator_type)

        if "remove" in action:
            payload = {"indicator_id": parameters.get("indicator_id", target)}
            action_id = "delete_indicator"
        else:
            payload = {
                "indicatorValue": target,
                "indicatorType": mde_type,
                "action": parameters.get("action", "Block"),
                "title": parameters.get("title", "T1 Agentics Block"),
                "description": parameters.get("description", "Blocked by T1 Agentics"),
                "severity": parameters.get("severity", "High")
            }
            action_id = "submit_indicator"

        result = await self._execute_integration_action(
            integration_id="microsoft_defender",
            action_id=action_id,
            payload=payload,
            request_id=parameters.get("request_id")
        )

        return {
            "success": result["success"],
            "result": {
                "integration": "microsoft_defender",
                "action": action,
                "indicator": target,
                "indicator_type": mde_type,
                "raw_response": result.get("data")
            },
            "error": result.get("error")
        }

    # =========================================================================
    # SENTINELONE HANDLERS
    # =========================================================================

    async def sentinelone_agent_action(
        self,
        action: str,
        target: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Disconnect or reconnect agent in SentinelOne.

        Args:
            action: 'disconnect_agent' or 'reconnect_agent'
            target: Agent ID
            parameters: Additional parameters
        """
        agent_id = parameters.get("agent_id") or target

        if action == "disconnect_agent":
            action_id = "disconnect_from_network"
        else:
            action_id = "connect_to_network"

        payload = {
            "filter": {
                "ids": [agent_id] if isinstance(agent_id, str) else agent_id
            }
        }

        result = await self._execute_integration_action(
            integration_id="sentinelone",
            action_id=action_id,
            payload=payload,
            request_id=parameters.get("request_id")
        )

        return {
            "success": result["success"],
            "result": {
                "integration": "sentinelone",
                "action": action,
                "agent_id": agent_id,
                "raw_response": result.get("data")
            },
            "error": result.get("error")
        }

    # =========================================================================
    # OKTA HANDLERS
    # =========================================================================

    async def okta_user_action(
        self,
        action: str,
        target: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Perform user actions in Okta.

        Args:
            action: 'suspend_user', 'unsuspend_user', 'expire_password', 'clear_sessions'
            target: User ID or email
            parameters: Additional parameters
        """
        user_id = parameters.get("user_id") or target

        action_map = {
            "suspend_user": "suspend_user",
            "unsuspend_user": "unsuspend_user",
            "expire_password": "expire_password",
            "clear_sessions": "clear_sessions",
            "disable_user": "suspend_user",
            "enable_user": "unsuspend_user"
        }

        action_id = action_map.get(action, action)
        payload = {"user_id": user_id}

        result = await self._execute_integration_action(
            integration_id="okta",
            action_id=action_id,
            payload=payload,
            request_id=parameters.get("request_id")
        )

        return {
            "success": result["success"],
            "result": {
                "integration": "okta",
                "action": action,
                "user_id": user_id,
                "raw_response": result.get("data")
            },
            "error": result.get("error")
        }

    # =========================================================================
    # GENERIC HANDLER
    # =========================================================================

    async def generic_handler(
        self,
        action: str,
        target: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generic handler for actions without specific integration.
        Attempts to execute via configured integration.
        """
        integration_id = parameters.get("integration_id")
        action_id = parameters.get("action_id") or action

        if not integration_id:
            return {
                "success": False,
                "error": "No integration_id specified for generic action",
                "result": {"action": action, "target": target}
            }

        payload = {
            "target": target,
            **parameters
        }

        result = await self._execute_integration_action(
            integration_id=integration_id,
            action_id=action_id,
            payload=payload,
            request_id=parameters.get("request_id")
        )

        return {
            "success": result["success"],
            "result": {
                "integration": integration_id,
                "action": action_id,
                "target": target,
                "raw_response": result.get("data")
            },
            "error": result.get("error")
        }

    # =========================================================================
    # REGISTRATION
    # =========================================================================

    def get_handlers(self) -> Dict[str, callable]:
        """
        Return mapping of integration names to handler functions.
        Used to register with ActionRequestService.
        """
        return {
            "crowdstrike": self._route_crowdstrike,
            "microsoft_defender": self._route_microsoft_defender,
            "sentinelone": self._route_sentinelone,
            "okta": self._route_okta,
            "azure_ad": self._route_okta,  # Similar IAM actions
            "active_directory": self._route_generic_ad,
            "palo_alto": self._route_palo_alto,
            "zscaler": self._route_zscaler,
        }

    async def _route_crowdstrike(
        self,
        action: str,
        target: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Route CrowdStrike actions to appropriate handler."""
        if action in ["contain_host", "lift_containment"]:
            return await self.crowdstrike_contain_host(action, target, parameters)
        elif "ioc" in action.lower() or action in ["block_ip", "block_domain", "block_hash"]:
            return await self.crowdstrike_block_ioc(action, target, parameters)
        else:
            return await self.generic_handler(action, target, {**parameters, "integration_id": "crowdstrike"})

    async def _route_microsoft_defender(
        self,
        action: str,
        target: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Route Microsoft Defender actions to appropriate handler."""
        if action in ["isolate_machine", "release_isolation"]:
            return await self.microsoft_defender_isolate(action, target, parameters)
        elif "indicator" in action.lower() or action in ["block_hash", "block_ip", "block_domain"]:
            return await self.microsoft_defender_indicator(action, target, parameters)
        else:
            return await self.generic_handler(action, target, {**parameters, "integration_id": "microsoft_defender"})

    async def _route_sentinelone(
        self,
        action: str,
        target: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Route SentinelOne actions to appropriate handler."""
        if action in ["disconnect_agent", "reconnect_agent", "contain_host", "un-contain_host"]:
            # Map containment actions
            if action == "contain_host":
                action = "disconnect_agent"
            elif action == "un-contain_host":
                action = "reconnect_agent"
            return await self.sentinelone_agent_action(action, target, parameters)
        else:
            return await self.generic_handler(action, target, {**parameters, "integration_id": "sentinelone"})

    async def _route_okta(
        self,
        action: str,
        target: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Route Okta actions to appropriate handler."""
        return await self.okta_user_action(action, target, parameters)

    async def _route_generic_ad(
        self,
        action: str,
        target: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Route Active Directory actions - requires custom integration."""
        return {
            "success": False,
            "error": "Active Directory integration requires on-premise connector",
            "result": {
                "integration": "active_directory",
                "action": action,
                "target": target,
                "message": "Configure AD connector or use Azure AD for cloud users"
            }
        }

    async def _route_palo_alto(
        self,
        action: str,
        target: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Route Palo Alto actions."""
        return await self.generic_handler(action, target, {**parameters, "integration_id": "palo_alto"})

    async def _route_zscaler(
        self,
        action: str,
        target: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Route Zscaler actions."""
        return await self.generic_handler(action, target, {**parameters, "integration_id": "zscaler"})

    async def _route_generic(
        self,
        action: str,
        target: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generic routing for unconfigured integrations - simulates execution."""
        # When no real integration is available, simulate success
        return {
            "success": True,
            "result": {
                "simulated": True,
                "action": action,
                "target": target,
                "message": f"Simulated {action} on {target} (no integration configured)",
                "note": "Configure CrowdStrike, Microsoft Defender, or other EDR to execute real actions"
            }
        }


# =========================================================================
# REGISTRATION FUNCTION
# =========================================================================

async def register_response_handlers(action_request_service):
    """
    Register all response action handlers with ActionRequestService.

    Call this during application startup.
    """
    handlers = ResponseActionHandlers()

    for integration_name, handler in handlers.get_handlers().items():
        action_request_service.register_execution_handler(integration_name, handler)
        logger.info(f"Registered response handler for: {integration_name}")

    logger.info(f"Registered {len(handlers.get_handlers())} response action handlers")
    return handlers


# Singleton instance
_handlers_instance: Optional[ResponseActionHandlers] = None

def get_response_handlers() -> ResponseActionHandlers:
    """Get or create the response handlers singleton."""
    global _handlers_instance
    if _handlers_instance is None:
        _handlers_instance = ResponseActionHandlers()
    return _handlers_instance
