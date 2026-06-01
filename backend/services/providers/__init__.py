# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Threat Intelligence Providers
"""

from services.providers.base_provider import BaseThreatIntelProvider
from services.virustotal import VirusTotalService

# Registry of available providers
AVAILABLE_PROVIDERS = {
    'virustotal': VirusTotalService,
    # More providers will be added here:
    # 'otx': OTXService,
    # 'threatfox': ThreatFoxService,
    # 'urlscan': URLScanService,
}

__all__ = ['BaseThreatIntelProvider', 'VirusTotalService', 'AVAILABLE_PROVIDERS']
