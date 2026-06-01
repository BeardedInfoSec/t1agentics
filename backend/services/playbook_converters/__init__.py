# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Playbook Converters Package

Converts playbooks from various SOAR platforms to T1 Agentics native format.
Supported platforms:
- Splunk SOAR (Phantom)
- Palo Alto XSOAR (Demisto)
- Tines
- Swimlane
- Google Chronicle SOAR (Siemplify)
- IBM QRadar SOAR (Resilient)
- Microsoft Sentinel (Azure Logic Apps)
- FortiSOAR (Fortinet)
- LogicHub (SOAR + SIEM)
- Resolve (Resolve Systems)
- ServiceNow Security Operations (Flow Designer)
- Exabeam (New-Scale SOAR)
- Rapid7 InsightConnect (Komand)
- TheHive / Cortex (StrangeBee)
- Shuffle (Open Source SOAR)
- Torq (Hyperautomation)
- BlinkOps (No-Code Security Automation)
- D3 Security (Smart SOAR)
"""

from .base import PlaybookConverter, ConversionReport, ParsedPlaybook, SourcePlatform
from .action_maps import ACTION_MAPS
from .splunk_soar import SplunkSOARConverter
from .xsoar import XSOARConverter
from .tines import TinesConverter
from .swimlane import SwimlaneConverter
from .chronicle_soar import ChronicleSoarConverter
from .qradar_soar import QRadarSOARConverter
from .sentinel import SentinelConverter
from .fortisoar import FortiSOARConverter
from .logichub import LogicHubConverter
from .resolve import ResolveConverter
from .servicenow_secops import ServiceNowSecOpsConverter
from .exabeam import ExabeamConverter
from .insight_connect import InsightConnectConverter
from .thehive import TheHiveConverter
from .shuffle import ShuffleConverter
from .torq import TorqConverter
from .blinkops import BlinkOpsConverter
from .d3_security import D3SecurityConverter

__all__ = [
    'PlaybookConverter',
    'ConversionReport',
    'ParsedPlaybook',
    'SourcePlatform',
    'ACTION_MAPS',
    'SplunkSOARConverter',
    'XSOARConverter',
    'TinesConverter',
    'SwimlaneConverter',
    'ChronicleSoarConverter',
    'QRadarSOARConverter',
    'SentinelConverter',
    'FortiSOARConverter',
    'LogicHubConverter',
    'ResolveConverter',
    'ServiceNowSecOpsConverter',
    'ExabeamConverter',
    'InsightConnectConverter',
    'TheHiveConverter',
    'ShuffleConverter',
    'TorqConverter',
    'BlinkOpsConverter',
    'D3SecurityConverter',
]
