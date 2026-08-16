"""Bounded, local NetFlow v9/IPFIX analysis proof of concept.

The POC has no router configuration, credentials, packet capture, model
loading, or response action. Live UDP collection is opt-in and guarded by the
collector policy in :mod:`network_ai.flow_poc.collector`.
"""

from .analysis import AnalysisRunOutcome, FlowAnalyzer, analyze_and_record
from .collector import FlowCollector, ListenerPolicy
from .protocol import TemplateCache, decode_datagram
from .storage import FlowRepository

__all__ = [
    "FlowAnalyzer",
    "AnalysisRunOutcome",
    "analyze_and_record",
    "FlowCollector",
    "FlowRepository",
    "ListenerPolicy",
    "TemplateCache",
    "decode_datagram",
]
