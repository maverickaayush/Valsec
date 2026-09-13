"""Vendor-neutral configuration normalization entry points."""

from .cisco_ios import CiscoIOSNormalizer, LearnedMappingResolver, MappingMatch
from .generic import GenericFallbackNormalizer
from .fortios import FortiOSNormalizer
from .schema import (
    Confidence,
    MappingSource,
    NormalizationResult,
    NormalizedFinding,
    UnknownLine,
    VendorNeutralConfig,
)

__all__ = [
    "CiscoIOSNormalizer",
    "Confidence",
    "GenericFallbackNormalizer",
    "FortiOSNormalizer",
    "LearnedMappingResolver",
    "MappingMatch",
    "MappingSource",
    "NormalizationResult",
    "NormalizedFinding",
    "UnknownLine",
    "VendorNeutralConfig",
]
