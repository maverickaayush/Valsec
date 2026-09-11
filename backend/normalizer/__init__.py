"""Vendor-neutral configuration normalization entry points."""

from .cisco_ios import CiscoIOSNormalizer, LearnedMappingResolver, MappingMatch
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
    "LearnedMappingResolver",
    "MappingMatch",
    "MappingSource",
    "NormalizationResult",
    "NormalizedFinding",
    "UnknownLine",
    "VendorNeutralConfig",
]
