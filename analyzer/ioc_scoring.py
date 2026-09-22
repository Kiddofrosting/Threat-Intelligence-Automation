"""IOC significance/importance scoring.

Not every extracted indicator deserves equal attention in the report.
This module scores each IOC purely from the evidence actually
attached to it in *this* capture -- detection signals that named it,
threat-intelligence assessments that matched it, and how often it was
observed -- and sorts it into a significance tier. No indicator is
hardcoded into a tier; the tier is entirely a function of the evidence
found for that specific indicator.
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List

from analyzer.detector import DetectionSignal
from analyzer.ioc_extractor import IOC
from analyzer.ti_interpreter import TIAssessment

INSIGNIFICANT = "insignificant"
NOTEWORTHY = "noteworthy"
SUSPICIOUS_TIER = "suspicious"
HIGH_PRIORITY = "high-priority"


@dataclass
class IOCProfile:
    indicator: str
    ioc_type: str
    significance: int = 0
    tier: str = INSIGNIFICANT
    detection_rule_ids: List[str] = field(default_factory=list)
    ti_states: List[str] = field(default_factory=list)
    observation_count: int = 0


def _tier_for(score: int) -> str:
    if score >= 45:
        return HIGH_PRIORITY
    if score >= 25:
        return SUSPICIOUS_TIER
    if score >= 8:
        return NOTEWORTHY
    return INSIGNIFICANT


def classify_iocs(
    iocs: List[IOC],
    detections: List[DetectionSignal],
    ti_assessments: Dict[str, List[TIAssessment]],
    observation_counts: Dict[str, int],
) -> Dict[str, IOCProfile]:
    profiles: Dict[str, IOCProfile] = {
        ioc.indicator: IOCProfile(indicator=ioc.indicator, ioc_type=ioc.type,
                                    observation_count=observation_counts.get(ioc.indicator, 0))
        for ioc in iocs
    }

    for det in detections:
        if det.suppressed:
            continue
        profile = profiles.get(det.indicator)
        if profile is None:
            continue
        profile.significance += det.score
        profile.detection_rule_ids.append(det.rule_id)

    for indicator, assessments in ti_assessments.items():
        profile = profiles.get(indicator)
        if profile is None:
            continue
        for a in assessments:
            profile.significance += a.weight
            if a.state != "UNKNOWN":
                profile.ti_states.append(f"{a.feed}:{a.state}")

    for profile in profiles.values():
        if profile.observation_count > 1:
            profile.significance += min(int(math.log2(profile.observation_count)), 5)
        profile.tier = _tier_for(profile.significance)

    return profiles


def summarize_tiers(profiles: Dict[str, IOCProfile]) -> Dict[str, int]:
    counts = {INSIGNIFICANT: 0, NOTEWORTHY: 0, SUSPICIOUS_TIER: 0, HIGH_PRIORITY: 0}
    for profile in profiles.values():
        counts[profile.tier] += 1
    return counts
