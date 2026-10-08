#!/usr/bin/env python3
"""Build threatlib/atlas_threats.json.

Merges the stock pytm threat library with the Py-Threat-Atlas cloud, AI and
agentic extensions, and tags every threat with a primary STRIDE category so the
site can group findings. pytm ignores the extra "stride" key when loading.

Usage: python tools/build_threatlib.py [--check]
"""

import json
import sys
from pathlib import Path

import pytm

ROOT = Path(__file__).resolve().parents[1]
EXTENSIONS = ROOT / "threatlib" / "atlas_extensions.json"
OUTPUT = ROOT / "threatlib" / "atlas_threats.json"
PYTM_THREATS = Path(pytm.__file__).parent / "threatlib" / "threats.json"

S, T, R, I, D, E = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)

# Primary STRIDE category for each stock pytm (CAPEC-derived) threat.
STOCK_STRIDE = {
    # Spoofing: identity, session and credential attacks
    "AA01": S, "AA02": S, "AA03": S, "CR01": S, "CR03": S, "CR04": S,
    "AC11": S, "AC16": S, "AC17": S, "AC18": S, "AC19": S, "AC20": S,
    "AC21": S, "AC22": S, "INP20": S,
    # Tampering: injection, parameter and protocol manipulation
    "INP03": T, "INP04": T, "INP06": T, "INP08": T, "INP09": T, "INP10": T,
    "INP13": T, "INP14": T, "INP15": T, "INP17": T, "INP21": T, "INP23": T,
    "INP25": T, "INP27": T, "INP28": T, "INP29": T, "INP30": T, "INP32": T,
    "INP35": T, "INP36": T, "INP37": T, "INP38": T, "INP39": T, "INP40": T,
    "INP41": T, "SC02": T, "SC03": T, "SC04": T, "SC05": T, "DE02": T,
    "LB01": T, "AC02": T, "AC04": T, "AC05": T, "AC08": T, "AC15": T,
    "AA04": T, "CR06": T, "CR07": T, "CR08": T,
    # Repudiation
    "DE04": R,
    # Information disclosure
    "CR02": I, "CR05": I, "SC01": I, "DS01": I, "DS02": I, "DS03": I,
    "DS04": I, "DS05": I, "DS06": I, "DE01": I, "DE03": I, "DR01": I,
    "HA01": I, "HA02": I, "HA03": I, "HA04": I, "INP11": I, "INP18": I,
    "AC10": I,
    # Denial of service
    "DO01": D, "DO02": D, "DO03": D, "DO04": D, "DO05": D, "INP19": D,
    "INP22": D, "INP34": D,
    # Elevation of privilege: code execution and access-control bypass
    "INP01": E, "INP02": E, "INP05": E, "INP07": E, "INP12": E, "INP16": E,
    "INP24": E, "INP26": E, "INP31": E, "INP33": E, "AC01": E, "AC03": E,
    "AC06": E, "AC07": E, "AC09": E, "AC12": E, "AC13": E, "AC14": E,
    "API01": E, "API02": E,
}


# Corrections to stock pytm 1.3.1 conditions with inverted logic.
CONDITION_PATCHES = {
    # XXE / DTD threats fired for every server that does NOT parse XML.
    "INP19": "target.usesXMLParser is True and target.controls.disablesDTD is False",
    "INP21": "target.usesXMLParser is True and target.controls.disablesDTD is False",
    "INP22": "target.usesXMLParser is True and target.controls.disablesDTD is False",
    # Fired when stored data WAS encrypted at rest instead of when it was not.
    "DR01": (
        "(target.hasDataLeaks() or any(d.isCredentials or d.isPII for d in target.data)) and "
        "(not target.controls.isEncrypted or "
        "(not target.isResponse and any(d.isStored and not d.isDestEncryptedAtRest for d in target.data)) or "
        "(target.isResponse and any(d.isStored and not d.isSourceEncryptedAtRest for d in target.data)))"
    ),
}


def build():
    stock = json.loads(PYTM_THREATS.read_text(encoding="utf8"))
    extensions = json.loads(EXTENSIONS.read_text(encoding="utf8"))

    for threat in stock:
        if threat["SID"] in CONDITION_PATCHES:
            threat["condition"] = CONDITION_PATCHES[threat["SID"]]
            threat["patched"] = True

    unmapped = [t["SID"] for t in stock if t["SID"] not in STOCK_STRIDE]
    if unmapped:
        sys.exit(f"No STRIDE mapping for stock threats: {', '.join(unmapped)}")

    for threat in stock:
        threat["stride"] = STOCK_STRIDE[threat["SID"]]
        threat["source"] = "pytm"
    for threat in extensions:
        if "stride" not in threat:
            sys.exit(f"Extension threat {threat['SID']} is missing 'stride'")
        threat["source"] = "atlas"

    ids = [t["SID"] for t in stock + extensions]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        sys.exit(f"Duplicate threat IDs: {', '.join(sorted(duplicates))}")

    return json.dumps(stock + extensions, indent=2, ensure_ascii=False) + "\n"


def main():
    content = build()
    if "--check" in sys.argv:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf8") != content:
            sys.exit("threatlib/atlas_threats.json is stale; run tools/build_threatlib.py")
        print("threatlib/atlas_threats.json is up to date")
        return
    OUTPUT.write_text(content, encoding="utf8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
