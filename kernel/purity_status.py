"""Kernel purity status.

Verify path is MEASURED. Issuance is refused by construction.
Emission remains HELD. UNKNOWN is never PASS.
"""

from __future__ import annotations

from typing import Dict, Any


def status() -> Dict[str, Any]:
    return {
        "protocol": "COIN.KERNEL.PURITY.v1",
        "law": "LAW WINS",
        "boundary": "NOT_FOR_EMISSION",
        "verify_path": "MEASURED",
        "issuance": "REFUSED_BY_CONSTRUCTION",
        "emission": "HELD",
        "live_coin": False,
        "live_wallet": False,
        "keys_in_repo": "TRANSITIONAL",
        "unknown_never_pass": True,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(status(), indent=2))
