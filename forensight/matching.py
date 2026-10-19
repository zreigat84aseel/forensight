"""Match one email against the known campaigns from the clustering module (Section 17).

An email belongs to a known campaign when it shares at least one strong indicator with it,
or at least two weak indicators: the same rule that the clustering uses to link two emails.
This lets the dashboard and the API recognise a new email from an existing campaign.
"""

import json
from pathlib import Path

from forensight.clustering import MIN_WEAK_SHARED, STRONG, WEAK

CAMPAIGNS_FILE = Path("output") / "campaigns.json"


def load_campaigns(path=CAMPAIGNS_FILE):
    """Return (summary, campaigns) from the clustering output, or (None, []) if it does not exist."""
    path = Path(path)
    if not path.is_file():
        return None, []
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("summary"), data.get("campaigns", [])


def match_campaigns(indicators, campaigns, email_name=None):
    """Return the campaigns that this email belongs to, best match first.

    indicators: set of (type, value) pairs from clustering.extract_indicators().
    email_name: file name of the email; if it is listed in a campaign it is a known member.
    """
    matches = []
    for campaign in campaigns:
        known = {(item["type"], item["value"]) for item in campaign["indicators"]}
        shared = set(indicators) & known
        strong = sorted(pair for pair in shared if pair[0] in STRONG)
        weak = sorted(pair for pair in shared if pair[0] in WEAK)
        member = bool(email_name) and email_name in campaign.get("emails", ())
        if member or strong or len(weak) >= MIN_WEAK_SHARED:
            matches.append({"id": campaign["id"], "size": campaign["size"], "member": member,
                            "strong": strong, "weak": weak})
    matches.sort(key=lambda m: (not m["member"], -len(m["strong"]), -len(m["weak"]), -m["size"]))
    return matches
