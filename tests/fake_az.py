#!/usr/bin/env python3
import json
import sys
import time
from urllib.parse import urlsplit

if sys.argv[1:3] != ["account", "get-access-token"]:
    sys.exit(2)
resource = sys.argv[sys.argv.index("--resource") + 1]
if urlsplit(resource).hostname == "timeout.test":
    time.sleep(60)
print(
    json.dumps(
        {
            "accessToken": "fake-" + (urlsplit(resource).hostname or "unknown"),
            "expires_on": int(time.time()) + 3600,
        }
    )
)
