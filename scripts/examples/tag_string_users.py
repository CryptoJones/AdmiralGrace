"""Tag every function that uses a string matching a pattern, and bookmark the
one that uses the most of them.

    ag run ./sample.elf --project sample.agproj -- \
        python3 scripts/examples/tag_string_users.py 'hello|world' greeting

The first argument is the pattern; the second is the tag (default
`strings`). The tags land in the project file, where the workbench's
navigator filters by them (`#greeting`).
"""

import sys
from collections import Counter
from pathlib import Path

# The client module lives one directory up, beside the examples.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ag import Session  # noqa: E402

pattern = sys.argv[1] if len(sys.argv) > 1 else "."
tag = sys.argv[2] if len(sys.argv) > 2 else "strings"

ag = Session()
users = Counter()
for string in ag.strings(filter=pattern, limit=5000)["strings"]:
    for function in string["functions"]:
        users[function["address_hex"]] += 1

for address in users:
    ag.set_tags(address, add=[tag], on="function")
    print(f"tagged {address} {tag}", file=sys.stderr)

if users:
    busiest, count = users.most_common(1)[0]
    ag.set_bookmark(busiest)
    ag.set_comment(busiest, f"uses {count} string(s) matching {pattern!r}", above=True)
    print(f"bookmarked {busiest} ({count} strings)", file=sys.stderr)
else:
    print(f"no string matches {pattern!r}", file=sys.stderr)
