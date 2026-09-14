"""Validate stable release branch names and tags used to stamp gophlare builds."""

import re
import sys

VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"


def release_tag(branch):
    match = re.fullmatch(rf"(?:release|hotfix)/v?({VERSION})", branch)
    if match is None:
        raise ValueError("Use release/vX.Y.Z or hotfix/vX.Y.Z with a stable version")
    return f"v{match[1]}"


def check_version(tag):
    if re.fullmatch(rf"v{VERSION}", tag) is None:
        raise ValueError("Release tags must be stable versions: vX.Y.Z")


def main(args):
    if args[0] == "tag":
        print(release_tag(args[1]))
    elif args[0] == "version":
        check_version(args[1])
    else:
        raise ValueError("Unknown policy command")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (ValueError, IndexError) as exc:
        sys.exit(str(exc))
