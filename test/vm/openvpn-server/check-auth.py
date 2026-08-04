#!/usr/bin/python3

import base64
import binascii
import hmac
import sys

FIXTURE_OTP = "246810"


def unpack_static_challenge(value: str) -> tuple[str, str] | None:
    if not value.startswith("SCRV1:"):
        return value, ""
    fields = value.split(":", 2)
    if len(fields) != 3:
        return None
    try:
        password = base64.b64decode(fields[1], validate=True).decode("utf-8")
        response = base64.b64decode(fields[2], validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    return password, response


def main() -> int:
    if len(sys.argv) != 2:
        return 1

    try:
        with open(sys.argv[1], encoding="utf-8") as credentials:
            supplied_username = credentials.readline().rstrip("\r\n")
            supplied_password = credentials.readline().rstrip("\r\n")
    except OSError:
        return 1

    if not supplied_username or not supplied_password:
        return 1
    unpacked = unpack_static_challenge(supplied_password)
    if unpacked is None:
        return 1
    supplied_password, challenge_response = unpacked
    if challenge_response and not hmac.compare_digest(
        challenge_response,
        FIXTURE_OTP,
    ):
        return 1

    try:
        with open("/etc/openvpn/server/users", encoding="utf-8") as users:
            for line in users:
                username, separator, password = line.rstrip("\n").partition(":")
                if not separator:
                    continue
                username_matches = hmac.compare_digest(username, supplied_username)
                password_matches = hmac.compare_digest(password, supplied_password)
                if username_matches and password_matches:
                    return 0
    except OSError:
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
