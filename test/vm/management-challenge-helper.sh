#!/bin/sh
set -eu

# The protocol request is deliberately consumed even though this deterministic
# fixture always returns the same test-only OTP. Production helpers can parse
# the bounded JSON fields to dispatch to a TOTP store or an interactive broker.
cat >/dev/null
printf '%s\n' '246810'
