#!/bin/sh
# Refuse to start without a token, as `python -m loom_computer` does: under a
# supervisor the API would otherwise just restart in a loop.
if [ -z "$LOOM_COMPUTER_TOKEN" ]; then
  echo "loom-computer: LOOM_COMPUTER_TOKEN is not set; refusing to start" >&2
  exit 1
fi
exec supervisord -c /opt/loom-computer/image/supervisord.conf
