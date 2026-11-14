#!/bin/sh
# Serve the leaderboard on this machine only, so ?live can refresh in place.
#   sh scripts/serve_board.sh            ->  http://127.0.0.1:8766/leaderboard.html?live
#   PORT=9000 sh scripts/serve_board.sh  (if 8766 is taken)
cd "$(dirname "$0")/../dashboard" && exec python3 -m http.server "${PORT:-8766}" --bind 127.0.0.1
