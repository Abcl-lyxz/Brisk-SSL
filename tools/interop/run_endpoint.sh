#!/bin/bash
# quic-interop-runner endpoint script (quic-network-simulator contract): client role only.
set -e
/setup.sh # the simulator's routes and qdiscs
if [ "$ROLE" != "client" ]; then
    echo "brisk is a client-only library"
    exit 127
fi
case "$TESTCASE" in
handshake | transfer | multiplexing | retry | chacha20 | keyupdate | resumption) ;;
*) exit 127 ;;
esac
/wait-for-it.sh sim:57832 -s -t 30
echo "brisk_hq: $TESTCASE"
set +e
brisk_hq
rc=$?
echo "brisk_hq: exit $rc"
exit $rc
