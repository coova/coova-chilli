#!/bin/sh
# copyright (c) David Bird <david@coova.com>
# this is the pure shell version...

cat <<EOF
HTTP/1.0 200 OK
Content-Type: text/javascript
Cache: none

EOF

. ./config.sh

cat ChilliLibrary.js

echo "chilliController.host = '$hs_uamlisten';"
echo "chilliController.port = $hs_uamport;"
[ -n "$hs_uamservice" ] && echo "chilliController.uamService = '$hs_uamservice';"
[ "$hs_openidauth" = "on" ] && echo "chilliController.openid = true;"

cat chilliController.js
