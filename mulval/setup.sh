#!/bin/sh
# Clone the attack graph engine at the commit every recorded result was produced with.
# Nothing here is vendored: this script fetches, checks and reports, and stops short of
# building XSB, which has its own installer and would fail halfway if pretended otherwise.
set -e

COMMIT=07d279f
REPO=https://github.com/risksense/mulval.git
DEST="${MULVALROOT:-$HOME/mulval}"

if [ -d "$DEST/.git" ]; then
    echo "mulval already at $DEST"
else
    echo "cloning $REPO into $DEST"
    git clone "$REPO" "$DEST"
fi

cd "$DEST"
git fetch --quiet origin
git checkout --quiet "$COMMIT"
echo "mulval pinned at $(git rev-parse --short HEAD)"

echo
missing=0
for tool in xsb dot; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "  found    $tool"
    else
        echo "  MISSING  $tool"
        missing=1
    fi
done

if [ ! -x "$HOME/XSB/bin/xsb" ] && ! command -v xsb >/dev/null 2>&1; then
    cat <<'MSG'

  XSB Prolog is not on PATH. MulVAL will not run without it; graph_gen.sh reports
  "xsb: not found" and leaves no VERTICES.CSV behind, which is easy to mistake for an
  empty graph. Install it from https://xsb.sourceforge.net and put its bin/ on PATH:

      export PATH=$HOME/XSB/bin:$PATH
MSG
    missing=1
fi

echo
echo "then:  export MULVALROOT=$DEST"
echo "       export PATH=\$MULVALROOT/utils:\$HOME/XSB/bin:\$PATH"
[ "$missing" -eq 0 ] || echo
[ "$missing" -eq 0 ] || echo "one or more dependencies are missing; see above."
