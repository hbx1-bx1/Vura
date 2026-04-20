#!/bin/bash
set -euo pipefail

# Resolve and cd to the directory this script lives in, so `rm -rf` below
# can NEVER run against the user's cwd (e.g. their home dir).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Sanity-check: refuse to proceed if we're not actually in the VURA repo.
if [ ! -f "main.py" ] || [ ! -d "app" ]; then
    echo "[!] Refusing to clean: build.sh must be run from the VURA project root." >&2
    exit 1
fi

echo "[+] Cleaning old build files..."
rm -rf main.build main.dist main.onefile-build vura

echo "[+] Starting VURA compilation using Nuitka..."
# --python-flag=-OO  : strip asserts + docstrings at bytecode level (smaller binary)
# --remove-output    : delete *.build/ intermediates on success so the tree stays clean
python -m nuitka --standalone --onefile \
    --python-flag=-OO \
    --remove-output \
    --include-package=app \
    --include-package=rich \
    --include-package=cryptography \
    --include-package=requests \
    main.py -o vura

echo "========================================="
echo "[✔] Compilation Finished!"
echo "[✔] Your commercial executable is ready: ./vura"
echo "========================================="
