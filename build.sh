#!/bin/bash

echo "[+] Cleaning old build files..."
rm -rf main.build main.dist main.onefile-build vura

echo "[+] Starting VURA compilation using Nuitka..."
# نقوم بدمج الحزم الأساسية لضمان عمل الملف التنفيذي بدون أخطاء
python -m nuitka --standalone --onefile \
    --include-package=app \
    --include-package=rich \
    --include-package=cryptography \
    --include-package=requests \
    main.py -o vura

echo "========================================="
echo "[✔] Compilation Finished!"
echo "[✔] Your commercial executable is ready: ./vura"
echo "========================================="
