#!/bin/sh
#
# american fuzzy lop - QEMU build script
# --------------------------------------
#
# Written by Andrew Griffiths <agriffiths@google.com> and
#            Michal Zalewski <lcamtuf@google.com>
#
# Copyright 2015 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# This script downloads, patches, and builds a version of QEMU with
# minor tweaks to allow non-instrumented binaries to be run under
# afl-fuzz.
#
# The modifications reside in patches/*. The standalone QEMU binary
# will be written to ../afl-qemu-trace.
#

echo "================================================="
echo "AFL binary-only instrumentation QEMU build script"
echo "================================================="
echo

echo "[*] Performing basic sanity checks..."

if [ ! "`uname -s`" = "Linux" ]; then

  echo "[-] Error: QEMU instrumentation is supported only on Linux."
  exit 1

fi

if [ ! -f "patches/afl-qemu-cpu-inl.h" -o ! -f "../config.h" ]; then

  echo "[-] Error: key files not found - wrong working directory?"
  exit 1

fi

if [ ! -f "../afl-showmap" ]; then

  echo "[-] Error: ../afl-showmap not found - compile AFL first!"
  exit 1

fi


for i in libtool wget python automake autoconf sha384sum bison iconv; do

  T=`which "$i" 2>/dev/null`

  if [ "$T" = "" ]; then

    echo "[-] Error: '$i' not found, please install first."
    exit 1

  fi

done

if [ ! -d "/usr/include/glib-2.0/" -a ! -d "/usr/local/include/glib-2.0/" ]; then

  echo "[-] Error: devel version of 'glib2' not found, please install first."
  exit 1

fi

if echo "$CC" | grep -qF /afl-; then

  echo "[-] Error: do not use afl-gcc or afl-clang to compile this tool."
  exit 1

fi

echo "[+] Building a multi-CB-ready qemu!"

if [ -d qemu-dev ]; then
    echo "[*] Reusing the existing qemu-dev dir (dev only! will just run make)"
    QEMU_DIR=qemu-dev
    cd $QEMU_DIR || exit 1
else
    QEMU_DIR=multicb-qemu
    rm -rf $QEMU_DIR
    echo "[*] Cloning our multi-CB QEMU branch..."
    git clone --branch multicb_afl --depth=1 git@git.seclab.cs.ucsb.edu:cgc/qemu.git $QEMU_DIR || exit 1
    echo "[+] Checked out."
    cd $QEMU_DIR || exit 1
    echo "[*] Configuring QEMU..."
    ./cgc_configure_opt
    echo "[+] Configuration complete."
fi

echo "[*] Attempting to build QEMU (fingers crossed!)..."

make -j || exit 1

echo "[+] Build process successful!"

echo "[*] Copying binary..."

cp -f "i386-linux-user/qemu-i386" "../../../fakeforksrv/multicb-qemu" || exit 1
echo "[+] Successfully created '../../../fakeforksrv/multicb-qemu'."

echo "[+] All set, you should now be able to use it together with fakeforksrv!"

exit 0
