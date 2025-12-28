#!/bin/bash

cd kernel/deps/flanterm/
git apply ../patches/flanterm/aarch64_alignment_fix.patch
cd ../../..