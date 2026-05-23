#!/usr/bin/env python3
"""
Benign exec-from-/tmp trigger.

Creates a tiny shell script in /tmp, marks it executable, and runs it.
"""

import os
import stat
import subprocess
import tempfile
import time

script = tempfile.NamedTemporaryFile(prefix="signalhunter_exec_", suffix=".sh", dir="/tmp", delete=False)
script.write(b"#!/bin/sh\necho SIGNALHUNTER_TMP_EXEC\nsleep 5\n")
script.close()

os.chmod(script.name, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

print(f"[test] executing {script.name}")
subprocess.run([script.name], check=False)

try:
    os.unlink(script.name)
except OSError:
    pass

time.sleep(2)
