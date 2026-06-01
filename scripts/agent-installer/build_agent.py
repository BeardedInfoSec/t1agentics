#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Agent Build Script
=====================
Builds obfuscated, standalone executables of the T1 agent.

Methods:
1. PyInstaller + PyArmor (best obfuscation)
2. PyInstaller + Cython (compiles to C)
3. Nuitka (compiles to native code)

Usage:
    python3 build_agent.py --method pyarmor
    python3 build_agent.py --method cython
    python3 build_agent.py --method nuitka

Requirements:
    pip install pyinstaller pyarmor cython nuitka
"""

import os
import sys
import shutil
import subprocess
import argparse
import tempfile
from pathlib import Path

AGENT_FILES = [
    "t1_unified_agent.py",
    "t1_agent.py",
    "t1_edr.py"
]

OUTPUT_DIR = "dist"


def clean_build():
    """Clean previous build artifacts"""
    for d in ["build", "dist", "__pycache__", "*.spec"]:
        if "*" in d:
            for f in Path(".").glob(d):
                if f.is_file():
                    f.unlink()
        else:
            p = Path(d)
            if p.exists():
                shutil.rmtree(p)
    print("[+] Cleaned build artifacts")


def build_with_pyarmor(source_file: str) -> str:
    """
    Build with PyArmor obfuscation + PyInstaller

    PyArmor provides:
    - Code obfuscation
    - String encryption
    - Anti-debugging
    - License binding (optional)
    """
    print(f"[+] Building {source_file} with PyArmor obfuscation...")

    base_name = Path(source_file).stem
    output_name = f"t1-agent-{base_name.replace('t1_', '').replace('_agent', '')}"

    # Create temp directory for obfuscated source
    with tempfile.TemporaryDirectory() as tmpdir:
        # Step 1: Obfuscate with PyArmor
        print("    [*] Obfuscating code...")
        cmd = [
            "pyarmor", "gen",
            "--output", tmpdir,
            "--enable-jit",  # JIT protection
            "--enable-bcc",  # Byte code encryption
            "--mix-str",     # String obfuscation
            source_file
        ]

        try:
            subprocess.run(cmd, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            print(f"    [!] PyArmor failed: {e.stderr.decode()}")
            print("    [*] Falling back to basic PyInstaller...")
            return build_with_pyinstaller(source_file)
        except FileNotFoundError:
            print("    [!] PyArmor not installed. Run: pip install pyarmor")
            return build_with_pyinstaller(source_file)

        # Find obfuscated file
        obf_file = Path(tmpdir) / source_file
        if not obf_file.exists():
            obf_file = Path(tmpdir) / "dist" / source_file

        # Step 2: Build with PyInstaller
        print("    [*] Building executable...")
        cmd = [
            "pyinstaller",
            "--onefile",
            "--strip",
            "--name", output_name,
            "--hidden-import", "requests",
            "--hidden-import", "psutil",
            "--hidden-import", "pyinotify",
            "--collect-all", "pyarmor_runtime",
            str(obf_file)
        ]

        subprocess.run(cmd, check=True)

    output_path = Path(OUTPUT_DIR) / output_name
    print(f"[+] Built: {output_path}")
    return str(output_path)


def build_with_cython(source_file: str) -> str:
    """
    Build with Cython compilation

    Cython provides:
    - Compiles Python to C
    - Native machine code
    - Harder to reverse engineer
    """
    print(f"[+] Building {source_file} with Cython...")

    base_name = Path(source_file).stem
    output_name = f"t1-agent-{base_name.replace('t1_', '').replace('_agent', '')}"

    # Create setup.py for Cython
    setup_content = f'''
from setuptools import setup
from Cython.Build import cythonize

setup(
    ext_modules=cythonize(
        "{source_file}",
        compiler_directives={{
            'language_level': "3",
            'embedsignature': False,
        }},
        annotate=False,
    ),
)
'''

    with open("setup_cython.py", "w") as f:
        f.write(setup_content)

    try:
        # Build C extension
        print("    [*] Compiling to C...")
        subprocess.run([sys.executable, "setup_cython.py", "build_ext", "--inplace"], check=True)

        # Create wrapper script
        wrapper = f'''
import sys
sys.path.insert(0, '.')
from {base_name} import main
if __name__ == '__main__':
    main()
'''
        wrapper_file = f"{base_name}_wrapper.py"
        with open(wrapper_file, "w") as f:
            f.write(wrapper)

        # Build with PyInstaller
        print("    [*] Building executable...")
        subprocess.run([
            "pyinstaller",
            "--onefile",
            "--strip",
            "--name", output_name,
            wrapper_file
        ], check=True)

    finally:
        # Cleanup
        for f in Path(".").glob("*.c"):
            f.unlink()
        for f in Path(".").glob("*.so"):
            f.unlink()
        Path("setup_cython.py").unlink(missing_ok=True)
        Path(f"{base_name}_wrapper.py").unlink(missing_ok=True)

    output_path = Path(OUTPUT_DIR) / output_name
    print(f"[+] Built: {output_path}")
    return str(output_path)


def build_with_nuitka(source_file: str) -> str:
    """
    Build with Nuitka

    Nuitka provides:
    - Full Python to C compilation
    - Native machine code
    - Best obfuscation (no Python bytecode)
    - Smallest file size
    """
    print(f"[+] Building {source_file} with Nuitka...")

    base_name = Path(source_file).stem
    output_name = f"t1-agent-{base_name.replace('t1_', '').replace('_agent', '')}"

    cmd = [
        sys.executable, "-m", "nuitka",
        "--standalone",
        "--onefile",
        "--remove-output",
        "--lto=yes",                    # Link-time optimization
        "--disable-console",            # No console window
        f"--output-filename={output_name}",
        "--include-module=requests",
        "--include-module=psutil",
        "--include-module=pyinotify",
        source_file
    ]

    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        print("    [!] Nuitka not installed. Run: pip install nuitka")
        return build_with_pyinstaller(source_file)

    output_path = Path(OUTPUT_DIR) / output_name
    print(f"[+] Built: {output_path}")
    return str(output_path)


def build_with_pyinstaller(source_file: str) -> str:
    """
    Build with PyInstaller only (basic)

    This is the fallback - least obfuscation but most reliable.
    """
    print(f"[+] Building {source_file} with PyInstaller (basic)...")

    base_name = Path(source_file).stem
    output_name = f"t1-agent-{base_name.replace('t1_', '').replace('_agent', '')}"

    cmd = [
        "pyinstaller",
        "--onefile",
        "--strip",
        "--name", output_name,
        "--hidden-import", "requests",
        "--hidden-import", "psutil",
        "--hidden-import", "pyinotify",
        source_file
    ]

    subprocess.run(cmd, check=True)

    output_path = Path(OUTPUT_DIR) / output_name
    print(f"[+] Built: {output_path}")
    return str(output_path)


def create_install_script(agent_binary: str):
    """Create install script for the compiled binary"""

    script = f'''#!/bin/bash
# T1 Agent Installer (Compiled Binary)
set -e

RED='\\033[0;31m'
GREEN='\\033[0;32m'
NC='\\033[0m'

print_success() {{ echo -e "${{GREEN}}[OK] $1${{NC}}"; }}
print_error() {{ echo -e "${{RED}}[ERROR] $1${{NC}}" >&2; }}

# Check root
if [ "$EUID" -ne 0 ]; then
    print_error "Run as root"
    exit 1
fi

SERVER_URL="$1"
if [ -z "$SERVER_URL" ]; then
    echo "Usage: $0 SERVER_URL [MODE]"
    echo "  MODE: full, edr, log-collector (default: full)"
    exit 1
fi

MODE="${{2:-full}}"
INSTALL_DIR="/opt/t1-agent"
SERVICE_NAME="t1-agent"

# Install
mkdir -p "$INSTALL_DIR"
cp {Path(agent_binary).name} "$INSTALL_DIR/t1-agent"
chmod 755 "$INSTALL_DIR/t1-agent"
print_success "Installed to $INSTALL_DIR"

# Create service
cat > /etc/systemd/system/${{SERVICE_NAME}}.service << EOF
[Unit]
Description=T1 Agentics Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/t1-agent --server $SERVER_URL --mode $MODE
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

print_success "Service started"
echo ""
echo "Commands:"
echo "  Status:  systemctl status $SERVICE_NAME"
echo "  Logs:    journalctl -u $SERVICE_NAME -f"
'''

    install_script = Path(OUTPUT_DIR) / "install.sh"
    with open(install_script, "w") as f:
        f.write(script)
    install_script.chmod(0o755)
    print(f"[+] Created: {install_script}")


def main():
    parser = argparse.ArgumentParser(description="Build T1 Agent binaries")
    parser.add_argument("--method", "-m",
                        choices=["pyarmor", "cython", "nuitka", "basic"],
                        default="pyarmor",
                        help="Build method (default: pyarmor)")
    parser.add_argument("--source", "-s",
                        default="t1_unified_agent.py",
                        help="Source file to build")
    parser.add_argument("--clean", "-c", action="store_true",
                        help="Clean build artifacts first")
    parser.add_argument("--all", "-a", action="store_true",
                        help="Build all agent variants")

    args = parser.parse_args()

    if args.clean:
        clean_build()

    # Select build method
    build_func = {
        "pyarmor": build_with_pyarmor,
        "cython": build_with_cython,
        "nuitka": build_with_nuitka,
        "basic": build_with_pyinstaller
    }[args.method]

    # Build
    if args.all:
        for source in AGENT_FILES:
            if Path(source).exists():
                binary = build_func(source)
        create_install_script(binary)
    else:
        if not Path(args.source).exists():
            print(f"[!] Source file not found: {args.source}")
            sys.exit(1)
        binary = build_func(args.source)
        create_install_script(binary)

    print("\n" + "="*50)
    print("Build complete!")
    print(f"Binaries in: {OUTPUT_DIR}/")
    print("="*50)


if __name__ == "__main__":
    main()
