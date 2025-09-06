#!/usr/bin/env bash
set -euo pipefail

: "${PROJECT_NAME:=carbide}"
: "${SRC:=carbide.c}"
: "${INCLUDE_DIR:=include}"
: "${HEADER:=${INCLUDE_DIR}/Carbide/Recipe.h}"
: "${OUT:=./${PROJECT_NAME}}"
: "${PREFIX:=/usr/local}"
: "${BINDIR:=${PREFIX}/bin}"
: "${INCDIR:=${PREFIX}/include/Carbide}"

usage() {
	cat <<EOF
Usage:
  $(basename "$0")           Build locally into ./$(basename "$OUT")
  $(basename "$0") install   Install binary and header into $PREFIX
  $(basename "$0") uninstall Remove installed binary and header from $PREFIX
EOF
}

if [[ -z "${CC:-}" ]]; then
	if command -v cc >/dev/null 2>&1; then
		CC="cc"
	elif command -v gcc >/dev/null 2>&1; then
		CC="gcc"
	elif command -v clang >/dev/null 2>&1; then
		CC="clang"
	else
		echo "error: no C compiler found" >&2
		exit 1
	fi
fi

OS="$(uname -s)"
: "${CFLAGS:=-O2 -g -fPIC -Wall -Wextra -I${INCLUDE_DIR}}"
: "${LDFLAGS:=}"
: "${EXPORT_FLAGS:=}"

case "$OS" in
	Linux)
		if [[ -z "${_export_flags_set:=}" && "$EXPORT_FLAGS" == "" ]]; then
			EXPORT_FLAGS="-rdynamic"
		fi
		if [[ -z "${_ldflags_set:=}" && "$LDFLAGS" == "" ]]; then
			LDFLAGS="-ldl"
		fi
		;;
	Darwin)
		if [[ -z "${_export_flags_set:=}" && "$EXPORT_FLAGS" == "" ]]; then
			EXPORT_FLAGS="-Wl,-export_dynamic"
		fi
		;;
	*)
		echo "warning: unknown OS '$OS', building with default flags"
		;;
esac

cmd="${1:-build}"

case "$cmd" in
	build|"")
		echo "[*] Building $PROJECT_NAME using $CC on $OS"
		echo "[*] CFLAGS=$CFLAGS"
		echo "[*] LDFLAGS=$LDFLAGS"
		echo "[*] EXPORT_FLAGS=$EXPORT_FLAGS"
		"$CC" -DTOOL_ROOT=$PREFIX $CFLAGS $EXPORT_FLAGS "$SRC" -o "$OUT" $LDFLAGS
		echo "[+] Build complete: $OUT"
		;;
	install)
		echo "[*] Installing to $PREFIX"
		sudo install -d "$BINDIR"
		sudo install -m 0755 "$OUT" "$BINDIR/$PROJECT_NAME"
		sudo install -d "$INCDIR"
		sudo install -m 0644 "$HEADER" "$INCDIR/Recipe.h"
		echo "[+] Installed:"
		echo "    $BINDIR/$PROJECT_NAME"
		echo "    $INCDIR/Recipe.h"
		;;
	uninstall)
		echo "[*] Uninstalling from $PREFIX"
		BIN_PATH="$BINDIR/$PROJECT_NAME"
		HDR_PATH="$INCDIR/Recipe.h"

		if [[ -e "$BIN_PATH" ]]; then
			sudo rm -f "$BIN_PATH"
			echo "[-] Removed $BIN_PATH"
		else
			echo "[i] Skipping: $BIN_PATH not found"
		fi

		if [[ -e "$HDR_PATH" ]]; then
			sudo rm -f "$HDR_PATH"
			echo "[-] Removed $HDR_PATH"
		else
			echo "[i] Skipping: $HDR_PATH not found"
		fi

		if [[ -d "$INCDIR" ]] && [[ -z "$(ls -A "$INCDIR")" ]]; then
			sudo rmdir "$INCDIR" && echo "[-] Removed empty dir $INCDIR" || true
		fi
		if [[ -d "$BINDIR" ]] && [[ -z "$(ls -A "$BINDIR")" ]]; then
			sudo rmdir "$BINDIR" && echo "[-] Removed empty dir $BINDIR" || true
		fi

		echo "[+] Uninstall complete."
		;;
	-h|--help|help)
		usage
		;;
	*)
		echo "error: unknown command '$cmd'"
		usage
		exit 1
		;;
esac
