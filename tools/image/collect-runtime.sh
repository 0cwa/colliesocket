#!/bin/sh
# Collect reviewed non-glibc files from the target-architecture pinned builder.
# The pinned Debian runtime retains its own complete libc/loader/NSS family.
set -eu
binary=$1
destination=$2
install -d "$destination/usr/local/bin" "$destination/usr/share/colliesocket" "$destination/usr/local/lib/colliesocket"
install -m 0755 "$binary" "$destination/usr/local/bin/mollysocket"
link_report=$(mktemp)
trap 'rm -f "$link_report"' EXIT HUP INT TERM
ldd "$binary" > "$link_report"
if grep -q 'not found' "$link_report"; then
    echo 'Missing runtime library' >&2
    exit 1
fi
awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}' "$link_report" |
    sort -u |
    while IFS= read -r library; do
        soname=$(basename "$library")
        case "$soname" in
            ld-linux*.so.*|libc.so.6|libm.so.6|libpthread.so.0|libdl.so.2|librt.so.1|libutil.so.1|libresolv.so.2|libanl.so.1|libnss_*.so.2|libBrokenLocale.so.1|libnsl.so.1)
                continue ;;
            libssl.so.3|libcrypto.so.3|libgcc_s.so.1|libstdc++.so.6|libz.so.1) ;;
            *) echo 'Unreviewed non-glibc runtime dependency' >&2; exit 1 ;;
        esac
        real_library=$(readlink -f "$library")
        case "$real_library" in
            /usr/lib/*|/lib/*|/lib64/*) ;;
            *) echo 'Unexpected runtime library path' >&2; exit 1 ;;
        esac
        install -m 0755 "$real_library" "$destination/usr/local/lib/colliesocket/$soname"
        digest=$(sha256sum "$real_library" | cut -d ' ' -f 1)
        printf '%s  /usr/local/lib/colliesocket/%s\n' "$digest" "$soname"
    done > "$destination/usr/share/colliesocket/runtime-libraries.sha256"
test -s "$destination/usr/share/colliesocket/runtime-libraries.sha256"
install -D -m 0644 /etc/ssl/certs/ca-certificates.crt "$destination/etc/ssl/certs/ca-certificates.crt"
install -D -m 0644 /etc/ssl/openssl.cnf "$destination/etc/ssl/openssl.cnf"
