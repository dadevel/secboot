#!/bin/sh
PS4='> '
set -eux

PREFIX="${PREFIX:-/usr/local}"

cd "$(dirname "$0")"
install -m 0755 -D ./secboot.py "$PREFIX/bin/secboot"
case "$(. /usr/lib/os-release && echo "${ID_LIKE:-$ID}")" in
    arch)
        mkdir -p /etc/pacman.d/hooks/
        cp ./pacman/*.hook /etc/pacman.d/hooks/
        ;;
    debian)
        mkdir -p /etc/kernel/postinst.d/ /etc/kernel/postrm.d/
        # replace dracut hooks with nops
        for path in /etc/kernel/postinst.d/dracut /etc/kernel/postrm.d/dracut; do
            rm -f "${path}"
            touch "${path}"
            chmod 0755 "${path}"
        done
        ln -sf "$PREFIX/bin/secboot" /etc/kernel/postinst.d/secboot
        ln -sf "$PREFIX/bin/secboot" /etc/kernel/postrm.d/secboot
        ;;
esac
mkdir -p /etc/secboot/
[ -f /etc/secboot/config.json ] || echo '{}' > /etc/secboot/config.json
