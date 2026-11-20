#!/bin/sh
set -eu
umask 077
if [ ! -s /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key
fi
/usr/sbin/sshd -t
exec /usr/sbin/sshd -D -e
