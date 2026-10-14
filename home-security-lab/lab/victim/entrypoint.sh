#!/bin/sh
set -e
# Log files live on a shared volume that the shipper reads.
mkdir -p /var/log/nginx
touch /var/log/auth.log /var/log/nginx/access.log
chmod 644 /var/log/auth.log /var/log/nginx/access.log
# Ubuntu's rsyslog drops privileges to the syslog user, so it must own auth.log.
chown syslog:adm /var/log/auth.log
rm -f /run/rsyslogd.pid
rsyslogd
nginx
# No -e: sshd must log to syslog (auth.log), not to the container output.
exec /usr/sbin/sshd -D
