# Deliberately weak Ubuntu server: password SSH login, nginx, sudo.
# Only reachable inside the lab network. Never expose it to the internet.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server nginx rsyslog sudo passwd \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 # rsyslog cannot read the kernel log inside a container
 && sed -i '/imklog/s/^/#/' /etc/rsyslog.conf \
 # IPv4 only: Docker networks often have IPv6 disabled
 && sed -i '/listen \[::\]/d' /etc/nginx/sites-available/default \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
 && useradd --create-home --shell /bin/bash --groups sudo labuser \
 && echo 'labuser:labpassword' | chpasswd
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 22 80
ENTRYPOINT ["/entrypoint.sh"]
