# Small attacker box with the tools used by attack.sh.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl nmap openssh-client sshpass ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY attack.sh /usr/local/bin/attack.sh
RUN chmod +x /usr/local/bin/attack.sh
CMD ["attack.sh"]
