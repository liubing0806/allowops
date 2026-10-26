# Throwaway agent host for the StarRocks/Dremio end-to-end run. The context is
# assembled by e2e_test.go; the container uses the host network so the agent
# reaches the gateway and the databases on 127.0.0.1.
FROM debian:12
RUN apt-get update && apt-get install -y --no-install-recommends sudo \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --user-group --home-dir /var/lib/allowops --shell /usr/sbin/nologin allowops \
    && install -d -m 0700 -o allowops -g allowops /var/lib/allowops \
    && install -d -m 0700 /var/lib/allowops-exec \
    && install -d -m 0755 /etc/allowops/catalog-keys /etc/allowops/credentials /usr/libexec/allowops
COPY allowops-agent /usr/bin/allowops-agent
COPY allowops-exec /usr/libexec/allowops/allowops-exec
COPY allowops.sudoers /etc/sudoers.d/allowops
COPY catalog.pub.pem /etc/allowops/catalog-keys/catalog.pub.pem
COPY agent.yaml /etc/allowops/agent.yaml
COPY join.token /run/join.token
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /usr/bin/allowops-agent /usr/libexec/allowops/allowops-exec /entrypoint.sh \
    && chmod 0440 /etc/sudoers.d/allowops && visudo -cf /etc/sudoers.d/allowops \
    && chmod 0644 /etc/allowops/agent.yaml /etc/allowops/catalog-keys/catalog.pub.pem && chmod 0600 /run/join.token
ENTRYPOINT ["/entrypoint.sh"]
