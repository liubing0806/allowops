FROM debian:12
RUN apt-get update && apt-get install -y --no-install-recommends sudo passwd \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --user-group --home-dir /var/lib/allowops --shell /usr/sbin/nologin allowops \
    && install -d -m 0700 -o allowops -g allowops /var/lib/allowops \
    && install -d -m 0700 /var/lib/allowops-exec \
    && install -d -m 0755 /etc/allowops/catalog-keys /usr/libexec/allowops
COPY allowops-exec /usr/libexec/allowops/allowops-exec
COPY fixture /usr/local/bin/allowops-test-fixture
COPY root-tests /tests/root-tests
COPY agent-tests /tests/agent-tests
COPY allowops.sudoers /etc/sudoers.d/allowops
RUN chmod 0755 /usr/libexec/allowops/allowops-exec /usr/local/bin/allowops-test-fixture /tests/root-tests /tests/agent-tests \
    && chmod 0440 /etc/sudoers.d/allowops && visudo -cf /etc/sudoers.d/allowops
ENV ALLOWOPS_CONTAINER_TEST=1
COPY run.sh /tests/run.sh
CMD ["/bin/bash", "/tests/run.sh"]
