ARG GO_IMAGE=golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea
FROM ${GO_IMAGE} AS certificates
FROM scratch
COPY allowops-gateway /usr/bin/allowops-gateway
COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY LICENSE /usr/share/licenses/allowops/LICENSE
COPY dist/THIRD_PARTY_NOTICES /usr/share/licenses/allowops/THIRD_PARTY_NOTICES
COPY deploy/docker/CA-NOTICE /usr/share/licenses/allowops/CA-NOTICE
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/usr/bin/allowops-gateway"]
CMD ["serve", "--config", "/etc/allowops/gateway.yaml"]
