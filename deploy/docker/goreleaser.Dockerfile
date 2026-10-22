ARG GO_IMAGE=golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5
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
