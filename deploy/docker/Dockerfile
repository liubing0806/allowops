ARG GO_IMAGE=golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61
FROM ${GO_IMAGE} AS source
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY gen ./gen
COPY deploy/packaging/notices.sh ./deploy/packaging/notices.sh
COPY LICENSE ./LICENSE
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1

FROM source AS gateway-build
ARG VERSION=0.1.0
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/allowops-gateway ./cmd/allowops-gateway \
    && sh deploy/packaging/notices.sh

# No shell or distribution packages are shipped in the gateway image.
FROM scratch AS gateway
COPY --from=gateway-build /out/allowops-gateway /usr/bin/allowops-gateway
COPY --from=gateway-build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=gateway-build /src/LICENSE /usr/share/licenses/allowops/LICENSE
COPY --from=gateway-build /src/dist/THIRD_PARTY_NOTICES /usr/share/licenses/allowops/THIRD_PARTY_NOTICES
COPY deploy/docker/CA-NOTICE /usr/share/licenses/allowops/CA-NOTICE
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/usr/bin/allowops-gateway"]
CMD ["serve", "--config", "/etc/allowops/gateway.yaml"]
