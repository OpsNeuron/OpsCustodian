FROM golang:1.25.13-alpine@sha256:1e0126852075c9c60731c8ba49088448b91f63e2aed97ca9d1a9791622a05946 AS build

WORKDIR /src
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/opscustodian ./cmd/opscustodian

FROM openpolicyagent/opa:1.21.2-static@sha256:0843d2adce51655422e8b95a803629ab9f424803c4bd27876e7f44cce9a2b84d AS opa

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS certificates

RUN apk add --no-cache ca-certificates

FROM busybox:1.37.0-musl@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092

COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/opscustodian /usr/local/bin/opscustodian
COPY --from=opa /opa /usr/local/bin/opa
COPY action/entrypoint.sh /usr/local/bin/opscustodian-action
RUN chmod 0755 /usr/local/bin/opscustodian /usr/local/bin/opscustodian-action /usr/local/bin/opa

WORKDIR /github/workspace
ENTRYPOINT ["/usr/local/bin/opscustodian-action"]
