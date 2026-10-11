FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build

WORKDIR /src
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/opscustodian ./cmd/opscustodian

FROM openpolicyagent/opa:1.21.0-static@sha256:9eb36ac3ceb3b855e776e60926a8a5142f96109a219a5fcd490fa1744c755bec AS opa

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
