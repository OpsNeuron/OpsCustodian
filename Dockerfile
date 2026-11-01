FROM golang:1.26.10-alpine@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS build

WORKDIR /src
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/opscustodian ./cmd/opscustodian

FROM openpolicyagent/opa:1.21.3-static@sha256:bf27411c17e72f3d16063725a74c69f711fb267eb9a4cebdae78028b72adc847 AS opa

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
