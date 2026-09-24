FROM golang:1.25-alpine AS build

WORKDIR /src
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/opscustodian ./cmd/opscustodian

FROM openpolicyagent/opa:1.7.1-static AS opa

FROM alpine:3.21

RUN apk add --no-cache ca-certificates
COPY --from=build /out/opscustodian /usr/local/bin/opscustodian
COPY --from=opa /opa /usr/local/bin/opa
COPY action/entrypoint.sh /usr/local/bin/opscustodian-action
RUN chmod 0755 /usr/local/bin/opscustodian /usr/local/bin/opscustodian-action /usr/local/bin/opa

WORKDIR /github/workspace
ENTRYPOINT ["/usr/local/bin/opscustodian-action"]
