FROM golang:1.25-alpine AS build

WORKDIR /src
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/opscustodian ./cmd/opscustodian

FROM alpine:3.21

RUN apk add --no-cache ca-certificates
COPY --from=build /out/opscustodian /usr/local/bin/opscustodian
COPY action/entrypoint.sh /usr/local/bin/opscustodian-action
RUN chmod 0755 /usr/local/bin/opscustodian /usr/local/bin/opscustodian-action

WORKDIR /github/workspace
ENTRYPOINT ["/usr/local/bin/opscustodian-action"]
