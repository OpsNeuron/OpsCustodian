FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build

WORKDIR /src
COPY go.mod go.sum ./
COPY integration/loadprobe ./integration/loadprobe
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/opscustodian-loadprobe ./integration/loadprobe

FROM busybox:1.37.0-musl@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092

COPY --from=build /out/opscustodian-loadprobe /usr/local/bin/opscustodian-loadprobe
ENTRYPOINT ["/usr/local/bin/opscustodian-loadprobe"]
