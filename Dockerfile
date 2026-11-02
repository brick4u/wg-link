# syntax=docker/dockerfile:1
ARG BUILDPLATFORM
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine3.24 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY cmd/ ./cmd/
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/wg-link ./cmd/wg-link

FROM alpine:3.24.3
RUN apk add --no-cache ca-certificates iproute2 wireguard-tools nftables
COPY --from=build /out/wg-link /usr/local/bin/wg-link
LABEL org.opencontainers.image.title="wg-link" \
      org.opencontainers.image.description="Pod-local WireGuard networking with Kubernetes endpoint discovery" \
      org.opencontainers.image.source="https://github.com/brick4u/wg-link"
ENTRYPOINT ["/usr/local/bin/wg-link"]
