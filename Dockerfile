# Copyright 2026 OpenSourceOM
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=
ARG COMMIT=
ARG DATE=
# Empty VERSION, COMMIT, and DATE fall through to the VCS metadata Go stamps.
# safe.directory lets that work when the build context is owned by another user.
# Release workflows pass all three.
RUN git config --global --add safe.directory /src \
    && CGO_ENABLED=0 go build -trimpath \
        -ldflags "-s -w -X github.com/OpenSourceOM/core/internal/version.version=${VERSION} -X github.com/OpenSourceOM/core/internal/version.commit=${COMMIT} -X github.com/OpenSourceOM/core/internal/version.date=${DATE}" \
        -o /om ./cmd/om

FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN apk add --no-cache ca-certificates
COPY --from=builder /om /usr/local/bin/om
WORKDIR /app
COPY go.mod ./
COPY migrations/ ./migrations/
EXPOSE 8080
ENTRYPOINT ["om"]
CMD ["serve"]
