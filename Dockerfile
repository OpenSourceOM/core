# Copyright 2026 OpenSourceOM
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS builder
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

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache ca-certificates
COPY --from=builder /om /usr/local/bin/om
WORKDIR /app
COPY go.mod ./
COPY migrations/ ./migrations/
EXPOSE 8080
ENTRYPOINT ["om"]
CMD ["serve"]
