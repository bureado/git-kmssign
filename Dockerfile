# syntax=docker/dockerfile:1

# ---- Build stage (minimal Wolfi Go toolchain) ----
# The Linux/KMS path has no cgo dependencies, so we build a fully static
# binary. The -dev variant is used only for the builder because it provides a
# shell for RUN steps; it never ships in the final image.
FROM cgr.dev/chainguard/go:latest-dev AS build

WORKDIR /work

# Cache module downloads separately from the source for faster rebuilds.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source.
COPY . .

# Version string injected into the binary (defaults to a dev marker; override
# with --build-arg VERSION=$(git describe --tags --always)).
ARG VERSION=dev

# Static, stripped Linux binary. No cgo -> no libc dependency in the runtime.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath \
    -ldflags "-s -w -X main.versionString=${VERSION}" \
    -o /out/git-kmssign .

# ---- Runtime stage (distroless Wolfi) ----
# chainguard/static is a scratch-like image that still ships CA certificates,
# which the Azure SDK needs to validate TLS to *.vault.azure.net. It runs as a
# non-root user by default.
FROM cgr.dev/chainguard/static:latest

COPY --from=build /out/git-kmssign /usr/bin/git-kmssign

ENTRYPOINT ["/usr/bin/git-kmssign"]
