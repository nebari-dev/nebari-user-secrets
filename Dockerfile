# Build the user-secrets and user-secrets-init binaries.
# The builder always runs on the build host and cross-compiles for the target
# platform, so multi-arch builds need no QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.26 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

# Copy the Go source (relies on .dockerignore to filter).
COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -o /out/user-secrets ./cmd/user-secrets && \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -o /out/user-secrets-init ./cmd/user-secrets-init

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /out/user-secrets /user-secrets
COPY --from=builder /out/user-secrets-init /user-secrets-init
USER 65532:65532

ENTRYPOINT ["/user-secrets"]
