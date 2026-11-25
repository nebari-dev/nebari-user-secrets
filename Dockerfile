# Build the user-secrets and user-secrets-init binaries.
# The builder always runs on the build host and cross-compiles for the target
# platform, so multi-arch builds need no QEMU emulation.
# GO_BUILDER_IMAGE comes from ci/pins.env (the Makefile passes it); this default
# is checked against the pin by test/journeys/catalog.
ARG GO_BUILDER_IMAGE=golang:1.26@sha256:6e59e17a20f13c102e49d82dffab66d41cffe6c266b225d82794328aea859ab5
FROM --platform=$BUILDPLATFORM ${GO_BUILDER_IMAGE} AS builder
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
