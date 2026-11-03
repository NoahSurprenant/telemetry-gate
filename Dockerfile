# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /telemetry-gate .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /telemetry-gate /telemetry-gate
# Numeric, so Kubernetes can check runAsNonRoot against it.
USER 65532:65532
ENTRYPOINT ["/telemetry-gate"]
