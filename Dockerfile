FROM --platform=$BUILDPLATFORM node:22-alpine AS frontend
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /src/internal/webassets/static ./internal/webassets/static
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-X main.version=${VERSION}" -o /noctis ./cmd/noctis

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /noctis /noctis
COPY migrations/ /migrations/
COPY prompts/ /prompts/
USER nonroot:nonroot
ENTRYPOINT ["/noctis"]
CMD ["v2", "--database-secret-file", "/run/secrets/database", "serve", "--mode", "api", "--listen", "0.0.0.0:8081", "--admin-secret-file", "/run/secrets/admin", "--origin", "https://noctis.invalid", "--tls-cert-file", "/run/secrets/tls.crt", "--tls-key-file", "/run/secrets/tls.key"]
