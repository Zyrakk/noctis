FROM golang:1.25-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION}" -o /noctis ./cmd/noctis

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /noctis /noctis
COPY migrations/ /migrations/
COPY prompts/ /prompts/
USER nonroot:nonroot
ENTRYPOINT ["/noctis"]
CMD ["serve", "--config", "/etc/noctis/config.yaml"]
