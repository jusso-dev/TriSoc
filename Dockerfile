FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/trisoc ./cmd/trisoc

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/trisoc /usr/local/bin/trisoc
COPY controls /app/controls
COPY config /app/config
USER nonroot:nonroot
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/trisoc"]
CMD ["mcp", "serve", "--transport", "http", "--listen", "0.0.0.0:8787"]
