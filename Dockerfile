FROM golang:latest AS builder
ADD . /app/
WORKDIR /app/
RUN CGO_ENABLED=0 make

FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
COPY --from=builder /app/bin/ ./app/
COPY --from=builder /app/configs/ ./app/configs/
RUN mkdir -p /app/results
ENTRYPOINT ["/app/ncml"]
CMD ["-conf", "/app/configs/config.toml"]
 
