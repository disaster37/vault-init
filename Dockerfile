FROM golang:1.10.3 AS builder
WORKDIR /go/src/github.com/disaster37/vault-init
ADD . .
RUN \
  CGO_ENABLED=0 \
  GOOS=linux \
  GOARCH=amd64 \
  go build -a -installsuffix cgo -o vault-init .

FROM alpine
ENV VAULT_URL="https://120.0.0.1:8200" \
    CHECK_INTERVAL="5" \
    BACKEND="file-store" \
    BACKEND_OTIONS="--help"
COPY --from=builder /go/src/github.com/disaster37/vault-init/vault-init /
RUN apk add --update curl bash ca-certificates &&\
    rm -rf /var/cache/apk/*
CMD ["/vault-init --vault-url ${VAULT_URL} --check-interval ${CHECK_INTERVAL} ${BACKEND} ${BACKEND_OPTIONS}"]
