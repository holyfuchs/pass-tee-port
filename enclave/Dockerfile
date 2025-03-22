FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev openssl-dev pkgconf openssl

ENV OPENSSL_DIR=/usr
ENV OPENSSL_LIB_DIR=/usr/lib
ENV OPENSSL_INCLUDE_DIR=/usr/include

WORKDIR /usr/src/app
COPY . .
RUN cargo build --release
RUN apk add --no-cache gdb

FROM alpine
COPY --from=builder /usr/src/app/target/release/pass-tee-port-enclave /usr/local/bin/pass-tee-port-enclave

EXPOSE 8080
CMD ["pass-tee-port-enclave"]
