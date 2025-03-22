FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev openssl-dev pkgconf openssl

ENV OPENSSL_DIR=/usr
ENV OPENSSL_LIB_DIR=/usr/lib
ENV OPENSSL_INCLUDE_DIR=/usr/include

WORKDIR /usr/src/app
COPY . .
RUN cargo build --release

FROM alpine
COPY --from=builder /usr/src/app/target/release/passproof-server /usr/local/bin/passproof-server

EXPOSE 8080
CMD ["passproof-server"]
