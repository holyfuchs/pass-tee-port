FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev openssl-dev pkgconf
RUN apk add --no-cache openssl-libs-static

WORKDIR /usr/src/app
COPY . .
RUN cargo build --release
RUN apk add --no-cache gdb

FROM alpine
COPY --from=builder /usr/src/app/target/release/pass-tee-port-enclave /usr/local/bin/pass-tee-port-enclave
COPY masterList.pem /masterList.pem


EXPOSE 8080
CMD ["pass-tee-port-enclave"]
