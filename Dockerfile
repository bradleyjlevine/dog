FROM rust:bookworm AS build

WORKDIR /build
COPY /src /build/src
COPY /dns /build/dns
COPY /dns-transport /build/dns-transport
COPY /man /build/man
COPY build.rs Cargo.toml /build/

RUN cargo build --release

FROM debian:bookworm

RUN apt update && apt install -y libssl3 ca-certificates && apt clean all

COPY --from=build /build/target/release/dog /dog

ENTRYPOINT ["/dog"]
