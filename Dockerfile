FROM rust:1.88-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM gcr.io/distroless/cc-debian12:nonroot
ARG SOURCE_SHA=unknown
ARG SOURCE_URL=https://example.invalid/daemonloom/identity
LABEL org.opencontainers.image.revision=$SOURCE_SHA \
      org.opencontainers.image.source=$SOURCE_URL
COPY --from=builder /src/target/release/daemonloom-identity /usr/local/bin/daemonloom-identity
VOLUME ["/var/lib/daemonloom-identity"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/daemonloom-identity"]
