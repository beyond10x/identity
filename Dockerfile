# syntax=docker/dockerfile:1.7
FROM rust:1.88-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,id=daemonloom-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=daemonloom-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=daemonloom-identity-target,target=/src/target,sharing=locked \
    cargo build --locked --release && \
    install -D /src/target/release/daemonloom-identity /out/daemonloom-identity

FROM gcr.io/distroless/cc-debian12:nonroot
ARG SOURCE_SHA=unknown
LABEL org.opencontainers.image.revision=$SOURCE_SHA
COPY --from=builder /out/daemonloom-identity /usr/local/bin/daemonloom-identity
VOLUME ["/var/lib/daemonloom-identity"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/daemonloom-identity"]
