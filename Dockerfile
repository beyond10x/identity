# syntax=docker/dockerfile:1.7
FROM rust:1.88-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,id=daemonloom-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=daemonloom-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=daemonloom-identity-target,target=/src/target,sharing=locked \
    find Cargo.toml Cargo.lock src -type f -exec touch {} + && \
    cargo build --locked --release && \
    install -D /src/target/release/daemonloom-identity /out/daemonloom-identity

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:adcd20c7b4c988b73cbfbddb26d2eee574571e6d7c9ffea29b3821e0690efb77
ARG SOURCE_SHA=unknown
LABEL org.opencontainers.image.revision=$SOURCE_SHA
COPY --from=builder /out/daemonloom-identity /usr/local/bin/daemonloom-identity
VOLUME ["/var/lib/daemonloom-identity"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/daemonloom-identity"]
