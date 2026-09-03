# syntax=docker/dockerfile:1.7
FROM rust:1.88-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./
COPY crates ./crates
COPY src ./src
RUN --mount=type=cache,id=b10x-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=b10x-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=identity-target,target=/src/target,sharing=locked \
    find Cargo.toml Cargo.lock build.rs crates src -type f -exec touch {} + && \
    cargo build --locked --release --package identity && \
    install -D /src/target/release/identity /out/identity

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:adcd20c7b4c988b73cbfbddb26d2eee574571e6d7c9ffea29b3821e0690efb77
ARG SOURCE_SHA=unknown
LABEL org.opencontainers.image.revision=$SOURCE_SHA \
      org.opencontainers.image.source="https://github.com/beyond10x/identity"
COPY --from=builder /out/identity /usr/local/bin/identity
VOLUME ["/var/lib/identity"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/identity"]
