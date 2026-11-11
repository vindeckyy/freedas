# Sandbox image used by freedas-sandbox-runner (docs: `freedas/sandbox:<version>`).
#
# The runner creates one container/Job per sandbox and runs, inside it:
#   git clone <repo> /workspace && git checkout -b freedas/sandbox-<id>
#   freedas run --auto --format json "<task>"
# so the image needs a shell, git, CA certificates, and the freedas binary.
#
# Build from the repository root:
#   docker build -f docker/sandbox.Dockerfile -t freedas/sandbox:0.1.0 .
FROM rust:1.89-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock CHANGELOG.md LICENSE NOTICE ./
COPY crates ./crates
RUN cargo build --locked --release -p freedas \
    && strip target/release/freedas

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates bash \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1000 --create-home --shell /bin/bash agent \
    && mkdir -p /workspace \
    && chown agent:agent /workspace
COPY --from=build /src/target/release/freedas /usr/local/bin/freedas

# The runner passes `user: "1000"`; HOME must be writable for config/state.
ENV HOME=/home/agent \
    FREEDAS_HOME=/home/agent \
    CI=1 \
    NO_COLOR=1 \
    TERM=dumb
USER 1000
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/freedas"]
CMD ["--version"]
