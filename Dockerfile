# Built by release.yml from the static musl binary — image ≈ binary size.
# Local build: put a x86_64-unknown-linux-musl `b2p` binary at ./b2p first.
FROM scratch
COPY b2p /b2p
EXPOSE 9009
ENTRYPOINT ["/b2p", "relay", "serve"]
