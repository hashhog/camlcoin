# ---------- build ----------
FROM ocaml/opam:debian-12-ocaml-5.1 AS build

RUN sudo apt-get update && sudo apt-get install -y --no-install-recommends \
        pkg-config libgmp-dev libssl-dev libev-dev libffi-dev \
        librocksdb-dev libsecp256k1-dev libsodium-dev \
    && sudo rm -rf /var/lib/apt/lists/*

WORKDIR /home/opam/src
COPY --chown=opam:opam . .
RUN opam install . --deps-only -y && \
    eval $(opam env) && \
    dune build --force @install

# ---------- runtime ----------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libgmp10 libssl3 libev4 libffi8 \
        librocksdb7.8 libsecp256k1-1 libsodium23 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /home/opam/src/_build/default/bin/main.exe /usr/local/bin/camlcoin

VOLUME /data
EXPOSE 48347 48337

ENTRYPOINT ["camlcoin"]
CMD ["--datadir=/data", "--network=testnet4"]
