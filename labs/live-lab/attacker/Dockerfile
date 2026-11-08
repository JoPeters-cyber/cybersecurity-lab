FROM debian:bookworm-slim

# Offensive tooling for the guided exercises. kept intentionally small.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        nmap \
        hydra \
        sqlmap \
        ca-certificates \
        iputils-ping \
        less \
        vim-tiny \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/attacker
# a small wordlist for the brute-force exercise
RUN printf 'admin\npassword\nletmein\n123456\nqwerty\nabc123\npassword\ndragon\n' > passwords.txt \
    && printf 'admin\nuser\ntest\nguest\n' > users.txt

CMD ["sleep", "infinity"]
