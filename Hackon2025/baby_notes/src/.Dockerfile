#if you have problems running docker compose in your system run:
#sudo sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=0
#sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
FROM ubuntu:24.04@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782 AS base

WORKDIR /app
COPY chall run
COPY ld-linux-x86-64.so.2 .
COPY libc.so.6 .

#ARG FLAG
#RUN echo "${FLAG}" > flag.txt
COPY flag.txt .
RUN chmod 644 flag.txt
RUN mv flag.txt flag-$(md5sum flag.txt | awk '{print $1}').txt

FROM pwn.red/jail
COPY --from=base / /srv
EXPOSE 5000
CMD ["/srv/app/run"]
