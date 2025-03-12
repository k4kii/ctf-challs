#if you have problems running docker compose in your system run:
#sudo sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=0
#sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
FROM ubuntu:24.04@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782

RUN apt update && apt full-upgrade -y && apt install xinetd build-essential -y && apt install libseccomp-dev -y

COPY ./ctf.xinetd /etc/xinetd.d/ctf
COPY ./entrypoint.sh /start.sh
RUN echo "Blocked by ctf_xinetd" > /etc/banner_fail

RUN chmod +x /start.sh

COPY ./chall /chall
COPY ld-linux-x86-64.so.2 /ld-linux-x86-64.so.2
COPY libc.so.6 /libc.so.6

RUN chmod +x /chall

COPY ./flag.txt /flag.txt
RUN chmod 644 flag.txt
RUN mv flag.txt flag-$(md5sum flag.txt | awk '{print $1}').txt

CMD ["/start.sh"]

EXPOSE 9999
