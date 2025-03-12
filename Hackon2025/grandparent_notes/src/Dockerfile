FROM ubuntu:24.04@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y xinetd qemu-system

COPY run.sh /run.sh
RUN chmod +x /run.sh
COPY bzImage /bzImage
COPY rootfs.cpio.gz /rootfs.cpio.gz
COPY ctf.xinetd /etc/xinetd.d/ctf

CMD ["/usr/sbin/xinetd", "-dontfork"]
EXPOSE 6969
