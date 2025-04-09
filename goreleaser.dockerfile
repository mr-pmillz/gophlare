FROM ghcr.io/mr-pmillz/alpine-bash-tini:latest

COPY gophlare /usr/local/bin/gophlare
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/gophlare

ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]