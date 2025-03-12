FROM alpine:latest
COPY gophlare /gophlare
ENTRYPOINT ["/gophlare"]