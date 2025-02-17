FROM alpine:3.21.2 AS final
RUN apk add --no-cache tcpdump iproute2
# running simple tcp echo server
CMD [ "nc", "-l", "-p", "8080", "-e", "/bin/cat" ]

