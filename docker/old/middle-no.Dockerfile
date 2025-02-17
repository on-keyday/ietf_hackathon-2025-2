# Use a lightweight base image
FROM alpine:3.21.2 AS final

# Install necessary packages for a lightweight router
RUN apk update && apk add --no-cache \
    iproute2 \
    iptables \
    quagga \
    ip6tables \
    --verbose

# Copy configuration files (if any)
# COPY ./config /etc/quagga/


# Start services (replace with actual start commands)
CMD ["sh", "-c", "sysctl -w net.ipv4.ip_forward=1 && /usr/sbin/zebra -d && /usr/sbin/ospfd -d && /usr/sbin/bgpd -d"]
