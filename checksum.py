import struct

def checksum(data):
    """Calculate the checksum of the given data."""
    sum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + (data[i+1] if i+1 < len(data) else 0)
        sum += word
        sum = (sum & 0xFFFF) + (sum >> 16)  # Keep the sum to 16 bits
    return ~sum & 0xFFFF  # One's complement of the sum

# Example input from the debug log (ICMPv6 packet data)
input_data = bytes.fromhex("20010db8000000050000000000000005ff020000000000000000000000000001000000200000003a870000000000000020010db800000005000000000000000201010242ac1e0009")

# Assuming this is the complete packet with IPv6 header + ICMPv6 message
# Calculate checksum over the provided data (excluding the checksum part)
calculated_checksum = checksum(input_data)

# Compare calculated checksum with the provided checksum (6eb3)
expected_checksum = 0x6eb3

print(f"Calculated checksum: {calculated_checksum:#04x}")
print(f"Expected checksum: {expected_checksum:#04x}")
print("Checksum is correct!" if calculated_checksum == expected_checksum else "Checksum is incorrect.")
