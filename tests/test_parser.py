import binascii
from pyengineio_parser import encode_packet, decode_packet, encode_payload, decode_payload, encode_binary_payload, \
    decode_binary_payload


def gen_string(size=5, start=0):
    return ''.join([chr(x) for x in range(start, start + size)])


def gen_bytearray(size=5, start=0):
    return bytearray(gen_string(size, start))


def test_message_string():
    packet = {'type': 'message', 'data': gen_string()}

    encoded = encode_packet(packet, lambda encoded: encoded)
    assert encoded == "4\x00\x01\x02\x03\x04"  # test against node result

    decoded = decode_packet(encoded)

    print 'decoded:', decoded
    assert decoded == packet


def test_message_bytearray():
    packet = {'type': 'message', 'data': gen_bytearray()}

    encoded = encode_packet(packet, lambda encoded: encoded)
    assert encoded == "b4AAECAwQ="  # test against node result

    decoded = decode_packet(encoded)

    print 'decoded:', decoded
    assert decoded == packet


def test_payload_string_bytearray():
    packets = [
        {'type': 'message', 'data': gen_bytearray()},
        {'type': 'message', 'data': 'hello'}
    ]

    encoded = encode_payload(packets, lambda encoded: encoded)
    assert encoded == "10:b4AAECAwQ=6:4hello"  # test against node result

    decoded_packets = []

    def decode_callback(packet, index, total):
        decoded_packets.append(packet)

    decode_payload(encoded, decode_callback)

    print 'decoded_packets:', decoded_packets
    assert decoded_packets == packets


def test_payload_binary():
    packets = [
        {'type': 'message', 'data': gen_bytearray()},
        {'type': 'message', 'data': gen_bytearray(start=5, size=4)}
    ]

    encoded = encode_binary_payload(packets, lambda encoded: encoded)
    assert encoded == '\x00\x01\x00\xffb4AAECAwQ=\x00\x01\x00\xffb4BQYHCA=='

    decoded_packets = []

    def decode_callback(packet, index, total):
        decoded_packets.append(packet)

    decode_binary_payload(encoded, decode_callback)

    print 'decoded_packets:', decoded_packets
    assert decoded_packets == packets

    assert False
