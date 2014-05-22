from base64 import b64encode
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
    first = gen_bytearray()
    second = gen_bytearray(start=5, size=4)

    packets = [
        {'type': 'message', 'data': first},
        {'type': 'message', 'data': second}
    ]

    actual = encode_binary_payload(packets, lambda encoded: encoded)
    print 'actual  :', repr(actual)

    # Validate encoded data
    expected = bytearray().join([
        # {'type': 'message', 'data': gen_bytearray()}
        # ----------------------------------------------------
        '\x01'                  # true-binary
        '\x06',                 # length = 6
        '\xff',                 # separator
        '\x04',                 # type = binary message
        first,                  # data (in binary)

        # {'type': 'message', 'data': gen_bytearray(start=5, size=4)}
        # ----------------------------------------------------
        '\x01'                  # true-binary
        '\x05',                 # length = 5
        '\xff',                 # separator
        '\x04',                 # type = binary message
        second                  # data (in binary)
    ])
    print 'expected:', repr(expected)

    assert actual == expected

    # Decode into packets again
    decoded_packets = []

    def decode_callback(packet, index, total):
        decoded_packets.append(packet)

    decode_binary_payload(actual, decode_callback)

    # Ensure decoded packets match original
    assert decoded_packets == packets


def test_payload_binary_string():
    first = gen_bytearray(123)

    packets = [
        {'type': 'message', 'data': first},
        {'type': 'message', 'data': 'hello'},
        {'type': 'close'}
    ]

    actual = encode_binary_payload(packets, lambda encoded: encoded)
    print 'actual  :', repr(actual)

    # Validate encoded data
    expected = bytearray().join([
        # {'type': 'message', 'data': gen_bytearray(123)}
        # ----------------------------------------------------
        '\x01'                  # true-binary
        '\x01\x02\x04',         # length = 124 bytes
        '\xff',                 # separator
        '\x04',                 # type = binary message
        first,                  # data (in binary)

        # {'type': 'message', 'data': 'hello'}
        # ----------------------------------------------------
        '\x00'                  # not true-binary
        '\x06',                 # length = 6 bytes
        '\xff',                 # separator
        '4',                    # type = message
        'hello',                # data

        # {'type': 'close'}
        # ----------------------------------------------------
        '\x00'                  # not true-binary
        '\x01',                 # length = 1 byte
        '\xff',                 # separator
        '1',                    # type = close
    ])
    print 'expected:', repr(expected)

    assert expected == actual

    # Decode into packets again
    decoded_packets = []

    def decode_callback(packet, index, total):
        decoded_packets.append(packet)

    decode_binary_payload(actual, decode_callback)

    # Ensure decoded packets match original
    assert decoded_packets == packets


def test_blank_data():
    # String encoding
    encoded = encode_payload([{'type': 'ping', 'data': None}], lambda encoded: encoded, False)
    assert encoded == '1:2'

    assert encoded == encode_payload([{'type': 'ping'}], lambda encoded: encoded, False)

    # Binary encoding
    encoded = encode_payload([{'type': 'ping', 'data': None}], lambda encoded: encoded, True)
    assert encoded == '\x00\x01\xff\x32'

    assert encoded == encode_payload([{'type': 'ping'}], lambda encoded: encoded, True)
