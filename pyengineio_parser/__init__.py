from pyengineio_parser.util import try_convert, byte_length
from base64 import b64encode, b64decode

# Current protocol version
PROTOCOL = 3

# Packet types (name: code)
PACKETS = {
    'open':     0,    # non-ws
    'close':    1,    # non-ws
    'ping':     2,
    'pong':     3,
    'message':  4,
    'upgrade':  5,
    'noop':     6
}

# Packet type map (code: name)
PACKET_MAP = dict([(v, k) for k, v in PACKETS.items()])

# Pre-made error packet
ERR = {'type': 'error', 'data': 'parser error'}


def encode_packet(packet, callback, supports_binary=False):
    """Encodes a packet."""
    data = packet.get('data')

    if packet.get('type') not in PACKETS:
        raise ValueError('Packet type provided is invalid or unknown')

    if type(data) is bytearray:
        return encode_bytearray_packet(packet, callback, supports_binary)

    # Sending data as a utf-8 string
    encoded = str(PACKETS[packet['type']])

    # data fragment is optional
    if data:
        encoded += str(data)

    return callback(encoded)


def encode_bytearray_packet(packet, callback, supports_binary=False):
    """Encode Buffer data"""
    data = packet['data']

    if not supports_binary:
        return encode_base64_packet(packet, callback)

    result = bytearray([PACKETS[packet['type']]])
    result.extend(packet['data'])

    return callback(result)


def encode_base64_packet(packet, callback):
    """Encodes a packet with binary data in a base64 string

    :param packet: packet, has `type` and `data`
    :type packet: dict

    :rtype: str
    """
    data = packet['data']

    message = 'b' + str(PACKETS[packet['type']])
    message += b64encode(data)

    return callback(message)


def decode_packet(data, binary_type=None):
    """Decodes a packet. Data also available as an ArrayBuffer if requested.

    :return: packet, has `type` and `data`
    :rtype: dict
    """
    if not data:
        return ERR

    # String decoding
    if isinstance(data, basestring):
        packet_type = data[0]

        if packet_type == 'b':
            return decode_base64_packet(data[1:], binary_type)

        packet_type = try_convert(packet_type, int)

        if packet_type is None or packet_type not in PACKET_MAP:
            return ERR

        data = data[1:]

        if data:
            return {'type': PACKET_MAP[packet_type], 'data': data}

        return {'type': PACKET_MAP[packet_type]}

    # Byte Array decoding
    if type(data) is bytearray:
        packet_type = data[0]

        return {'type': PACKET_MAP[packet_type], 'data': data[1:]}

    raise ValueError('Parameter "data" has an unknown type, expecting str or bytearray')


def decode_base64_packet(msg, binary_type):
    """Decodes a packet encoded in a base64 string.

    :param msg: base64 encoded message
    :type msg: str

    :return: packet, has `type` and `data`
    :rtype: dict
    """
    packet_type = PACKET_MAP.get(try_convert(msg[0], int))
    data = bytearray(b64decode(msg[1:]), 'base64')

    return {'type': packet_type, 'data': data}


def encode_payload(packets, callback, supports_binary=False):
    """Encodes multiple messages (payload).

    :param packets: list
    """
    if supports_binary:
        return encode_binary_payload(packets, callback)

    if not packets:
        return callback('0:')

    def set_length_header(message):
        return '%s:%s' % (len(message), message)

    def encode_one(packet):
        def encode_callback(message):
            return set_length_header(message)

        return encode_packet(packet, encode_callback, supports_binary)

    return callback(''.join(map(encode_one, packets)))


def decode_payload(data, callback, binary_type=None):
    """Decodes data when a payload is maybe expected. Possible binary contents are
       decoded from their base64 representation

    :param data: encoded payload
    :type data: str

    :param callback: callback method
    :type callback: function
    """
    if data and not isinstance(data, basestring):
        return decode_binary_payload(data, callback, binary_type)

    if not data:
        # parser error - ignoring payload
        return callback(ERR, 0, 1)

    length = ''
    x = 0

    while x < len(data):
        char = data[x]

        # Read length until ':' character is found
        if char != ':':
            length += char
            x += 1
            continue

        length = try_convert(length, int)

        if not length:
            # parser error - ignoring payload
            return callback(ERR, 0, 1)

        msg = data[x + 1:x + 1 + length]

        if len(msg) != length:
            # parser error - ignoring payload
            return callback(ERR, 0, 1)

        if len(msg):
            packet = decode_packet(msg, binary_type)

            if packet == ERR:
                # parser error in individual packet - ignoring payload
                return callback(ERR, 0, 1)

            if callback(packet, x + length, 1) is False:
                return

        # advance cursor
        x += length + 1
        length = ''

    if length != '':
        # parser error - ignoring payload
        return callback(ERR, 0, 1)


def encode_binary_payload(packets, callback):
    """Encodes multiple messages (payload) as binary.

    :param packets: packets
    :type packets: list

    :return: encoded payload
    :rtype: buffer
    """
    if not packets:
        return callback(bytearray())

    def encode_one(p):
        def encode_callback(packet):
            result = bytearray()

            if isinstance(packet, basestring):
                encoding_length = str(byte_length(packet))
                result.append(0)  # is a string (not true binary = 0)
            else:
                encoding_length = str(len(packet))
                result.append(1)  # is binary (true binary = 1)

            # size
            for x in xrange(len(encoding_length)):
                result.append(int(encoding_length[x]))

            result.append(255)

            result.extend(bytearray(packet))
            return result

        return encode_packet(p, encode_callback, True)

    return callback(bytearray().join(map(encode_one, packets)))


def decode_binary_payload(data, callback, binary_type=None):
    buf = data
    messages = []

    while len(buf) > 0:
        msg_len = ''
        is_string = buf[0] == 0

        # Read length until separator byte
        x = 1
        while buf[x] != 255:
            msg_len += str(buf[x])
            x += 1

        # Remove message length from data buffer
        buf = buf[len(msg_len) + 1:]

        # Parse message length
        msg_len = int(msg_len)

        # Retrieve message
        msg = buf[1:msg_len + 1]
        if is_string:
            msg = str(msg)

        messages.append(msg)
        buf = buf[msg_len + 1:]

    # Decode packets and fire callback
    total = len(messages)

    for x, message in enumerate(messages):
        callback(decode_packet(message, binary_type), x, total)
