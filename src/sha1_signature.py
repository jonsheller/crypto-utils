#!/usr/bin/env python3
from sha1 import SHA1, padding


def print_internal_state(header, s):
    import struct
    print(header, s._data_len, struct.pack('>5I', *s._h).hex())


def sign(secret, data):
    s = SHA1()
    s.update(secret).update(data)
    return s.finalize().hex()


def verify_signature(secret, data, signature):
    s = SHA1()
    valid_sig = s.update(secret).update(data).finalize().hex()
    print(valid_sig)
    return valid_sig == signature


def extend(data, signature, total_length, additional_data):
    h = [int(signature[8*i:8*i+8], 16) for i in range(5)]
    s = SHA1(h, total_length + len(padding(total_length)))
    s.update(additional_data)
    return data + padding(total_length) + additional_data, s.finalize().hex()


def step_by_step(key, data, additional_data):
    s = SHA1()
    print_internal_state('init', s)
    s.update(key)
    print_internal_state('key', s)
    s.update(data)
    print_internal_state('data', s)
    s.update(padding(len(key) + len(data)))
    print_internal_state('padding', s)
    s.update(additional_data)
    print_internal_state('additional', s)
    print('final', s.finalize().hex())


def main():
    d = b'a=1&b=2'
    key = b'my secret key'
    sig = sign(key, d)
    nd, ns = extend(d, sig, len(d) + len(key), b'&b=5')
    print(nd, ns, verify_signature(key, nd, ns))
    step_by_step(key, d, b'&b=5')


if __name__ == '__main__':
    main()
