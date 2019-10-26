#!/usr/bin/env python3
import io
import struct

INITIAL_H = (0x67452301,
             0xEFCDAB89,
             0x98BADCFE,
             0x10325476,
             0xC3D2E1F0)


def leftrotate(v, n):
    return 0xFFffFFff & ((0xFFffFFff & (v << n)) | (0xFFffFFff & (v >> (32 - n))))


def padding(data_length):
    pad = [0x80] + [0x0] * ((56 - (data_length + 1) % 64) % 64)
    return bytes(pad) + struct.pack('>Q', data_length * 8)


class SHA1:
    def __init__(self, h = INITIAL_H, data_len = 0):
        self._h = h
        self._unprocessed = bytes()
        self._data_len = data_len

    def update(self, data):
        inp = io.BytesIO(self._unprocessed + data)
        while True:
            chunk = inp.read(64)
            if len(chunk) < 64:
                self._unprocessed = chunk
                break
            self._h = self._add_chunk(self._h, chunk)
            self._data_len += 64
        return self

    def finalize(self):
        padding_data = self._padding()
        inp = io.BytesIO(self._unprocessed + padding_data)
        h = self._h
        while True:
            chunk = inp.read(64)
            if len(chunk) < 64:
                break
            h = self._add_chunk(h, chunk)
        return struct.pack('>5I', *h)

    def _padding(self):
        total_len = self._data_len + len(self._unprocessed)
        return padding(total_len)

    def _add_chunk(self, h, chunk):
        w = list(struct.unpack('>16I', chunk))
        for i in range(16, 80):
            w.append(leftrotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))

        a, b, c, d, e = h
        for i in range(80):
            if i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5a827999
            elif i <= 39:
                f = b ^ c ^ d
                k = 0x6ed9eba1
            elif i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8f1bbcdc
            else:
                f = b ^ c ^ d
                k = 0xca62c1d6

            t = 0xffFFffFF & (leftrotate(a, 5) + f + e + k + w[i])
            a, b, c, d, e = t, a, leftrotate(b, 30), c, d

        a += h[0]
        b += h[1]
        c += h[2]
        d += h[3]
        e += h[4]

        return (a & 0xffFFffFF, b & 0xffFFffFF, c & 0xffFFffFF, d & 0xffFFffFF, e & 0xffFFffFF)


if __name__ == '__main__':
    main()
