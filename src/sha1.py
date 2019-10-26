#!/usr/bin/env python3
import io
import struct

INITIAL_H = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)


def leftrotate(v, n):
    return 0xFFFFFFFF & ((0xFFFFFFFF & (v << n)) | (0xFFFFFFFF & (v >> (32 - n))))


def padding(data_length):
    pad = [0x80] + [0x0] * ((56 - (data_length + 1) % 64) % 64)
    return bytes(pad) + struct.pack(">Q", data_length * 8)


class SHA1:
    def __init__(self, h=INITIAL_H, data_len=0):
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
        return struct.pack(">5I", *h)

    def _padding(self):
        total_len = self._data_len + len(self._unprocessed)
        return padding(total_len)

    def _add_chunk(self, h, chunk):
        w = list(struct.unpack(">16I", chunk))
        for i in range(16, 80):
            w.append(leftrotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))

        a, b, c, d, e = h
        for i in range(80):
            if i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            t = 0xFFFFFFFF & (leftrotate(a, 5) + f + e + k + w[i])
            a, b, c, d, e = t, a, leftrotate(b, 30), c, d

        a += h[0]
        b += h[1]
        c += h[2]
        d += h[3]
        e += h[4]

        return (
            a & 0xFFFFFFFF,
            b & 0xFFFFFFFF,
            c & 0xFFFFFFFF,
            d & 0xFFFFFFFF,
            e & 0xFFFFFFFF,
        )


if __name__ == "__main__":
    main()
