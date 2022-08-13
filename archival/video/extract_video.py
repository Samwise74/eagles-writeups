import struct

with open('carved', 'rb') as f:
    sz = struct.unpack('<I', f.read(4))[0]
    k1 = int.from_bytes(f.read(1), byteorder='big')
    k2 = int.from_bytes(f.read(1), byteorder='big')
    _ = f.read(9)
    sz -= 10 + 6
    content = f.read(sz)

print(sz, k1, k2)

out = b''
for x in range(0, sz, 2):
    if x + 1 < sz:
        out += bytes([content[x + 1] ^ k1, content[x] ^ k2])
    else:
        out += bytes([content[x] ^ k1])
# print(out[:4])
with open('flagout.png', 'wb') as f:
    f.write(out)
