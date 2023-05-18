# python3
import struct
import binascii
import struct

def decode(cookie_value):
     (host, port, end) = cookie_value.split('.')
     [a, b, c, d] = struct.unpack("<BBBB", binascii.unhexlify(binascii.hexlify(struct.pack("<I", int(host)))))
     p = [int(i) for i in bytes.fromhex(binascii.hexlify(struct.pack("<I", int(port))).decode())]
     port = p[0]*256 + p[1]
     result = "{0}.{1}.{2}.{3}:{4}".format(a,b,c,d,port)
     return result

if __name__ == '__main__':
     cookie = '487098378.24095.0000'
     cookie = '1677787402.36895.0000'
     print(decode(cookie))