# -*- coding: utf-8 -*-
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.backends import default_backend

import io,gzip
import hashlib
import base64
import uuid

def upper_str(text):
    return text.upper()


class AES_GZIP:
    def gzip_decode(self, content):
        buf = io.BytesIO(content)
        gf = gzip.GzipFile(fileobj=buf)
        content = gf.read()
        return content

    def pwd_decrypt(self, content):
        key = b'XXXX'
        iv = b'XXXXX'
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        data = decryptor.update(content)
        return self.gzip_decode(data)

class CommonFunc:
    def __init__(self) -> None:
        pass

    def md5(self, plaintext, length=32):
        """
        md5加密函数
        length指定长度32或者16位
        """
        ciphertext = hashlib.md5(plaintext.encode(encoding="UTF-8")).hexdigest()
        if length == 32:
            return ciphertext
        else:
            return ciphertext[8:-8]
    
    def base64_encrypt(self, plaintext):
        return base64.b64encode(plaintext.encode()).decode()
    
    def base64_decrypt(self, ciphertext):
        return base64.b64decode(ciphertext).decode()

    def uuid(self, mode=1):
        """
        默认使用uuid1
        uuid1 基于时间戳
        uuid3 基于名字的MD5散列值
        uuid4 基于随机数
        uuid5 基于名字的SHA-1散列值
        """
        if mode == 1:
            return uuid.uuid1()
        elif mode == 3:
            namespace_uuid = uuid.NAMESPACE_DNS  # 命名空间 UUID
            name_str = "example.com"             # 名称
            return uuid.uuid3(namespace_uuid, name_str)
        elif mode == 4:
            return uuid.uuid4()
        elif mode == 5:
            namespace_uuid = uuid.NAMESPACE_DNS  # 命名空间 UUID
            name_str = "example.com"              # 名称
            return uuid.uuid5(namespace_uuid, name_str)

    def str_to_hex(self, payload):
        """
        字符串转b'\xe7\xaf\xae\xe7\x90\x83'
        :param s:
        :return:
        """
        byte_array = payload.encode('utf-8')
        hex_str = ''.join(['\\x{:02x}'.format(b) for b in byte_array])
        return hex_str
    
    def hex_to_str(self, payload: bytes):
        text = payload.decode('utf-8')
        return text
    
    def str_to_unicode(self, payload):
        encoded_text = payload.encode('unicode_escape').decode()
        return encoded_text

    def unicode_to_str(self, payload):
        codes = payload.split('\\u')[1:] # 拆分出每个编码点
        # 将编码点转换为整数，并转换为对应的 Unicode 字符，然后拼接为完整的字符串
        text = ''.join([chr(int(code, 16)) for code in codes])
        return text

if __name__ == "__main__":
    # gzip_aes = AES_GZIP()
    # gzip_aes.pwd_decrypt()
    # payload = '123456'
    # en_payload = 'MTIzNDU2'
    # cf = CommonFunc()
    # print(cf.upper_str('aaaaa'))
    # print(CommonFunc.upper_str('fff'))
    pass
