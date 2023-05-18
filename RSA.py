import rsa

class RsaEncrypt(object):
    """
    RSA 加密无填充
    """
    def __init__(self, e, m):
        self.e = e
        self.m = m

    def encrypt(self, message, upper=True):
        mm = int(self.m, 16)
        ee = int(self.e, 16)
        rsa_pubkey = rsa.PublicKey(mm, ee)
        crypto = self._encrypt(message.encode(), rsa_pubkey)
        ciphertext = crypto.hex()
        if upper:
            ciphertext = ciphertext.upper()
        return ciphertext

    def _pad_for_encryption(self, message, target_length):
        message = message[::-1]
        max_msglength = target_length - 11
        msglength = len(message)

        padding = b''
        padding_length = target_length - msglength - 3

        for i in range(padding_length):
            padding += b'\x00'

        return b''.join([b'\x00\x00', padding, b'\x00', message])

    def _encrypt(self, message, pub_key):
        keylength = rsa.common.byte_size(pub_key.n)
        padded = self._pad_for_encryption(message, keylength)

        payload = rsa.transform.bytes2int(padded)
        encrypted = rsa.core.encrypt_int(payload, pub_key.e, pub_key.n)
        block = rsa.transform.int2bytes(encrypted, keylength)

        return block


if __name__ == '__main__':
    #模
    m = "ae068c2039bd2d82a529883f273cf20a48e0b6faa564e740402375a9cb332a029b8492ae342893d9c9d53d94d3ab8ae95de9607c2e03dd46cebe211532810b73cc764995ee61ef435437bcddb3f4a52fca66246dbdf2566dd85fbc4930c548e7033c2bcc825b038e8dd4b3553690e0c438bbd5ade6f5a476b1cbc1612f5d501f"
    #指数
    e = '10001'
    en = RsaEncrypt(e, m)
    message = '123456'
    print(en.encrypt(message))