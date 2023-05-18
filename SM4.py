from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT



class MySM4:
    def __init__(self, key) -> None:
        self.key = key
        self.crypt_sm4 = CryptSM4()
    
    def encrypt_ecb(self, plaintext):
        self.crypt_sm4.set_key(self.key, SM4_ENCRYPT)
        encrypt_value = self.crypt_sm4.crypt_ecb(plaintext)
        return encrypt_value
    
    def decrypt_ecb(self, ciphertext):
        self.crypt_sm4.set_key(self.key, SM4_DECRYPT)
        decrypt_value = self.crypt_sm4.crypt_ecb(ciphertext).decode()
        return decrypt_value
    
    def encrypt_cbc(self, iv, plaintext):
        self.crypt_sm4.set_key(self.key, SM4_ENCRYPT)
        encrypt_value = self.crypt_sm4.crypt_cbc(iv, plaintext)
        return encrypt_value
    
    def decrypt_cbc(self, iv, ciphertext):
        self.crypt_sm4.set_key(self.key, SM4_DECRYPT)
        decrypt_value = self.crypt_sm4.crypt_cbc(iv, ciphertext).decode()
        return decrypt_value

if __name__ == '__main__':
    key = b'3l5butlj26hvv313'
    iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' #  bytes类型
    payload = b'123456'
    mys4 = MySM4(key)
    # result = mys4.encrypt_ecb(payload)
    # result = mys4.decrypt_ecb(result)

    result = mys4.encrypt_cbc(iv, payload)
    result = mys4.decrypt_cbc(iv, result)
    print(result)
