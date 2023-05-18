import base64
import binascii
from gmssl import sm2, func

class SM2:
    """
    非对称算法 SM2 加解密脚本
    """
    def __init__(self, private_key, public_key):
        """
        初始化sm2
        """
        self.sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=private_key)    

    def sm2_decrypt(self, ciphertext_payload:bytes):
        """
        解密函数
        """
        dec_data = self.sm2_crypt.decrypt(ciphertext_payload)
        return dec_data
    
    def sm2_encrypt(self, plaintext_payload:bytes):
        """
        加密函数
        """
        enc_data = self.sm2_crypt.encrypt(plaintext_payload)
        return enc_data

if __name__ == "__main__":
    plaintext_payload = b'111'
    ciphertext_payload = b"\xcb\xa4>^H\xe1\x0c\xabK\x82\x00b\x82\x800%R!\x0c\xfb6\x19\x11\x06\x91Q\xa34\xe0\xb2\xb53\xd7%\xbdP\xef\xa0\x8b\\\xf7sT\x7f\xb21H\xc1\xe3\x13\xcbo\x01\xda\xbep\xce\xf0W\xab\x0e\x8d\xb6\xc8\x9b\xd0\xf9\x7f\xbe\x8eO\x8b\xa4\x90l\xb4\xff\xbf)\x1e\xba<\xad\x80N\x19j\xebJ'%\xf3\x90\xb2g\xf97\n\xe7"
    #16进制的公钥和私钥
    private_key = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
    public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'
    sm2 = SM2(private_key, public_key)
    # r = sm2.sm2_encrypt(plaintext_payload)
    r = sm2.sm2_decrypt(ciphertext_payload)
    print(r)
    