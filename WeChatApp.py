from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64

class Weixin():
    """
    微信小程序sessionKey泄露加解密脚本
    """
    def __init__(self, key, iv) -> None:
        """
        初始化session_key和iv
        """
        self.key = key
        self.iv = iv

    def encrypto(self, plaintext_payload : bytes):
        """
        加密函数
        """
        backend = default_backend()
        cipher = Cipher(algorithms.AES(base64.b64decode(self.key)), modes.CBC(base64.b64decode(self.iv)), backend=backend)
        padder = padding.PKCS7(128).padder()
        payload = padder.update(plaintext_payload) + padder.finalize()
        encryptor = cipher.encryptor()
        ct = encryptor.update(payload) + encryptor.finalize()
        return base64.b64encode(ct)

    def decrypto(self, ciphertext_payload : str):
        """
        解密函数
        """
        backend = default_backend()
        cipher = Cipher(algorithms.AES(base64.b64decode(self.key)), modes.CBC(base64.b64decode(self.iv)), backend=backend)
        decryptor = cipher.decryptor()
        pt = decryptor.update(base64.b64decode(ciphertext_payload)) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        pt = unpadder.update(pt) + unpadder.finalize()
        return pt.decode()

if __name__ == "__main__":
    ciphertext_payload = "CiyLU1Aw2KjvrjMdj8YKliAjtP4gsMZMQmRzooG2xrDcvSnxIMXFufNstNGTyaGS9uT5geRa0W4oTOb1WT7fJlAC+oNPdbB+3hVbJSRgv+4lGOETKUQz6OYStslQ142dNCuabNPGBzlooOmB231qMM85d2/fV6ChevvXvQP8Hkue1poOFtnEtpyxVLW1zAo6/1Xx1COxFvrc2d7UL/lmHInNlxuacJXwu0fjpXfz/YqYzBIBzD6WUfTIF9GRHpOn/Hz7saL8xz+W//FRAUid1OksQaQx4CMs8LOddcQhULW4ucetDf96JcR3g0gfRK4PC7E/r7Z6xNrXd2UIeorGj5Ef7b1pJAYB6Y5anaHqZ9J6nKEBvB4DnNLIVWSgARns/8wR2SiRS7MNACwTyrGvt9ts8p12PKFdlqYTopNHR1Vf7XjfhQlVsAJdNiKdYmYVoKlaRv85IfVunYzO0IKXsyl7JCUjCpoG20f0a04COwfneQAGGwd5oa+T8yO5hzuyDb/XcxxmK01EpqOyuxINew=="
    plaintext_payload = b'{"openId":"oGZUI0egBJY1zhBYw2KhdUfwVJJE","nickName":"Band","gender":1,"language":"zh_CN","city":"Guangzhou","province":"Guangdong","country":"CN","avatarUrl":"http://wx.qlogo.cn/mmopen/vi_32/aSKcBBPpibyKNicHNTMM0qJVh8Kjgiak2AHWr8MHM4WgMEm7GFhsf8OYrySdbvAMvTsw3mo8ibKicsnfN5pRjl1p8HQ/0","unionId":"ocMvos6NjeKLIBqg5Mr9QjxrP1FA","watermark":{"timestamp":1477314187,"appid":"wx4f4bc4dec97d474b"}}'
    session_key = 'tiihtNczf5v6AKRyjwEUhQ=='
    iv = 'r7BXXKkLb8qrSNn05n0qiA=='
    wx = Weixin(session_key, iv)
    r = wx.decrypto(ciphertext_payload)
    # r = wx.encrypto(plaintext_payload)
    print(r)