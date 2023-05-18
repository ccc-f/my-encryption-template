from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
import base64

class RSAPadding():
    """
    RSA 加密，有填充
    """
    def __init__(self, e, m) -> None:
        self.e = e
        self.m = m

    def data_encrypt(self, text):
        """
        RSA 加密
        :param text:    加密前内容
        :return:        加密后内容
        """
        public_exponent = int(self.e,16) 
        public_modulus= int(self.m, 16)
        content = text
        max_length = 117
        public_key = rsa.RSAPublicNumbers(public_exponent, public_modulus).public_key(default_backend())
        data = b''
        for i in range(0, len(content), max_length):
            data += public_key.encrypt(content[i: i + max_length].encode(),
                                    padding.PKCS1v15())
        data = base64.b64encode(data).decode()
        return data

if __name__ == '__main__':
    e = "10001"
    m = 'B23322F080BD5876C0735D585D25C7BC409F637237B07744D27FBF39FB100ABE59DF380EA6BFCDF28C286E7A0CD95BE87F6099F8F39B0E97D9782C3D33FCFB80D43D2F22A9D9417ECFD1A0B8421DEE1CD4B323E8078336E77419A97F94E60A90CA06551202F63819FC8E73425F06ECA4C05BBF8CA32366240A6C36CA61D85019'
    plaintext = '123456'
    rsap = RSAPadding(e, m)
    r = rsap.data_encrypt(plaintext)
    print(r)