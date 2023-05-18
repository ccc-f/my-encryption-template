# 公钥加密
import base64
import rsa
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.PublicKey import RSA

class RSAPulicKey():
    """
    实现了 RSA 公钥私钥加解密
    """
    def __init__(self) -> None:
        pass

    def rsa_encrypt(self, data, publicKeyStr):
        '''
        data:内容
        publicKeyStr:不需要-----BEGIN PUBLIC KEY-----开头，-----END PUBLIC KEY-----结尾的格式,只要中间部分即可
        key_encoded:需要-----BEGIN PUBLIC KEY-----开头，-----END PUBLIC KEY-----结尾的格式
        '''
        key_encoded='''-----BEGIN PUBLIC KEY-----
                        MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCdZGziIrJOlRomzh7M9qzo4ibw
                        QmwORcVDI0dsfUICLUVRdUN+MJ8ELd55NKsfYy4dZodWX7AmdN02zm1Gk5V5i2Vw
                        GVWE205u7DhtRe85W1oR9WTsMact5wuqU6okJd2GKrEGotgd9iuAJm90N6TDeDZ4
                        KHEvVEE1yTyvrxQgkwIDAQAB
                        -----END PUBLIC KEY-----'''
        publicKeyBytes = base64.b64decode(publicKeyStr.encode())
        key = RSA.import_key(publicKeyBytes)
        #key = RSA.import_key(key_encoded)
        # 4、对原密码加密
        encryptPassword = rsa.encrypt(data.encode(), key)
        return base64.b64encode(encryptPassword).decode()
    
    def rsa_decrypt(self, msg, privateKeyStr):
        msg = base64.b64decode(msg)
        # 私钥解密
        priobj = Cipher_pkcs1_v1_5.new(RSA.importKey(privateKeyStr))
        data = priobj.decrypt(msg,None).decode()
        return data

if __name__ =='__main__':
    data = '123456'
    publickey_str = """MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm8kPgp7ed4m69hcIkAzL
                        zyvy7Q8oUyuTJ5hX/Z6nz/f+IJAWCDd7s2QaznbvXmEPOi3r7SeoRlIVRXXhmVwE
                        8FH3JfhgXufd6vS1TntdVOAbhAOMYEwZzdqTvW7QogJoatD9AczN39ySeZ77ltn1
                        jb5sI0Yh9XCA/ldaPXKj2u141WQlg00g8CjFE0+CzwgrF+6sNStdG+tnE2tE0aPY
                        1Y3yorD8oFhCPLGC7dzBMzmOOO07JbQqPwPldj0aRpAh0+ThA7hCcM2+cQu8x1dq
                        +foGmd2G1J4zgebIsJ92H9YNQSKZ3Kr43/c0pLVWTIVJGI1JFTlX9dun3axRHtg3
                        5QIDAQAB"""
    privatekey_str = """-----BEGIN PRIVATE KEY-----
                        MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCbyQ+Cnt53ibr2
                        FwiQDMvPK/LtDyhTK5MnmFf9nqfP9/4gkBYIN3uzZBrOdu9eYQ86LevtJ6hGUhVF
                        deGZXATwUfcl+GBe593q9LVOe11U4BuEA4xgTBnN2pO9btCiAmhq0P0BzM3f3JJ5
                        nvuW2fWNvmwjRiH1cID+V1o9cqPa7XjVZCWDTSDwKMUTT4LPCCsX7qw1K10b62cT
                        a0TRo9jVjfKisPygWEI8sYLt3MEzOY447TsltCo/A+V2PRpGkCHT5OEDuEJwzb5x
                        C7zHV2r5+gaZ3YbUnjOB5siwn3Yf1g1BIpncqvjf9zSktVZMhUkYjUkVOVf126fd
                        rFEe2DflAgMBAAECggEAGXOAwDNaXyc2T0w2Duq4RXGFr6shSG0/DmH6RiosenKm
                        pwVDRDZkVEuPgZm2w7GRvkyQVd97w3lXllCK+fYprGWHvkFU5Ux2WhN+p4LKHbq7
                        ZBb8USM9t/700icPmNhR3Nml7Cxcmi08FPifW+biEjVBD4Y+uA2YVXVJ/e4DzRlr
                        tV8hgQ+T8+xB5b17Q9dmyjJUcN7kzaoZBSyoHcH0+7h1C/VxZJBCEaHKVlHd47IS
                        FhaR+piIXyU+byvMJVthvqWYFEjlZDeb7+JHk0NDzxd/MkuZv8QzzZmWdN8A5b8i
                        ApQfQyJKqj0cU5KdBlwfqdm0iC9D0soooIH+klIHRQKBgQDMvQNCR2HCDPi732cM
                        LlXqdl4pn+Wufihthd+Vqq+mAlKT2T/5LkdwnpM6h7yixcmDr2HaDLCZ71F9IiUt
                        iqvA8B/NVg4pI5zupF+OfDI1Sg9CGWxNJqfVQ2jC9D/pLc29XNnHIjXclabJL0U9
                        BlSvqq1BcYNCd8rs4tmobv7NxwKBgQDCyldmA9NXWA19qpwxESatVW75PdnJMLx6
                        nEH85XCbONxuS1Sf1orKWg0RklRVGGRnBAqf4V0zmP0u0OVfThYuAmnwp1pYG/wW
                        XmuXDWojrLrSbA1gtxK2F7m5KpXg8iCcK5Rnug/JVdHsrHqtJ9hTFnoL2af6I3jr
                        HiV62D388wKBgALrw2sjp5JkKvxLMKYs1w70R12iqV028Y62dT0mZUEiEVmIpPAC
                        KATETmdsXlWYKsrVKrk4qyBXGLuHTC59JvwmsN12F9egaXHCKJbY0MKP3u3bfP8Q
                        yR4yywDVCUBjZecItxavN0OBYxLFuOApAfZLohMn8m51VRDSH7bWdo4rAoGAT1cn
                        fi/0t1DwPc1uTTYVMOjpiK++s4ocWzymTCIQWckxT+NzFp/GbGF9jTizDO4ghy1I
                        PpMG6WtZROZlZwphUmA9Un53+Ad+CIZxAFfAccN7XRYR5ODsyCqlxVwpLDSzP6ko
                        i49nurQwC1y9oyXloQI4t/bxypsEN5BR59WIei0CgYBmcZhyWjV80SI7m996iNuo
                        Fy3gVDndbpUeHXwAj3JLN9izlR3OotoXbjGlah7Ddh6DFGWjpDVDKpEiqXv/GNMR
                        jbgWrjH+Rh3WH9pMnn0VWlfZ6T9IX6pqvXsfXEvyONDRhw360HSop5KdXey4b3q9
                        /5H03MmqOc7p0MzJ4U2z3A==
                        -----END PRIVATE KEY-----"""
    
    r = RSAPulicKey()
    result = r.rsa_encrypt(data, publickey_str)
    result = r.rsa_decrypt(result, privatekey_str)
    print(result)