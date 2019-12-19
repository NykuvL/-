from gmssl import sm2, func, sm3


def get_private_key():
    """
    生成私钥
    :return: <bytes> 私钥
    """
    return func.random_hex(64).encode()


def get_public_key(p_k):
    """
    生成私钥所对应的公钥
    :param p_k: <bytes> 私钥
    :return: <bytes> 公钥
    """
    f = sm2.CryptSM2(0, 0)
    return f._kg(int(p_k, 16),  sm2.default_ecc_table['g']).encode()


def sm2_encrypt(pub_k, value):
    """
    sm2加密
    :param pub_k: <bytes> 公钥
    :param value: <bytes> 明文
    :return: <bytes>
    """
    pub_k = pub_k.decode()
    sm2_crypt = sm2.CryptSM2(0, pub_k)
    return sm2_crypt.encrypt(value)


def sm2_decrypt(pri_k, enc_data):
    """
    sm2解密
    :param pri_k: <bytes>私钥
    :param enc_data: <bytes>密文
    :return: <bytes>
    """
    sm2_crypt = sm2.CryptSM2(pri_k, 0)
    if isinstance(enc_data, str):
        enc_data = enc_data.encode()
    return sm2_crypt.decrypt(enc_data)


def sm2_sign(pri_k, d):
    """
    签名
    :param pri_k: <bytes>公钥
    :param d: <bytes>数据
    :return: <bytes>
    """
    random = func.random_hex(64)
    sm2_crypt = sm2.CryptSM2(pri_k, 0)
    return sm2_crypt.sign(d, random).encode()


def sm2_verify(p_k, s, d):
    """
    验证签名
    :param p_k:<bytes>私钥
    :param s: <bytes>签名
    :param d: <bytes>数据
    :return: <bool>
    """
    p_k = p_k.decode()
    sm2_crypt = sm2.CryptSM2(0, p_k)
    return sm2_crypt.verify(s, d)


def sm3_hash(*args):
    """
    sm3杂凑
    :param args: <bytes>字符串
    :return: <bytes>
    """
    temp = ""
    for i in args:
        temp = temp + str(i)
    m = sm3.sm3_hash(func.bytes_to_list(bytes(temp.encode())))
    return bytes(m.encode())

