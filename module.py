import utils
import time
import pickle
import base64
import os
import base58
from datetime import datetime


class MerkleNode(object):
    """
    MerkleTree node
    """

    def __init__(self, left, right, data):
        """
        初始化默克尔树节点
        :param left:
        :param right:
        :param data:
        """
        if left is None and right is None:
            self.data = utils.sm3_hash(data)
        else:
            self.data = utils.sm3_hash(left.data, right.data)

        self.left = left
        self.right = right


class MerkleTree(object):
    """
    MerkleTree
    """

    def __init__(self, data_list):
        """
        初始化默克尔树
        :param data_list: 二进制数据列表
        """
        nodes = []
        if len(data_list) % 2 != 0:
            data_list.append(data_list[-1])

        for data in data_list:
            nodes.append(MerkleNode(None, None, data))

        for i in range(len(data_list)//2):
            new_level = []
            for j in range(0, len(nodes), 2):
                if j+1 == len(nodes):
                    node = MerkleNode(None, None, nodes[j].data)
                else:
                    node = MerkleNode(nodes[j], nodes[j+1], None)
                new_level.append(node)

            nodes = new_level

        self.__root = nodes[0]

    def root_hash(self):
        return self.__root.data


class Data:
    def __init__(self):
        self.timestamp = time.time()
        self.addr_key = {}  # 根据地址找公钥
        self.account_verify = {}  # 根据用户名找验证口令
        self.addr_rec_mail = {}  # 根据地址找收到邮件
        self.addr_send_mail = {}  # 根据地址找发出邮件

    def update(self):
        self.timestamp = time.time()


class Mail:
    def __init__(self, to_key, content, from_key):
        """
        邮件类型除time以外全变量bytes
        :param to_key: <str>接受方公钥
        :param content<dict>: 包含标题正文、发送方地址、接收方地址
        :param from_key: <str>发送方私钥
        """
        self.index = 0  # 邮件标号用于查找邮件
        self.content = utils.sm2_encrypt(to_key.encode(), pickle.dumps(content))
        self.time = str(datetime.fromtimestamp(int(time.time())))
        self.pub_k = to_key.encode()
        # self.pri_k = from_key.encode()
        self.content_hash = utils.sm3_hash(base64.b64encode(pickle.dumps(content)))
        self.verify = utils.sm2_sign(from_key.encode(), self.content_hash)


class Block:
    def __init__(self):
        self.index = 0  # 区块标号用于查找区块
        self.__mails = []
        self.data = pickle.dumps(Data())  # Data
        self.pre_hash = None  # bytes
        self.hash = None  # bytes
        self.merkle_root = None  # bytes
        self.timestamp = None  # bytes
        self.nonce = None  # int

    def seal_block(self, target):
        nodes = []
        for b_mail in self.__mails:
            nodes.append(pickle.dumps(b_mail))
        merkle_tree = MerkleTree(nodes)
        self.merkle_root = merkle_tree.root_hash()
        self.timestamp = str(time.time()).encode()
        self.hash = utils.sm3_hash(base64.b64encode(pickle.dumps(self.__mails)))
        data = self.pre_hash + self.hash + self.merkle_root + self.timestamp + self.data
        nonce = 0
        while True:
            hash_hex = utils.sm3_hash(data + str(nonce).encode())
            hash_int = int(hash_hex, 16)
            if hash_int > target:
                nonce += 1
            else:
                break
        self.nonce = nonce

    def validate(self, target):
        data = self.pre_hash + self.hash + self.merkle_root + self.timestamp + self.data
        hash_hex = utils.sm3_hash(data + str(self.nonce).encode())
        hash_int = int(hash_hex, 16)
        if hash_int > target:
            return False
        return True

    def update_data(self, data):
        if data.timestamp > pickle.loads(self.data).timestamp:
            self.data = pickle.dumps(data)

    def add_mail(self, b_mail):
        if len(self.__mails) > 0:
            b_mail.index = self.__mails[-1].index + 1
        self.__mails.append(b_mail)
        return b_mail.index

    def find_mail(self, index):
        for m in self.__mails:
            if m.index == index:
                return m
        return False

    def get_length(self):
        return len(self.__mails)


class BlockChain:
    def __init__(self):
        target_max = int('0xFFF00000FFFFF000000000000000000000000000000000000000000000000000', 16)
        # 最大目标
        difficulty = 1
        # 难度，数值越大难度越大
        self.__target = target_max / difficulty
        self.__chain = []

    def add_block(self, block):
        if block.nonce is None:
            if len(self.__chain) > 0:
                block.pre_hash = self.__chain[-1].hash
                block.index = self.__chain[-1].index + 1
            else:
                block.pre_hash = b'creation'
            block.seal_block(self.__target)
        self.__chain.append(block)
        self.save()
        return block.index

    def validate(self, block):
        if block.pre_hash == self.__chain[-1].hash:
            if block.validate(self.__target) is True:
                return True
        return False

    def find_block(self, index):
        for b in self.__chain:
            if b.index == index:
                return b
        return False

    def last_block(self):
        return self.__chain[-1]

    def get_length(self):
        return len(self.__chain)

    def save(self):
        db_file = 'center_db/chain.db'
        with open(db_file, 'wb') as file:
            pickle.dump(self.__chain, file)

    def load(self):
        db_file = 'center_db/chain.db'
        if os.path.getsize(db_file) > 0:
            with open(db_file, 'rb') as file:
                self.__chain = pickle.load(file)


class Account:
    def __init__(self, username, password):
        self.__username = username
        self.__password = password
        self.__pri_key = utils.get_private_key()
        self.__pub_key = utils.get_public_key(self.__pri_key)
        v = utils.sm3_hash(username.encode() + self.__pub_key)[:4]
        self.address = base58.b58encode(v).decode() + '@' + username
        pri_k = utils.sm3_hash(self.__username + self.__password)[:64]
        pub_k = utils.get_public_key(pri_k)
        code = utils.sm2_encrypt(pub_k, (self.__pri_key.decode() + '@' + self.__username).encode())
        self.verification = code  # 验证口令

    def verify(self, verify_code):
        pri_k = utils.sm3_hash(self.__username + self.__password)
        try:
            code = utils.sm2_decrypt(pri_k, verify_code).decode()
        except UnicodeDecodeError:
            return False

        verification = str(code.split('@', 1)[1])
        if verification == self.__username:
            self.__pri_key = str(code.split('@', 1)[0]).encode()
            self.__pub_key = utils.get_public_key(self.__pri_key)
            v = utils.sm3_hash(self.__username.encode() + self.__pub_key)[:4]
            self.address = base58.b58encode(v).decode() + '@' + self.__username
            self.verification = verify_code
            return True
        return False

    def get_pub_key(self):
        return self.__pub_key

    def get_pri_key(self):
        return self.__pri_key



# if __name__ == "__main__":
#     from_k = utils.get_private_key().decode()
#     to_k = utils.get_public_key(from_k).decode()
#     c = {
#         'title': 'abc',
#         'content': '123',
#         'to': to_k,
#         'from': from_k
#     }
#     mail = Mail(to_k, c, from_k)
#     b = Block()
#     b.add_mail(mail)
#     c = BlockChain()
#     c.add_block(b)
#     print(c.get_length())
