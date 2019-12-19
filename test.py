import utils
import pickle
import base64
import time
from gmssl import sm3
from datetime import datetime


class A:
    def __init__(self):
        self.a = []


class B:
    def __init__(self):
        self.b = pickle.dumps(A())


if __name__ == "__main__":
    b = B()
    asd = '123'
    qwe = '456'
    print(pickle.loads(b.b), asd, qwe)
