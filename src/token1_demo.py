#!/usr/bin/env python3
# -*- coding:utf-8 -*-
from base64 import urlsafe_b64encode
import os
from urllib.parse import quote
# import arrow
from Crypto.Hash import HMAC
from Crypto.Hash import SHA
import json


# 假设有如下的管理请求：
AccessKey = "MY_ACCESS_KEY"
SecretKey = "MY_SECRET_KEY"
url = "http://rs.qiniu.com/move/bmV3ZG9jczpmaW5kX21hbi50eHQ=/bmV3ZG9jczpmaW5kLm1hbi50eHQ="

signingStr = "/move/bmV3ZG9jczpmaW5kX21hbi50eHQ=/bmV3ZG9jczpmaW5kLm1hbi50eHQ=\n"


def sign_ak(AccessKey, SecretKey, signingStr):
    sign = HMAC.new(SecretKey.encode('utf-8'), digestmod=SHA)
    sign.update(signingStr.encode('utf-8'))
    signHex = sign.digest()
    encodedSign = urlsafe_b64encode(signHex).decode('utf-8')
    print(encodedSign)
    print("FXsYh0wKHYPEsIAgdPD9OfjkeEM=")

    # 最终的管理凭证是：
    return "{0}:{1}=".format(AccessKey, encodedSign)

def sign_ak1(AccessKey, SecretKey, signingStr):
    sign = HMAC.new(SecretKey.encode('utf-8'), digestmod=SHA)
    sign.update(signingStr.encode('utf-8'))
    signHex = sign.digest()
    encodedSign = urlsafe_b64encode(signHex).decode('utf-8')
    return "{0}:{1}".format(AccessKey, encodedSign)


token = sign_ak(AccessKey, SecretKey, signingStr)

token1 = sign_ak1(AccessKey, SecretKey, signingStr)
print(token1)
