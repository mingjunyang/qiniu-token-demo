#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
__created__='2016-07-14 11:50:40'
"""
from Crypto.Hash import SHA
from Crypto.Hash import HMAC
from base64 import urlsafe_b64encode

secret = b'MY_SECRET_KEY'
h = HMAC.new(secret, digestmod=SHA)
h.update(b'http://78re52.com1.z0.glb.clouddn.com/resource/flower.jpg?e=1468576877')
s = h.digest()
print(urlsafe_b64encode(s))
print(h.hexdigest())
