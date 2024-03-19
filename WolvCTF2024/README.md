Wolv CTF 2024 
=====

This CTF event had a lot of focus on AES and hashing for the crypto category. I managed to solve 5/7 this time around eventhough I think I could have solved the remaining 2 if I was given more time to do a thorough analysis. 
---

## crypto/Limited1

#### *chall_time.py*
```python
import time
import random
import sys

if __name__ == '__main__':
    flag = input("Flag? > ").encode('utf-8')
    correct = [189, 24, 103, 164, 36, 233, 227, 172, 244, 213, 61, 62, 84, 124, 242, 100, 22, 94, 108, 230, 24, 190, 23, 228, 24]
    time_cycle = int(time.time()) % 256
    if len(flag) != len(correct):
        print('Nope :(')
        sys.exit(1)
    for i in range(len(flag)):
        random.seed(i+time_cycle)
        if correct[i] != flag[i] ^ random.getrandbits(8):
            print('Nope :(')
            sys.exit(1)
    print(flag)
```
### Solution
This challenge basically demonstrates a simple XOR operation but the key we need is the epoch value of the time that the script was ran modded by 256. This makes the challenge relatively easy to solve due to the fact that the time was $\mod256$
We can just write a python script that brute force through all 256 possible values and check if the first 5 characters matches with *wctf*

```python
import random

correct = [189, 24, 103, 164, 36, 233, 227, 172, 244, 213, 61, 62, 84, 124, 242, 100, 22, 94, 108, 230, 24, 190, 23, 228, 24]

for i in range(256):
    random.seed(i)
    if 119 == correct[0] ^ random.getrandbits(8):
        random.seed(i+1)
        if 99 == correct[1] ^ random.getrandbits(8):
            random.seed(i+2)
            if 116 == correct[2] ^ random.getrandbits(8):
                random.seed(i+3)
                if 102 == correct[3] ^ random.getrandbits(8):
                    time_cycle = i
                    
print(time_cycle)

flag = ""
for i in range(len(correct)):
    random.seed(i+time_cycle)
    flag += chr(correct[i] ^ random.getrandbits(8))
print(flag)
```

### Flag
> wctf{f34R_0f_m1ss1ng_0ut}

## crypto/Limited2

#### *NY_chall_time.py*
```python
import time
import random
import sys

if __name__ == '__main__':
    flag = input("Flag? > ").encode('utf-8')
    correct = [192, 123, 40, 205, 152, 229, 188, 64, 42, 166, 126, 125, 13, 187, 91]
    if len(flag) != len(correct):
        print('Nope :(')
        sys.exit(1)
    if time.gmtime().tm_year >= 2024 or time.gmtime().tm_year < 2023:
        print('Nope :(')
        sys.exit(1)
    if time.gmtime().tm_yday != 365 and time.gmtime().tm_yday != 366:
        print('Nope :(')
        sys.exit(1)    
    for i in range(len(flag)):
        # Totally not right now
        time_current = int(time.time())
        random.seed(i+time_current)
        if correct[i] != flag[i] ^ random.getrandbits(8):
            print('Nope :(')
            sys.exit(1)
        time.sleep(random.randint(1, 60))
    print(flag)

```

### Solution
This challenge is a modified version of the Limited1 challenge. Now in Limited2, we are given a range of possible epoch time value between December 31 2023 to the start of January 1 2024. And for every character xored, the script will pause for a random amount of time before repeating the xor operation for the next character. The solution to this challenge is stil relatively similiar to how we solved Limited1, which is to just brute force all possible epoch time values and try to match the first few characters to the flag format *wctf*

```python
import random

correct = [192, 123, 40, 205, 152, 229, 188, 64, 42, 166, 126, 125, 13, 187, 91]

possible = []
for i in range(1703894400, 1704153600):
    random.seed(i)
    if "w" == chr(correct[0] ^ random.getrandbits(8)):
        i2 = i+random.randint(1,60)
        random.seed(i2+1)
        if "c" == chr(correct[1] ^ random.getrandbits(8)):
            i3 = i2+random.randint(1,60)
            random.seed(i3+2)
            if "t" == chr(correct[2] ^ random.getrandbits(8)):
                i4 = i3+random.randint(1,60)
                random.seed(i4+3)
                if "f" == chr(correct[3] ^ random.getrandbits(8)):
                        possible.append(i)
                        
flag = ""
for time_cycle in possible:
    flag = ""
    for i in range(len(correct)):
        random.seed(i+time_cycle)
        res = correct[i] ^ random.getrandbits(8)
        flag += chr(res)
        time_cycle += random.randint(1,60)
        
print(flag)
```

### Flag
> wctf{b4ll_dr0p}

## crypto/Blocked1

#### *server.py*
```python

"""
----------------------------------------------------------------------------
NOTE: any websites linked in this challenge are linked **purely for fun**
They do not contain real flags for WolvCTF.
----------------------------------------------------------------------------
"""

import random
import secrets
import sys
import time

from Crypto.Cipher import AES


MASTER_KEY = secrets.token_bytes(16)


def generate(username):
    iv = secrets.token_bytes(16)
    msg = f'password reset: {username}'.encode()
    if len(msg) % 16 != 0:
        msg += b'\0' * (16 - len(msg) % 16)
    cipher = AES.new(MASTER_KEY, AES.MODE_CBC, iv=iv)
    return iv + cipher.encrypt(msg)


def verify(token):
    iv = token[0:16]
    msg = token[16:]
    cipher = AES.new(MASTER_KEY, AES.MODE_CBC, iv=iv)
    pt = cipher.decrypt(msg)
    username = pt[16:].decode(errors='ignore')
    return username.rstrip('\x00')


def main():
    username = f'guest_{random.randint(100000, 999999)}'
    print("""                 __      __
 _      ______  / /___  / /_ _   __
| | /| / / __ \\/ / __ \\/ __ \\ | / /
| |/ |/ / /_/ / / /_/ / / / / |/ /
|__/|__/\\____/_/ .___/_/ /_/|___/
              /_/""")
    print("[      password reset portal      ]")
    print("you are logged in as:", username)
    print("")
    while True:
        print(" to enter a password reset token, please press 1")
        print(" if you forgot your password, please press 2")
        print(" to speak to our agents, please press 3")
        s = input(" > ")
        if s == '1':
            token = input(" token > ")
            if verify(bytes.fromhex(token)) == 'doubledelete':
                print(open('flag.txt').read())
                sys.exit(0)
            else:
                print(f'hello, {username}')
        elif s == '2':
            print(generate(username).hex())
        elif s == '3':
            print('please hold...')
            time.sleep(2)
            # thanks chatgpt
            print("Thank you for reaching out to WOLPHV customer support. We appreciate your call. Currently, all our agents are assisting other customers. We apologize for any inconvenience this may cause. Your satisfaction is important to us, and we want to ensure that you receive the attention you deserve. Please leave your name, contact number, and a brief message, and one of our representatives will get back to you as soon as possible. Alternatively, you may also visit our website at https://wolphv.chal.wolvsec.org/ for self-service options. Thank you for your understanding, and we look forward to assisting you shortly.")
            print("<beep>")


main()
```
### Solution

### Flag


## crypto/Blocked2

## crypto/TagSeries1
