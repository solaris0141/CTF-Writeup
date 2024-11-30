SherpaSec CTF 2024 
=====
Just wanted to write the writeup for this specific medium rev challenge since I put in quite some time after the event ended to find the flag for this challenge. 
---

## rev/CPythonGo

From the challenge title alone, I was sort of expecting maybe executables compiled over each other in these 3 different languages, but I definitely was hoping it wouldn't be something like this. And yet, when I first decompiled the file, the feeling that what I have expected came true.




We can use the pyinstxtractor to extract the python bytecode files out and then use pycdc to translate it back to a readable source code for us. One of the files (test.pyc) that we managed to translate gave us some interesting source code that directly hinted towards the final layer of the challenge. 

#### test.py
```python
import ctypes
import os
import base64
import time
import zlib

libc = ctypes.CDLL(None)
syscall = libc.syscall
fexecve = libc.fexecve

# Base64 and zlib decompression
x = zlib.decompress(base64.b64decode(b""))
key = b'CythonGo!'
content = bytearray(len(x))

# Decrypt content
for i in range(len(x)):
    content[i] ^= x[i] ^ key[i % 9]
    if i != len(x) - 1:
        content[i + 1] ^= content[i]

# Assuming the following should execute after the loop
fd = syscall(319, '', 1)
os.write(fd, content)

# Time-based key manipulation
t = int(time.time()).to_bytes(4, 'big')
key = bytearray('SherpaSecIstheBEST', 'utf-8')

# XOR time bytes with the key
for i in range(len(key)):
    key[i] = t[i % 4] ^ key[i]

# Prepare the argument array
argv = (ctypes.c_char_p * 2)(
    b'SGVyZSBpcyB0aGUgZmxhZyEgaHR0cHM6Ly95b3V0dS5iZS9kUXc0dzlXZ1hjUT90PTQy', 
    bytes(key)
)

# Execute using fexecve
fexecve(fd, argv, argv)

```

The zlib was decompressing a very huge base64 string so I had to cut it out from ![here](toolong.txt)
