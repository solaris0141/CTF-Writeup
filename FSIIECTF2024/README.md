FSIIEC CTF 2024 
=====

THis CTF was hosted as a collaboration between FSEC-SS APU Malaysia and ENSIIE France. The whole CTF event was 24 hours and was hosted live on cyber cohesion (warzone) platform. Though the platform had quite some buggy moments and the points system was going crazy, we still managed to solve a lot of the challenges.
---

## crypto/Cyber CHEF

```txt
Enc flag: O0pdKiM7Y1FqZDxeZzFOOksxJUM6MjQ5XzlpUHFFPiIhLk46M29CSDltVClfOi5KSyc6LkozIT1gJGNHPiY/XGI5Z2hIMg==
```

### Solution
A very simple and direct challenge, just put it into cyberchef and it will be solved via the magic tool. 

### Flag
> FSIIECTF{93567019dd9171f3094fd4dfbbcfa801}

## crypto/Cyber CHEF 2

```txt
Enc flag: Enc flag: NSY5LDcoMT8IFBVVSg9TGkdCRlVHCF0dEkNDBEBfA0FKFBNdFwhdHUMI
```

### Solution 
The description hinted at XOR, so just put it into Cyberchef and xor with the flag format **FSIIECTF{**, this will only leak 9 characters of the key. Luckily, the result was a 8 characters long key so we can now just xor the encrypted flag with the obtained key to get our flag. 

### Flag
> FSIIECTF{ae08d6c47605c8da63a24f89ac8ec8d0}

