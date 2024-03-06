LA CTF 2024 
=====

This CTF was really interesting with very unique challenges and I was only able to solve 4 crypto challenges. 

---

## crypto/round and round


#### *ct_2.txt*
```txt
2126226{19122929121712_6121911821_26422_842928}
```

### Solution
We can figure out that this is pizzini cipher right away from the challenge description.
Just use this [decoder](https://www.cachesleuth.com/pizzini.html) to solve the cipher 

### Flag
> RWSC{PIZZINI_CIPHER_WAS_EAZY}

## network/Last hope 

### Solution
We are given a .cap file and the challenge description mentions about cracking the wifi password. So I instantly went to use **aircrack** to do a simple dictionary attack on it.
> aircrack -ng RAWSECWIFI-01.cap 

### Flag

## Steganography/Zombiefy

#### *kowai* [file](https://github.com/solaris0141/CTF-Writeup/edit/main/rENTASCTF2024/kowai)



