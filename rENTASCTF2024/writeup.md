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
> aircrack -ng RAWSECWIFI-01.cap -w {your_wordlist}
Ended up finding the password to be **anonymous**
![aircrack](aircrack.jpg)

### Flag
> RSWC{anonymous}
## Steganography/Zombiefy

#### *kowai* [file](kowai)

### Solution
The file given is in base 32 so I threw it into cyberchef and ended up getting a .jpg image file out of it
![image](zombie.jpg)

Looking at the hex and ASCII values of the image, we can see a interesting string **"JDVRiF"** which instantly brought me to this [tool](https://github.com/CleasbyCode/jdvrif).
After extracting data using the jdvrif tool, we are able to obtain an mp3 file. From then on it's a guessing game on which audio steganography tool was used to encode the flag. In the end it was hinted that this particular [tool](https://github.com/danielcardeenas/AudioStego) was used for the audio steganography part. Finally after extracting the flag out of the audio file with this tool, we managed to obtain the hex values **52 57 53 43 7B 6B 75 72 30 6E 33 6B 4F 7D** which translates to the flag **RWSC{kur0n3kO}**

### Flag
> RWSC{kur0n3kO}



