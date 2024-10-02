IBOH (Battle Of Hackers) CTF 2024 
=====

This event was hosted by the FSEC club and I had the opportunity to create and present 6 of my challenges to the players for this CTF. I have tried my best to make the challenges as interesting as possible but I think one unsurprising factor was that only 1 person solved 1 of my 6 challenges so I guess there just isn't much people interested in learning more about cryptography. I was actually a bit unsatisfied with how I made my challenges after the event. As I put myself in the player's perspective, I don't think I would have enjoyed much from my own challenge simply because there isn't really the "interesting" factor implemented in it except just using known theories. Nevertheless, I am writing this writeup to hopefully encourage more people to try pivoting themselves more into the category of cryptography. 
---

## Grüß Gott!

This challenge was made by my friend which was an interesting C++ code of the enigma machine

```cpp
#include <string>
#include <ctime>
#include <algorithm>
#include <iostream>
using namespace std;

// Function to randomize the order of elements in the array
void randomizeArray(int arr[], int size) {
    srand(time(0)); // Seed for random number generator
    random_shuffle(arr, arr + size); // Shuffle the array
}

string Ciao(string input, int n[6]){
    int code;
    int nsize=6;
    string output;
    for (int i = 0; i < input.size();i++)
    {
        if(input[i]==' '){output+=' ';continue;}
        code = input[i]-'a';
        for (int j = 0; j < nsize;j++)
        {
            code = (code + n[j]) % 26;
        }

        if(code%2==0)   code++;else code--;  // Reflector: if even, add 1; if odd, subtract 1.

        for (int j = nsize-1; j >=0;j--)
        {
            code = code - n[j];
            if(code<0)code=26+code;
        }

        n[0]++;
        for (int j = 0; j < nsize-1; j++)
        {
            if (n[j]>=26)
            {
                n[j + 1]++;
                n[j] = 0;
            }
        }
        n[nsize-1] = n[nsize-1] % 26;
        output += code+'a';
    }
    return output;
}

int main()
{
    string secret="justexample";
    string flag="IBOH24{"+secret +"}";
    // Define 6 rotors from german 
    // hint: 1 - 26 
    int n[6] = {1, 2, 3, 4, 5, 6 }; // just example  
    randomizeArray(n, 6);
    string cipher=Ciao(secret,n);
    cout <<"cipher:"<< cipher<< endl;
    cout << "flag:"<<flag<<endl;
    return 0;
}

//  cipher:sijrknpjtmjjfdmhhlb
```

### Solution
Well first of all, Enigma is actually quite simple to reverse so I just threw it to ChatGPT to generate the reverse script for me. Now the important part is actually on this two line
> int n[6] = {1, 2, 3, 4, 5, 6 }; // just example

and

> if(code%2==0)   code++;else code--;  // Reflector: if even, add 1; if odd, subtract 1.

Essentially, the encryption is based on the values of the rotors, which consist of 6 integers from 1 to 26. By going the brute-forcing way, it would mean about $26^6$ amount of tries needed, which can be a hassle. Looking closely at the code again, it can be realised that the rotors value are actually determined by odd and even integers, so technically we are just brute forcing $2^6$ which is way faster than before by a significant amount. (You can try to test some random rotors value to check, {1,0,0,0,0,0} and {17,0,0,0,0,0} and {9,0,0,0,0,0} are the same ciphertext)

```python
import itertools

def reverse_Ciao(ciphertext, n):
    nsize = len(n)
    output = ""

    for i in range(len(ciphertext)):
        if ciphertext[i] == ' ':
            output += ' '
            continue
        
        code = ord(ciphertext[i]) - ord('a')

        n[0] -= 1
        for j in range(nsize - 1):
            if n[j] < 0:
                n[j] = 25
                n[j + 1] -= 1
            else:
                break
        
        for j in range(nsize):
            code = (code + n[j]) % 26
        
        if code % 2 == 0:
            code -= 1
        else:
            code += 1
        
        for j in range(nsize - 1, -1, -1):
            code = (code - n[j]) % 26
            if code < 0:
                code = 26 + code
        
        output += chr(code + ord('a'))

    return output

ciphertext = "sijrknpjtmjjfdmhhlb"
possible_values = [0, 1]
all_rotor_combinations = itertools.product(possible_values, repeat=6)
for rotors in all_rotor_combinations:
    rotor = list(rotors)
    secret = reverse_Ciao(ciphertext, rotor)
    print("Decrypted secret:", secret, rotors)
```

On a side note, if you just kept the original "example" rotor values which is just {1, 2, 3, 4, 5, 6 }, and run the reverse script, you would already be able to see almost all the characters of the secret, and from there you can just roughly determine the first two character based on the spelling. I still wanted to find a perfect solution though hahaha. 

### Flag
> IBOH24{thisflaglookslikeenigma}

## I'll Kill Yall

![before](flag_latest.png)

This is the Zodiac Killer Cipher based on the Z408 cryptogram. The tricky part about this is that the image given to us is actually cropped out in the hex and we have to edit the height in hex to view the full image. 

![after](fixed.png)

Now we can just put this into the Zodiac Cipher decoder on dcode.fr to solve for this challenge.
> ILIKETOKILLPEOPLECANUFINDMEOUTHAHATHISISTHEFLAGKILLINGPEOPLEEZAFSTOPME

### Flag
> IBOH24{KILLINGPEOPLEEZAF}

## Old MacData Had a Spy, E-I-E-I-O

