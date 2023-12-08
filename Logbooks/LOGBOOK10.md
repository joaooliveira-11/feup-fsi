# Secret Key Encryption

## Task 1: Frequency Analysis

For this task, we are given a ciphertext.txt file whose content is encrypted using a monoalphabetic cipher - a cipher in which each letter is replaced by another letter and this replacement will not vary throughout the text. Our goal is to find the original text through a frequency analysis.

Running the freq.py program, we obtain the frequency table of the letters of the encrypted text:

```
1-gram (top 20):                2-gram (top 20):                3-gram (top 20):
    n: 488                          yt: 115                         ytn: 78
    y: 373                          tn: 89                          vup: 30
    v: 348                          mu: 74                          mur: 20
    x: 291                          nh: 58                          ynh: 18
    u: 280                          vh: 57                          xzy: 16
    q: 276                          hn: 57                          mxu: 14
    m: 264                          vu: 56                          gnq: 14
    h: 235                          nq: 53                          ytv: 13
    t: 183                          xu: 52                          nqy: 13
    i: 166                          up: 46                          vii: 13
    p: 156                          xh: 45                          bxh: 13
    a: 116                          yn: 44                          lvq: 12
    c: 104                          np: 44                          nuy: 12
    z: 95                           vy: 44                          vyn: 12
    l: 90                           nu: 42                          uvy: 11
    g: 83                           qy: 39                          lmu: 11
    b: 83                           vq: 33                          nvh: 11
    r: 82                           vi: 32                          cmu: 11
    e: 76                           gn: 32                          tmq: 10
    d: 59                           av: 31                          vhp: 10
```


These tables show the frequencies of isolated letters, sequences of two letters, and sequences of three letters (1-gram, 2-gram, 3-gram, respectively). By consulting the articles 1-Gram, 2-Gram and 3-Gram we can verify these same occurrence frequencies in the English language.

Analyzing the data we obtained, we can see that the first two sequences of the 2-Gram and 3-Gram coincide with the two most common 2-Gram sequences and the 3-Gram sequence in the English language, so we proceed with the following substitution:

```bash
tr 'ytn' 'THE' < ciphertext.txt > dec.txt
```

From here, an analysis is made of both the text and the frequencies in order to make the safest possible substitutions. From a certain point, it becomes easy to understand the original text and make the correct substitutions because there are words to which only one letter is missing. The command that decrypts the entire file is as follows:

```bash
tr 'ytnmuvupxiqjzhgrdlabcsefko' 'THEINANDOLSQURBGYWCFMKPVXJ' < ciphertext.txt > dec.txt
```

## Task 2: Encryption with different Ciphers and Modes

In this task we should test the use of the openssl command to encrypt and decrypt files with different ciphers and modes. We used the file created in the previous task (dec.txt) to test the different modes and ciphers. Running the man openssl command we can verify that the command supports the following ciphers:

```
AES-128 Cipher, AES-192 Cipher, AES-256 Cipher, Aria-128 Cipher, Aria-192 Cipher, Aria-256 Cipher, Base64 Encoding, Blowfish Cipher, Camellia-128 Cipher, Camellia-192 Cipher, Camellia-256 Cipher, CAST Cipher, CAST5 Cipher, Chacha20 Cipher, DES Cipher, Triple-DES Cipher, IDEA Cipher, RC2 Cipher, RC4 Cipher, RC5 Cipher, SEED Cipher, SM4 Cipher
```

For most of the ciphers, an operation mode is also provided (cbc, cfb, ctr, ecb, ofb) which will define how the cipher is applied, block by block.

We tested the following commands:

```bash
$ openssl enc -aes128 -e -in dec.txt -out cipher.bin -K 00112233445566778889aabbccddeeff -iv 0102030405060708
hex string is too short, padding with zero bytes to length

$ openssl enc -aria-128-ctr -e -in dec.txt -out cipher.bin -K 00112233445566778889aabbccddeeff -iv 0102030405060708
hex string is too short, padding with zero bytes to length

$ openssl enc -aria-128-ecb -e -in dec.txt -out cipher.bin -K 00112233445566778889aabbccddeeff
```

**Note**: The last encryption method does not need -iv because it is in ecb mode which encrypts the blocks independently of each other.

## Task 3: ECB and CBC

| In this task we are given an image that we will have to encrypt in ecb and cbc modes so that we can later compare the results.| ![original](../docs/logbook10/pic_original.bmp) |
| :------------------------------------------------------------------------------------------------------------------------------: | :-------------------------------------------: |
|                                                                                                                                  |                 original image               |

The commands used to encrypt the image are:

```bash
openssl enc -aes-128-cbc -e -in pic_original.bmp -out pic_original_cbc.bmp -K 00112233445566778889aabbccddeeff -iv 0102030405060708
openssl enc -aes-128-ecb -e -in pic_original.bmp -out pic_original_ecb.bmp -K 00112233445566778889aabbccddeeff -iv 0102030405060708
```

The results obtained are the files `pic_cbc.bmp` e `pic_ecb.bmp`.

These files, at the moment, cannot be opened in any image viewer since their headers are encrypted. So we copied the headers from the original image to the encrypted files:

```bash
head -c 54 pic_original.bmp > header
tail -c +55 pic_cbc.bmp > body
cat header body > pic_cbc.bmp
tail -c +55 pic_ecb.bmp > body
cat header body > pic_ecb.bmp
```

| ![ecb](../docs/logbook10/pic_ecb.bmp) | ![cbc](../docs/logbook10/pic_cbc.bmp) |
| :--------------------------------------: | :--------------------------------------: |
|      `ecb`      |     `cbc`      |

It is possible to analyze that the information was much better hidden in cbc mode. To understand the reason, just pay attention to the operation mode - symmetric and asymmetric, respectively - of each one:

#### ECB: Electronic Code Book (symmetric)

This is the simplest encryption mode. The information to be encrypted is divided into blocks of equal size and each of these blocks will be encrypted individually with the same key. This is verified in the image encrypted in ecb mode where its information bytes are subject to uniform encryption. This uniformity makes it possible, even with different colors, to understand the shape of the original image. Another disadvantage of this encryption mode was verified in task 1 where the text was encrypted letter by letter. With symmetric encryption we can more easily infer its content through frequency analysis.

#### CBC: Cipher Block Chaining (assymmentric)

This mode is more complex than the previous one. Similarly to the previous process, the information to be encrypted is separated into blocks of equal size. Initially, an initial vector (the size of the blocks) is provided with which we will perform an XOR operation with the first block of information. Only then will the encryption key be applied to the first block. The resulting value, in addition to being the encrypted information, will be used to perform the XOR operation with the next block. This process is repeated until the final block is reached. The result - as can be seen - will be much more random and difficult to encrypt since each block will be unique - frequency analysis can no longer be done.

An advantage of this mode lies in the fact that, despite its encryption having to be done sequentially, its decryption can be parallelized since the first initialization vector is public and the following initialization vectors are the already encrypted blocks. Parallelization during decryption allows for faster decryption.