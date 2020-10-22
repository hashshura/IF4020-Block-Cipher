# Instructions

To encrypt a file please run: 

```bash
Feistel.py -e -m <ecb|cbc|counter> -t <plaintext file> -k <key> -o <ciphertext file>
```

Feistel-decrypt.py is run using python version2.

To decrypt a file please run:

```bash
Feistel.py -d -m <ecb|cbc|counter> -t <ciphertext file> -k <key> -o <resulting plaintext file>
```

Please make sure you have the input files for both feistel.py and feistel-decrypt.py in the same directory as the script.** **
