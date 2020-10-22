# Instructions

To encrypt a file: 

```bash
Feistel.py -e -m <ecb|cbc|counter> -t <plaintext file> -k <key> -o <ciphertext file>
```

To decrypt a file:

```bash
Feistel.py -d -m <ecb|cbc|counter> -t <ciphertext file> -k <key> -o <resulting plaintext file>
```
