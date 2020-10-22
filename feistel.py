import sys, getopt, hashlib
import random
from math import exp, expm1

ROUNDS = 8
BLOCKSIZE = 8
BLOCKSIZE_BITS = 64
PATH_TO_FILES = "Files/"
SECRET = "3f788083-77d3-4502-9d71-21319f1792b6"

sb1 = [ 4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3 ]
sb2 = [ 14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9 ]
sb3 = [ 5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11 ]
sb4 = [ 7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3 ]
sb5 = [ 6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2 ]
sb6 = [ 4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14 ]
sb7 = [ 13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12 ]
sb8 = [ 1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12 ]

sb = [ sb1, sb2, sb3, sb4, sb5, sb6, sb7, sb8 ]

def main(argv):
    decrypt = False
    encrypt = False

    try:
        opts, args = getopt.getopt(argv, "hdem:t:k:o:", [" mode ='', ptext=", "key=", "outfile="])

    except getopt.getoptError:
        sys.exit(1)

    if len(sys.argv[1:]) < 6:
        print ('Usage: ./feistel.py -[d|e] -m <mode> -t <inputfile> -k <key> -o <outputfile>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('Usage: ./feistel.py -[d|e] -m <mode> -t <inputfile> -k <key> -o <outputfile>')
            sys.exit()
        elif opt == "-d":
            decrypt = True
        elif opt == "-e":
            encrypt = True
        elif opt in ("-m", "--mode"):
            mode = str(arg).lower()
        elif opt in ("-t", "--ptext"):
            filename = str(arg)
        elif opt in ("-k", "--key"):
            key = str(arg)
        elif opt in ("-o", "--outfile"):
            outfilename = str(arg)

    if (encrypt and decrypt):
        print("Cannot encrypt AND decrypt")
        sys.exit(1)

    if (mode != "ecb" and mode != "cbc" and mode != "counter"):
        print ("Unknown cryptographic mode")
        sys.exit(1)


    with open(PATH_TO_FILES + filename, "r") as f:
        input = f.read()

    # call the crypto function
    if (encrypt):
        output = encryptMessage(key, input, mode)
    elif (decrypt):
        output = decryptCipher(key, input, mode)

    with open(PATH_TO_FILES + outfilename, 'w+') as fw:
        fw.write(output)

    # Print the ciphertext

    #print(ciphertext)

def shuffle(message, key):
    random.seed(key)
    l = range(len(message))
    random.shuffle(l)
    return [message[x] for x in l]

def unshuffle(shuffled_message, key):
    random.seed(key)
    l = range(len(shuffled_message))
    random.shuffle(l)
    out = [None] * len(shuffled_message)
    for i, x in enumerate(l):
        out[x] = shuffled_message[i]
    return out

def encryptMessage(key, message, mode):
    ciphertext = ""
    n = BLOCKSIZE  # 8 bytes (64 bits) per block

    # Split mesage into 64bit blocks
    message = [message[i: i + n] for i in range(0, len(message), n)]

    lengthOfLastBlock = len(message[len(message)-1])

    if ( lengthOfLastBlock < BLOCKSIZE):
        for i in range(lengthOfLastBlock, BLOCKSIZE):
            message[len(message)-1] += " "

    #print(message)

    # generate a 256 bit key based of user inputted key
    key = key_256(key)
    key_initial = key
    ctr = 0
    for block in message:
        L = [""] * (ROUNDS + 1)
        R = [""] * (ROUNDS + 1)
        L[0] = block[0:BLOCKSIZE/2]
        R[0] = block[BLOCKSIZE/2:BLOCKSIZE]

        for i in range(1, ROUNDS+1):
            round_key = subkeygen(str(i), key, i)
            LR_im = R[i - 1][:BLOCKSIZE/4]
            RR_im = R[i - 1][BLOCKSIZE/4:]

            LL_i = RR_im
            RL_i = xor(LR_im, scramble(RR_im, i, round_key))

            L[i] = LL_i + RL_i
            R[i] = xor(L[i - 1], scramble(R[i - 1], i, round_key))

        partial_cipher = L[ROUNDS] + R[ROUNDS]
        shuffle(partial_cipher, key)
        ciphertext += partial_cipher
        if (mode == "cbc"):
            key = subkeygen(L[0], key, i)
        if (mode == "counter"):
            key = subkeygen(str(ctr), key_initial, i)
            ctr += 1

    return ciphertext

def decryptCipher(key, ciphertext, mode):
    message = ""
    n = BLOCKSIZE  # 8 bytes (64 bits) per block

    # Split message into 64bit blocks
    ciphertext = [ciphertext[i: i + n] for i in range(0, len(ciphertext), n)]

    lengthOfLastBlock = len(ciphertext[len(ciphertext)-1])

    if ( lengthOfLastBlock < BLOCKSIZE):
        for i in range(lengthOfLastBlock, BLOCKSIZE):
            ciphertext[len(ciphertext)-1] += " "


    # generate a 256 bit key based off the user inputted key
    key = key_256(key)
    key_initial = key
    ctr = 0
    for block in ciphertext:
        #print ("Block: " + block)
        L = [""] * (ROUNDS + 1)
        R = [""] * (ROUNDS + 1)
        L[ROUNDS] = block[0:BLOCKSIZE/2]
        R[ROUNDS] = block[BLOCKSIZE/2:BLOCKSIZE]

        for i in range(ROUNDS, 0, -1):
            round_key = subkeygen(str(i), key, i)
            LL_i = L[i][:BLOCKSIZE/4]
            RL_i = L[i][BLOCKSIZE/4:]

            RR_im = LL_i
            LR_im = xor(RL_i, scramble(RR_im, i, round_key))

            R[i - 1] = LR_im + RR_im
            L[i - 1] = xor(R[i], scramble(R[i - 1], i, round_key))

        partial_message = L[0] + R[0]
        unshuffle(partial_message, key)
        message += partial_message
        if (mode == "cbc"):
            key = subkeygen(L[0], key, i)
        if (mode == "counter"):
            key = subkeygen(str(ctr), key_initial, i)
            ctr += 1

    return message


def key_256(key):
    return hashlib.sha256(key + SECRET).hexdigest()

def subkeygen(s1, s2, i):
    #print ("GENERATING KEY #" + str(i))
    #print ("S1: " + s1)
    #print ("S2: " + s2)
    result = hashlib.sha256(s1 + s2).hexdigest()
    #print ("RESULT: " + result)
    return result

def scramble(x, i, k):
    k = stobin(k)
    x = stobin(str(x))

    if (len(x) == 32) :
        out = ""
        for i in range(8):
            val = bintoint(x[i*4:(i*4) + 4])
            out += bin(sb[i].index(val))[2:].zfill(4)

        out = out[4:len(out)] + out[0:4]
    else:
        out = x

    k = bintoint(k)
    x = bintoint(out)

    res = pow((x * k), i)
    res = itobin(res)

    return bintostr(res)


# xor two strings
def xor(s1, s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))


# string to binary
def stobin(s):
    return ''.join('{:08b}'.format(ord(c)) for c in s)


# binary to int
def bintoint(s):
    return int(s, 2)


# int to binary
def itobin(i):
    return bin(i)


# binary to string
def bintostr(b):
    n = int(b, 2)
    return ''.join(chr(int(b[i: i + 8], 2)) for i in xrange(0, len(b), 8))


if __name__ == "__main__":
    main(sys.argv[1:])
