import sys
import rsa
import hashlib
import binascii
from datetime import datetime, timezone
# given an array of bytes, return a hex reprenstation of it
def bytesToString(data):
    return binascii.hexlify(data)

# given a hex reprensetation, convert it to an array of bytes
def stringToBytes(hexstr):
    return binascii.a2b_hex(hexstr)

def loadWallet(filename):
    with open(filename, mode='rb') as file:
        keydata = file.read()
    privkey = rsa.PrivateKey.load_pkcs1(keydata)
    pubkey = rsa.PublicKey.load_pkcs1(keydata)
    return pubkey, privkey

# save the wallet to a file
def saveWallet(pubkey, privkey, filename):
    # Save the keys to a key format (outputs bytes)
    pubkeyBytes = pubkey.save_pkcs1(format='PEM')
    privkeyBytes = privkey.save_pkcs1(format='PEM')
    # Convert those bytes to strings to write to a file (gibberish, but a string...)
    pubkeyString = pubkeyBytes.decode('ascii')
    privkeyString = privkeyBytes.decode('ascii')
    # Write both keys to the wallet file
    with open(filename, 'w') as file:
        file.write(pubkeyString)
        file.write(privkeyString)
    return

def main(args):
    if args[1] == 'name':
        print("BoffCoin")
    elif args[1] == 'genesis':
        with open("block_0.txt", 'w') as f:
            f.write("If there's a will, there's a way - someone")
        print("Genesis block created in 'block_0.txt'")
    elif args[1] == 'generate':
        # generate RSA key pair for a wallet
        filepath = args[2]
        (pubkey, privkey) = rsa.newkeys(1024)
        print(pubkey)
        print(privkey)
        saveWallet(pubkey, privkey, filepath)            
        print(f"New wallet generated at {filepath}")
    elif args[1] == 'address':
        filepath = args[2]
        pubkey, privkey = loadWallet(filepath)

        hex_n = format(pubkey.n, 'x')
        hex_e = format(pubkey.e, 'x')
        if len(hex_e) % 2 == 1:  # if odd length
            hex_e = '0' + hex_e  # pad with leading zero
        hex_str = hex_n + hex_e
        tag = hashlib.sha256(stringToBytes(hex_str)).hexdigest()[:16]
        print(tag)
    elif args[1] == 'fund':
        special_id = "bank"
        tag = args[2]
        amount = args[3]
        filepath = args[4]
        transaction_time = datetime.now()

        with open(filepath, 'w') as f:
            f.write(f"From: {special_id}\n")
            f.write(f"To: {tag}\n")
            f.write(f"Amount: {amount}\n")
            f.write(f"Date (EST): {transaction_time}")
        print(f"Funded wallet {tag} with {amount} BoffCoin on {transaction_time}")

if __name__ == "__main__":
    main(sys.argv)