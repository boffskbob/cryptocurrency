import sys
import rsa
import hashlib
import binascii
from datetime import datetime
import os 
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

def get_tag(pubkey):
    hex_n = format(pubkey.n, 'x')
    hex_e = format(pubkey.e, 'x')
    if len(hex_e) % 2 == 1:
        hex_e = '0' + hex_e
    hex_str = hex_n + hex_e
    tag = hashlib.sha256(stringToBytes(hex_str)).hexdigest()[:16]
    return tag

mempool_filename = "mempool.txt"

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
        saveWallet(pubkey, privkey, filepath)            
        print(f"New wallet generated at {filepath}")
    elif args[1] == 'address':
        filepath = args[2]
        pubkey, privkey = loadWallet(filepath)
        tag = get_tag(pubkey)
        print(tag)
    elif args[1] == 'fund':
        special_id = "bank"
        tag = args[2]
        amount = args[3]
        filepath = args[4]
        transaction_time = datetime.now()
        
        written_string = "From: {}\nTo: {}\nAmount: {}\nDate (EST): {}".format(special_id, tag, amount, transaction_time)

        with open(filepath, 'w') as f:
            f.write(written_string)
        print(f"Funded wallet {tag} with {amount} BoffCoin on {transaction_time}")
    elif args[1] == 'transfer':
        source_wallet_fn = args[2]
        dest_wallet_tag = args[3]
        amount = args[4]
        filepath = args[5]
        transaction_time = datetime.now()

        pubkey, privkey = loadWallet(source_wallet_fn)
        source_tag = get_tag(pubkey)

        written_string = "From: {}\nTo: {}\nAmount: {}\nDate (EST): {}".format(source_tag, dest_wallet_tag, amount, transaction_time)
        signature = hashlib.sha256(written_string.encode()).hexdigest()
        with open(filepath, 'w') as f:
            f.write(written_string + "\n" + signature)
        print("Transferred {} from {} to {} and statement to {} on {}".format(amount, source_wallet_fn, dest_wallet_tag, filepath, transaction_time))
    elif args[1] == "balance":
        # check blockchain
        cur_num = 1
        # iterate over blocks while they existin the files
        while os.path.exists(f"block_{cur_num}.txt"):
            with open(f"block_{cur_num}.txt") as f:
                for i, line in enumerate(f):
                    if i == 0 or i == len(f):
                        continue
                    # read transaction

                # read the block
        # iterate over lines in the mempool
        with open(mempool_filename, 'r') as f:
            for line in f:
                # read transaction



if __name__ == "__main__":
    main(sys.argv)