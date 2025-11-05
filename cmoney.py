import sys
import rsa
import hashlib
import binascii
from datetime import datetime
import os 
import random

def hashFile(filename):
    h = hashlib.sha256()
    with open(filename, 'rb', buffering=0) as f:
        for b in iter(lambda : f.read(128*1024), b''):
            h.update(b)
    return h.hexdigest()

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

# S transferred x to D on w
def readline(line):
    line = line.strip()
    sender, _, amount, _, receiver, _, *date = line.split(" ")
    return sender, amount, receiver, date

def getBalance(tag):
    balance = 0
    # check blockchain
    cur_num = 1
    # iterate over blocks while the existing the files
    while os.path.exists(f"block_{cur_num}.txt"):
        with open(f"block_{cur_num}.txt") as f:
            num_lines = sum(1 for _ in f)
            line_list = [line for line in f]
            for i, line in enumerate(line_list):
                # ignore previous block tag and nonce at the bottom
                if i == 0 or i == num_lines:
                    continue
                # read transaction
                sender, amount, receiver, date = readline(line)
                if sender == tag:
                    balance -= int(amount)
                if receiver == tag:
                    balance += int(amount)
        cur_num += 1

    # iterate over lines in the mempool
    if not os.path.exists(mempool_filename):
        with open(mempool_filename, 'r') as f:
            for line in f:
                # read transaction
                sender, amount, receiver, date = readline(line)
                if sender == tag:
                    balance -= int(amount)
                if receiver == tag:
                    balance += int(amount)
    return balance

def getTag(pubkey):
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
        tag = getTag(pubkey)
        print(tag)
    elif args[1] == 'fund':
        special_id = "bank"
        tag = args[2]
        amount = args[3]
        filepath = args[4]
        transaction_time = datetime.now()
        
        written_string = "From: {}\nTo: {}\nAmount: {}\nDate: {}".format(special_id, tag, amount, transaction_time)

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
        source_tag = getTag(pubkey)

        written_string = "From: {}\nTo: {}\nAmount: {}\nDate: {}\n".format(source_tag, dest_wallet_tag, amount, transaction_time)
        signature = hashlib.sha256(written_string.encode()).hexdigest()
        with open(filepath, 'w') as f:
            f.write(written_string + signature)
        print("Transferred {} from {} to {} and statement to {} on {}".format(amount, source_wallet_fn, dest_wallet_tag, filepath, transaction_time))
    elif args[1] == "balance":
        tag = args[2]
        print(getBalance(tag))
    elif args[1] == 'verify':
        wallet = args[2]
        transaction = args[3]
        
        pubkey, privkey = loadWallet(wallet)
        tag = getTag(pubkey)

        balance = getBalance(tag)

        sender, receiver, amount, date = 0, 0, 0, 0
        # read the balance from the file
        with open(transaction, 'r') as f:
            
            h = hashlib.sha256()
            lines = [line for line in f]
            num_lines = len(lines)
            for i, line in enumerate(lines):

                # check for auto case
                if i == 0:
                    _, sender = line.split(" ")
                    sender = sender.strip()
                    # auto accept
                    if sender == "bank":
                        sender = "bank"

                if i == 1:
                    _, receiver = line.split(" ")
                    receiver = receiver.strip()
                # checking balance
                if i == 2:
                    _, amount = line.split(" ")
                    amount = int(amount)
                    if sender == 'bank':
                        continue
                    if balance - amount < 0:
                        print("The transaction in file {} with wallet {} is not valid due to insufficient funds in the wallet".format(transaction, wallet))
                        return
                if i == 3:
                    _, *date = line.split(" ")
                    date = " ".join(date).strip()
                
                # checking hash
                if i == num_lines - 1:
                    if sender == 'bank':
                        continue
                    hash = h.hexdigest()
                    if line.strip() != hash:
                        print("The transaction in file {} with wallet {} is not valid due to not matching hashes".format(transaction, wallet))
                        return
                else:
                    h.update(line.encode())
        
        # write to mempool
        with open(mempool_filename, 'a') as f:
            f.write("{} transferred {} to {} on {}\n".format(sender, amount, receiver, date))
        print("The transaction in file {} with wallet {} is valid and was written to the mempool".format(transaction, wallet))
    elif args[1] == 'mine':
        difficulty = int(args[2])

        cur_num = 0
        while os.path.exists(f"block_{cur_num}.txt"):
            cur_num += 1

        full_string = ""
        
        # hash of previous block
        full_string += hashFile(f"block_{cur_num - 1}.txt") + "\n"

        # read in mempool
        with open(mempool_filename, "r") as f:
            for line in f:
                full_string += line
        
        nonce = -1
        hash_val = None
        # try nonces
        while True:
            nonce = int(random.getrandbits(32))
            hash_val = hashlib.sha256((full_string + f"nonce: {nonce}").encode()).hexdigest()
            # check against difficulty
            if hash_val[:difficulty] == "0" * difficulty:
                break
        
        with open(f"block_{cur_num}.txt", 'w') as f:
            f.write((full_string + f"nonce: {nonce}"))
        
        # clear the mempool
        open(mempool_filename, 'w').close()
        print(f"Mempool transactions moved to block_{cur_num}.txt and mined with difficulty {difficulty} and nonce {nonce}")
    elif args[1] == 'validate':
        cur_num = 1
        while os.path.exists(f"block_{cur_num}.txt"):
            # check previous hash
            with open(f"block_{cur_num}.txt") as f:
                prev_hash = f.readline().strip()
                if prev_hash != hashFile(f"block_{cur_num - 1}.txt"):
                    print("False")
                    return
            cur_num += 1
        print("True")

    



if __name__ == "__main__":
    main(sys.argv)