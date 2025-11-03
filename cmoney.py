import sys

def main(args):
    if sys.argv[1] == 'name':
        print("BoffCoin")
    elif sys.argv[1] == 'genesis':
        with open("block_0.txt", 'w') as f:
            f.write("If there's a will, there's a way - someone")
        print("Genesis block created in 'block_0.txt'")
    elif sys.argv[1] == 'generate':

        # generate RSA key pair for a wallet
        print("New wallet generated in ")

if __name__ == "__main__":
    try:
        main(sys.argv)
    except:
        print("Something went wrong...")
    