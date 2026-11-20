"""Make a new witness key file. Prints only the PUBLIC key.

  python -m witness.keygen --out keys/app.seed
"""
import argparse

from .keys import write_new_key_file


def main():
    parser = argparse.ArgumentParser(description="Create a witness seed file; prints the public key only")
    parser.add_argument("--out", required=True, help="where to write the new seed file (must not exist)")
    args = parser.parse_args()
    public_key = write_new_key_file(args.out)
    print("seed written to", args.out, "(keep it private)")
    print("public key:", public_key)


if __name__ == "__main__":
    main()
