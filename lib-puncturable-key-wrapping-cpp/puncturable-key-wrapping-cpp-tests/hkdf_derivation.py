from cryptography.hazmat.primitives.kdf import hkdf
from cryptography.hazmat.primitives import hashes

# for (h)pprf construction test

right = b"r"
left = b"l"
out = b"o"
if __name__ == '__main__':
    evals = [right, left, left, right, left, left]
    derived = b"\x00" * 16
    for eval in evals:
        derived = hkdf.HKDF(hashes.SHA256(), 16, salt=None, info=eval).derive(derived)
    derived = hkdf.HKDF(hashes.SHA256(), 16, salt=None, info=out).derive(derived)

    print('\\x'.join('{:02x}'.format(x) for x in derived))