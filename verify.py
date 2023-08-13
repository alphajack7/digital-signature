from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

def load_public_key_from_pem_file(filename):
    with open(filename, "rb") as file:
        pem_data = file.read()
    public_key = serialization.load_pem_public_key(pem_data, backend=default_backend())
    if not isinstance(public_key, RSAPublicKey):
        raise ValueError("Invalid public key format.")
    return public_key

def verify_signature(file_path, signature, public_key):
    with open(file_path, "rb") as file:
        message = file.read()
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is valid.")
    except: 
        print("Signature is NOT valid.")

if __name__ == "__main__":
    # Step 1: Load Public Key from PEM file
    public_key_filename = "public_key.pem"
    public_key = load_public_key_from_pem_file(public_key_filename)

    # Step 2: Simulate file path
    file_path = "abcd.txt"

    # Step 3: Read Signature from file or other sources
    # (In a real-world scenario, you'd have to obtain the signature from elsewhere)
    signature_filename = "signature.bin"
    with open(signature_filename, "rb") as signature_file:
        signature = signature_file.read()

    # Step 4: Verify Signature using Public Key
    verify_signature(file_path, signature, public_key)
