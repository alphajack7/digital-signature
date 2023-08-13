from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, "wb") as file:
        file.write(pem)

def sign_file(file_path, private_key):
    with open(file_path, "rb") as file:
        message = file.read()
    try:
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
    )
        print("Signed succesfully public key and signature has been saved in file")
    except:
        print("Signing unsuccessful")
    return signature

def save_signature(signature, filename):
    with open(filename, "wb") as file:
        file.write(signature)

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

    # Step 1: Generate Key Pair (Private Key and Public Key)
    private_key, public_key = generate_key_pair()
    #save the public key
    public_key_filename= 'public_key.pem'
    save_public_key(public_key, public_key_filename)

    # Step 2: Simulate file path
    file_path = "abcd.txt"

    # Step 3: Generate Signature using Private Key
    signature = sign_file(file_path, private_key)

    #save the signature
    signature_filename = "signature.bin"
    save_signature(signature, signature_filename)
    
    
    # Step 4: Verify Signature using Public Key
    #verify_signature(file_path, signature, public_key)
