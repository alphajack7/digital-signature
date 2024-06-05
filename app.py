from flask import Flask,render_template,request,send_file
import os
from http import HTTPStatus
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import shutil

app=Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/sign',methods=['POST','PUT','DELETE'])
def sign():
    
    return render_template("switch.html")

#chosing b/w private presrnt or not

@app.route('/switch',methods=['POST','PUT','DELETE'])
def switch():
    isPrivateKey=request.form['isPrivateKey']
    return render_template("signing.html",isPrivateKey=isPrivateKey)

@app.route('/signature',methods=['POST','PUT','DELETE'])
def signature():
    afile=request.files['afile']
    isPrivateKey=request.form['isPrivateKey']
    file_path='uploads/'+afile.filename
    afile.save(file_path)
    if isPrivateKey=="True":
        private_key_file=request.files['private_key']
        private_key_path='uploads/'+ private_key_file.filename
        private_key_file.save(private_key_path)
        #handling pem file
        password = b'alpha'
        private_key=load_private_key_from_pem_file(private_key_path,password)

        signature=sign_file(file_path,private_key)

        #saving signature
        signature_filepath = 'downloads/signature.bin'
        save_signature(signature, signature_filepath)
        #deleting user files
        os.remove(file_path),os.remove(private_key_path)
        return send_file(signature_filepath,as_attachment=True),os.remove(signature_filepath)

    
    else:
        private_key, public_key = generate_key_pair()
        #signing  occurs in below func
        signature=sign_file(file_path,private_key)
        
        #saving the files to let user download it....delete krna hoga last me
        public_key_filepath= 'downloads/public_key.pem'
        save_public_key(public_key, public_key_filepath)

        private_key_filepath='downloads/private_key.pem'
        password= 'alpha'
        save_private_key(private_key,private_key_filepath,password)

    #removing the uploaded file jo sign krna tha
    os.remove(file_path)
    signature_filepath = 'downloads/signature.bin'
    save_signature(signature, signature_filepath)

    return render_template("download.html")  

@app.route('/verification',methods=['POST','PUT','DELETE'])
def verification():
    
    return render_template("verification.html")

@app.route('/verify',methods=['POST','PUT','DELETE'])
def verify():
    vfile=request.files['vfile']
    file_path='uploads/'+ vfile.filename
    vfile.save(file_path)
    
    key_file=request.files['key_file']
    key_path='uploads/'+key_file.filename
    key_file.save(key_path)

    signed=request.files['signature']
    signature_filename='uploads/'+signed.filename
    signed.save(signature_filename)
    #conerting in binary signature
    with open(signature_filename, "rb") as signature_file:
        signature = signature_file.read()

    public_key=load_public_key_from_pem_file(key_path)
    result=verify_signature(file_path,signature,public_key)
    os.remove(file_path),os.remove(key_path),os.remove(signature_filename)
    return render_template("output.html",result=result)

@app.route('/download',methods=['POST','PUT','DELETE'])
def download():
    #making zip file using shutil lib
    shutil.make_archive('signature_and_keys', 'zip', 'downloads')
    os.remove('downloads/signature.bin'),os.remove('downloads/private_key.pem'),os.remove('downloads/public_key.pem')
    return send_file('signature_and_keys.zip',as_attachment=True),os.remove('signature_and_keys.zip')

def load_public_key_from_pem_file(filename):
    with open(filename, "rb") as file:
        pem_data = file.read()
    public_key = serialization.load_pem_public_key(pem_data, backend=default_backend())
    if not isinstance(public_key, RSAPublicKey):
        raise ValueError("Invalid public key format.")
    return public_key

def load_private_key_from_pem_file(pem_file_path, password):
    try:
        with open(pem_file_path, 'rb') as pem_file:
            pem_data = pem_file.read()

        private_key = serialization.load_pem_private_key(
            pem_data,
            password=password,
            backend=default_backend()
        )

        return private_key

    except Exception as e:
        print(f"An error occurred while loading the private key: {e}")
        return None

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
        return 'Signature is valid'
    except:
        print("Signature is NOT valid.")
        return 'Signature is not valid. File may be manipulated'
@app.route('/keygen', methods=['POST','PUT','DELETE'])
def new_key_pair():
    private_key,public_key=generate_key_pair()
    save_private_key(private_key,'generatedKeys/private_key.pem','alpha')
    save_public_key(public_key,'generatedKeys/public_key.pem')

    shutil.make_archive('key_pair', 'zip', 'generatedKeys')
    os.remove('generatedKeys/private_key.pem'),os.remove('generatedKeys/public_key.pem')
    return send_file('key_pair.zip',as_attachment=True),os.remove('key_pair.zip')


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        
    )
    public_key = private_key.public_key()
    return private_key, public_key

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

def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, "wb") as file:
        file.write(pem)

def save_private_key(private_key, filename,password):
    private_key_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode() if password else None)
    )

    # Write the private key to a file
    with open(filename, "wb") as key_file:
        key_file.write(private_key_data)
   
def save_signature(signature,filename):
    with open(filename,'wb') as file:
        file.write(signature)

if __name__== "__main__":
    app.run(debug=True)
