from Crypto.Cipher import AES
from flask import Flask, request

CONST_KEY_B = b'YELLOW SUBMARINE'

CONST_ROOT_REPLY = '''<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>200 OK</title>
<h1>Find the crypto API under /cryptoapi</h1>\n'''

CONST_INVALID_INPUT = '''<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>400 Invalid Input</title>
<h1>Invalid Input</h1>
<p>The API requires the parameters: prefix, ciphertext, and postfix.</p>
<p>Furthermore, parameters have to have a certain format, see API spec for details.</p>\n'''

app = Flask(__name__)

def ecb_encrypt(cleartext_b: bytes ,key_b: bytes) -> bytes:
    cipher = AES.new(key_b, AES.MODE_ECB)
    return cipher.encrypt(cleartext_b)

def ecb_decrypt(ciphertext_b: bytes ,key_b: bytes) -> bytes:
    cipher = AES.new(key_b, AES.MODE_ECB)
    return cipher.decrypt(ciphertext_b)

def padded_oracle(prepend_b: bytes,  ciphertext_b: bytes, append_b: bytes) -> bytes:
    plain_b = ecb_decrypt(ciphertext_b, CONST_KEY_B)
    padded_plain_b = prepend_b + plain_b + append_b
    return ecb_encrypt(padded_plain_b, CONST_KEY_B)

def valid_params(prepend_h, cipher_h, append_h):
    try:
        prepend_b = bytes.fromhex(prepend_h)
        cipher_b = bytes.fromhex(cipher_h)
        append_b = bytes.fromhex(append_h)
    except:
        raise ValueError("Input not valid")
    return (prepend_b,cipher_b,append_b)

@app.errorhandler(400)
def invalid_input(error):
    return CONST_INVALID_INPUT, 400

@app.route("/cryptoapi", methods=["POST"])
def encrypt():
    try:
        inp_bytes = valid_params(request.form['prefix'],
                                 request.form['ciphertext'],
                                 request.form['postfix'])
        if ((( len(inp_bytes[0])
            + len(inp_bytes[1])
            + len(inp_bytes[2])) % 16 != 0)
            or
            (len(inp_bytes[1]) == 0)):
            raise ValueError("Input not valid")
    except:
        return invalid_input('invalid input')
    result_b = padded_oracle(inp_bytes[0], inp_bytes[1], inp_bytes[2])
    return bytes.hex(result_b)



@app.route("/")
def hello():
    return CONST_ROOT_REPLY

if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=True)
