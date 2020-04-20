import requests

CONST_CIPHER_H = '21cb831dee353d8fbcbaf36cd82aab980257156247ec0310893dc4b0b2df0a928ecf5382f65c40bd12e5ab12563981650ef327305967d4747a920ca0a867e47e78a7d73e402b1cc99687bbd024a1f55438c5399d4a2a608ad27c197ee3ab5b22d16c0f806ad53f74cdfc3d303079a2434eec374356cd936f0893f37d587601cebfe63a6304700d8de9a57fdd0bf35362'


def call_api(prefix_h,ciphertext_h,postfix_h):
    url = 'http://localhost:5000/cryptoapi'
    post_param = {
        'prefix': prefix_h,
        'ciphertext': ciphertext_h,
        'postfix': postfix_h
    }
    x = requests.post(url, post_param)
    return x.text

def decrypt() -> bytearray:
    length = len(bytes.fromhex(CONST_CIPHER_H))
    ciphertext_b = bytearray()
    prepend = bytearray((length - 1) * b'A')
    append = bytearray(length * b'A')
    current_append = bytearray()
    for i in range(length):
        for j in range(32,123):
            current_append = append + chr(j).encode('utf-8')
            try:
                prepend_h = bytearray.hex(prepend)
                append_h = bytearray.hex(current_append)
                ciphertext_h = call_api(prepend_h,CONST_CIPHER_H,append_h)
                ciphertext_b = bytearray.fromhex(ciphertext_h)
                if ciphertext_b[length-16:length] == ciphertext_b[3*length -16:3*length]:
                    break
            except:
                pass
        prepend = prepend[1:]
        append =  current_append
    return append[length:]



if __name__ == '__main__':
    cleartext_b = decrypt()
    print('Cleartext: ' + bytearray.decode(cleartext_b))
