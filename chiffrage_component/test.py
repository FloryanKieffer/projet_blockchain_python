#Import packages
import binascii
import chiffrage_component
from ecies import encrypt, decrypt
from coincurve import PrivateKey

#coincurve key
k1 = PrivateKey.from_int(int("2888f53454fdafe8777c619a99a355c68e2fdbe3c3283a8833a7b7f32d10f35", 16))
pkey = k1.public_key.format(False).hex()
chiffrage = chiffrage_component.Chiffrage()
chiffrage.encrypt("Floryan", "ECIES_PublicKey.key")
print()

crypted_message = chiffrage.getEncryptedText()
print("Encrypted:", crypted_message)
prvkey = k1.to_hex()
decrypted_message = decrypt(prvkey,bytes(crypted_message, 'utf-8'))
print("Decrypted:", decrypted_message)
