#Import packages
import chifragge_component
from ecies import encrypt
from coincurve import PrivateKey

#coincurve key
k1 = PrivateKey.from_int(int("2888f53454fdafe8777c619a99a355c68e2fdbe3c3283a8833a7b7f32d10f35", 16))
pkey = k1.public_key.format(False).hex()

chiffrage = chiffragge_component.Chiffrage()
chiffrage.encrypt("Floryan", "ECIES_PublicKey.key")

message = b'Floryan'
crypted_message = encrypt(pkey,message)
print("Encrypted:", binascii.hexlify(crypted_message))
