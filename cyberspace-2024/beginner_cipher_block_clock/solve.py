import Crypto.Cipher.AES
import Crypto.Random
from Crypto.Util.Padding import unpad

# key and iv are swapped in the challenge, so actually the same iv is used twice

key0 = bytes.fromhex(
    "b800f4bfd38030ff3ed82560a11e9ef67e9c3529ab52938c9458c7d8602d7a51")
ct0 = bytes.fromhex(
    "5abb8490d872f101dcd89af421958c54204642e7d0f96a6393759f45c9630e9b6b16e87e9a96d00044fed28e295163c5fc6ed2a59839c4be433f74f8614fce54")

key1 = bytes.fromhex(
    "667a704a5b4730f1954692ea0d924a7f9ea8fe478415fa2aad8ae59604f7950e")
ct1 = bytes.fromhex("6570f5f9b8c43a6622b1b4abc037fa09cd82be1570ec1f262538eff17374161673276cb82304676f7a37b658ae9c997e6c5b17987928f2dd292cc7ec2fcc6b9ed22994616848ee716bcf6142e0689b3aa1c5abbcd3c316a3329f8f51f378cf6e10cbeeefe54a3611dc878d23c606e78e114da6816fa384605f75f26299a1d9dca83ded23b1f7cdd1e8acced6fcb199fda34a3bc26d2e88bc3ce01466a74e44744e5a0e65cab25745c64f178cd7680e2b3c993286e236cd3c55e22cdd71aac279c749ddcf4f8137867b682c29f10d754da4f6b22603531a4885a5144f012c8f23")

# --- Recover iv ---

pl1 = b"Lookie here, someone thinks that this message is unsafe, well I'm sorry to be the bearer of bad news but tough luck; the ciphertext is encrypted with MILITARY grade encryption. You're done kiddo."

cipher1 = Crypto.Cipher.AES.new(key1, Crypto.Cipher.AES.MODE_CBC, pl1[:16])
iv = cipher1.decrypt(ct1[:16])
print(iv)

# --- Recover flag ---

cipher0 = Crypto.Cipher.AES.new(key0, Crypto.Cipher.AES.MODE_CBC, iv)
flag = unpad(cipher0.decrypt(ct0), 32)
print(flag)
