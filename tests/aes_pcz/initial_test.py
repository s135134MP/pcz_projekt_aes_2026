from src.aes_pcz import AES_PCZ
from utils.path import path

def main ():
  key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
  plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
  
  aes_pcz = AES_PCZ(mode="ECB", key=key)
  encrypt_result = aes_pcz.encrypt(plaintext)
  decrypt_result = aes_pcz.decrypt(encrypt_result)

  if(decrypt_result == plaintext):
    print("PASSED:", decrypt_result.hex(), "==", plaintext.hex());
  else:
    print("FAILED:", decrypt_result.hex(), "!=", plaintext.hex());

  # try:
  #   aes_pcz2 = AES_PCZ(mode="Test")
  # except:
  #   print("OK")