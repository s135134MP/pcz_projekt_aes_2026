from src.aes_pcz import AES_PCZ
from utils.path import path

def main ():
  # Testing the AES ECB mode
  key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
  plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
  
  aes_pcz = AES_PCZ(mode="ECB", key=key)
  encrypt_result = aes_pcz.encrypt(plaintext)
  decrypt_result = aes_pcz.decrypt(encrypt_result)

  if(decrypt_result == plaintext):
    print("AES_ECB PASSED:", decrypt_result.hex(), "==", plaintext.hex());
  else:
    print("AES_ECB FAILED:", decrypt_result.hex(), "!=", plaintext.hex());

  # Testing the AES CTR mode with fixed nonce and counter
  plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
  expected_ciphertext = bytes.fromhex("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee")
  key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
  nonce = bytes.fromhex("f0f1f2f3f4f5f6f7")
  counter = int.from_bytes(bytes.fromhex("f8f9fafbfcfdfeff"), "big") 
  
  aes_pcz2 = AES_PCZ(mode="CTR", key=key) 
  (encrypt_result, nonce) = aes_pcz2.encrypt(plaintext, counter, nonce)

  if(encrypt_result == expected_ciphertext):
    print("AES_CTR PASSED:", encrypt_result.hex())
  else:
    print("AES_CTR FAILED:", encrypt_result.hex())



  # try:
  #   aes_pcz2 = AES_PCZ(mode="Test")
  # except:
  #   print("OK")