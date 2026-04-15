from src.aes_pcz import AES_PCZ
from utils.path import path

def main ():
  with open(path("files/key.bin"), "rb") as file:
    key = file.read()
    print(key, len(key) * 8)
  
  key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
  plaintext = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
  
  aes_pcz = AES_PCZ(mode="ECB", key=key)
  result = aes_pcz.encrypt(plaintext)

  print(result.hex())
  # try:
  #   aes_pcz2 = AES_PCZ(mode="Test")
  # except:
  #   print("OK")