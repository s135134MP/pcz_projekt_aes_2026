from utils.path import path
from src.aes_pcz import AES_PCZ

class TestCase:
  def __init__(self, type="ENCRYPT", mode = "ECB", count = 0, key = "", iv = "", plaintext = "", ciphertext = ""):
    self.type = type
    self.mode = mode
    self.count = count
    self.key = key
    self.iv = iv
    self.plaintext = plaintext
    self.ciphertext = ciphertext

  def test(self, print_result = False):
    key_bytes = bytes.fromhex(self.key)
    iv_bytes = bytes.fromhex(self.iv)

    aes = AES_PCZ(mode=self.mode, key=key_bytes)

    if self.type == "ENCRYPT":
      plain_bytes = bytes.fromhex(self.plaintext)

      result = aes.encrypt(bytes=plain_bytes, iv=iv_bytes, unified_return=True, add_pad=False)

      if(result[0].hex() == self.ciphertext):
        if print_result:
          print("\t" + self.count + ": PASSED")
        return True
      else:
        if print_result:
          print("\t" + self.count + ": FAILED " + result[0].hex() + " " + self.ciphertext)
    else:
      cipher_bytes = bytes.fromhex(self.ciphertext)
      result = aes.decrypt(bytes=cipher_bytes, iv=iv_bytes, pad_data=False)

      if(result.hex() == self.plaintext):
        if print_result:
          print("\t" + self.count + ": PASSED")
        return True
      else:
        if print_result:
          print("\t" + self.count + ": FAILED " + result.hex() + " " + self.plaintext)

    return False

class KATTestUnit: 
  def __init__(self, name, path, key_size, mode):
    self.name = name
    self.file = path
    self.key_size = key_size
    self.mode = mode
    self.encrypt_cases: list[TestCase] = []
    self.passed_encrypt_cases = 0
    self.decrypt_cases: list[TestCase] = []
    self.passed_decrypt_cases = 0

    self._parse_rsp_file()
  
  def _create_test_case(self, case, type):
    testCase = TestCase(mode=self.mode, type=type)

    testCase.count = case["COUNT"]
    testCase.key = case["KEY"]
    testCase.plaintext = case["PLAINTEXT"]
    testCase.ciphertext = case["CIPHERTEXT"]

    if "IV" in case:
      testCase.iv = case["IV"]
    
    return testCase

  def _parse_rsp_file(self):
    current_section = None
    current_case = None
  
    with open(self.file, "r") as f:
      for line in f:
        line = line.strip()

        if not line or line.startswith("#"):
          if current_case:
            testCase = self._create_test_case(current_case, current_section)

            if current_section == "ENCRYPT":
              self.encrypt_cases.append(testCase)
            else:
              self.decrypt_cases.append(testCase)
            current_case = None
          continue

        if line.startswith("[") and line.endswith("]"):
          current_section = line[1:-1]
          continue

        if "=" in line:
          key, value = map(str.strip, line.split("=", 1))

          if current_case is None:
            current_case = {}

          current_case[key] = value

    if current_case:
      testCase = self._create_test_case(current_case, current_section)

      if current_section == "ENCRYPT":
        self.encrypt_cases.append(testCase)
      else:
        self.decrypt_cases.append(testCase)
    
  def run_tests(self, print_step_result = False):
    print("=== ENCRYPT CASES: ")

    for case in self.encrypt_cases:
      result = case.test()

      if(result):
        self.passed_encrypt_cases = self.passed_encrypt_cases + 1

    count = len(self.encrypt_cases)

    percentage = self.passed_encrypt_cases / count * 100;
    
    print("\tPASSED TESTS: " + str(self.passed_encrypt_cases) + " / " + str(count) + " " + str(percentage) + "%")    

    print("=== DECRYPT CASES: ")

    for case in self.decrypt_cases:
      result = case.test(print_result=print_step_result)

      if(result):
        self.passed_decrypt_cases = self.passed_decrypt_cases + 1

    count = len(self.decrypt_cases)

    percentage = self.passed_decrypt_cases / count * 100;

    print("\tPASSED TESTS: " + str(self.passed_decrypt_cases) + " / " + str(count) + " " + str(percentage) + "%")    
    
    if self.passed_decrypt_cases + self.passed_encrypt_cases == len(self.encrypt_cases) + len(self.decrypt_cases):
      return True
    else:
      return False

def main():
  # MODES = ["CBC"]
  # KEY_SIZES = [128]
  # TEST_TYPES = ["GFSbox"]

  MODES = ["ECB", "CBC"]
  TEST_TYPES = ["GFSbox", "KeySbox", "VarTxt", "VarKey"]
  KEY_SIZES = [128, 192, 256]
  
  kat_tests = []

  for mode in MODES:
    for test_type in TEST_TYPES:
      for key_size in KEY_SIZES:
        name = mode + "-" + str(key_size) + " " + test_type
        file_name = mode + test_type + str(key_size) + ".rsp"

        test = KATTestUnit(name=name, path=path("files/nist/kat/" + file_name), key_size=key_size, mode=mode)

        kat_tests.append(test)

  passed_count = 0

  for test in kat_tests:
    print("=============================")
    print(test.name)
    result = test.run_tests(print_step_result=False)
    if result:
      passed_count = passed_count + 1

  print("=============================")
  percentage = passed_count / len(kat_tests) * 100
  print("PASSED TEST FILES: " + str(passed_count) + " / " + str(len(kat_tests)) + " " + str(percentage) + "%")    

    