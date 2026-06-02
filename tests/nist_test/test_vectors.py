NIST_PLAINTEXT = bytes.fromhex(
  "6bc1bee22e409f96e93d7e117393172a"
  "ae2d8a571e03ac9c9eb76fac45af8e51"
  "30c81c46a35ce411e5fbc1191a0a52ef"
  "f69f2445df4f9b17ad2b417be66c3710"
)

NIST_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
NIST_CTR_COUNTER = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

NIST_VECTORS = {
  "ECB": {
    128: {
      "key": bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
      "plaintext": NIST_PLAINTEXT,
      "ciphertext": bytes.fromhex(
        "3ad77bb40d7a3660a89ecaf32466ef97"
        "f5d3d58503b9699de785895a96fdbaaf"
        "43b1cd7f598ece23881b00e3ed030688"
        "7b0c785e27e8ad3f8223207104725dd4"
      ),
    },
    192: {
      "key": bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
      "plaintext": NIST_PLAINTEXT,
      "ciphertext": bytes.fromhex(
        "bd334f1d6e45f25ff712a214571fa5cc"
        "974104846d0ad3ad7734ecb3ecee4eef"
        "ef7afd2270e2e60adce0ba2face6444e"
        "9a4b41ba738d6c72fb16691603c18e0e"
      ),
    },
    256: {
      "key": bytes.fromhex(
        "603deb1015ca71be2b73aef0857d7781"
        "1f352c073b6108d72d9810a30914dff4"
      ),
      "plaintext": NIST_PLAINTEXT,
      "ciphertext": bytes.fromhex(
        "f3eed1bdb5d2a03c064b5a7e3db181f8"
        "591ccb10d410ed26dc5ba74a31362870"
        "b6ed21b99ca6f4f9f153e7b1beafed1d"
        "23304b7a39f9f3ff067d8d8f9e24ecc7"
      ),
    },
  },
  "CBC": {
    128: {
      "key": bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
      "iv": NIST_IV,
      "plaintext": NIST_PLAINTEXT,
      "ciphertext": bytes.fromhex(
        "7649abac8119b246cee98e9b12e9197d"
        "5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e22229516"
        "3ff1caa1681fac09120eca307586e1a7"
      ),
    },
    192: {
      "key": bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
      "iv": NIST_IV,
      "plaintext": NIST_PLAINTEXT,
      "ciphertext": bytes.fromhex(
        "4f021db243bc633d7178183a9fa071e8"
        "b4d9ada9ad7dedf4e5e738763f69145a"
        "571b242012fb7ae07fa9baac3df102e0"
        "08b0e27988598881d920a9e64f5615cd"
      ),
    },
    256: {
      "key": bytes.fromhex(
        "603deb1015ca71be2b73aef0857d7781"
        "1f352c073b6108d72d9810a30914dff4"
      ),
      "iv": NIST_IV,
      "plaintext": NIST_PLAINTEXT,
      "ciphertext": bytes.fromhex(
        "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
        "9cfc4e967edb808d679f777bc6702c7d"
        "39f23369a9d9bacfa530e26304231461"
        "b2eb05e2c39be9fcda6c19078c6a9d1b"
      ),
    },
  },
  "CTR": {
    128: {
      "key": bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
      "counter_block": NIST_CTR_COUNTER,
      "plaintext": NIST_PLAINTEXT,
      "ciphertext": bytes.fromhex(
        "874d6191b620e3261bef6864990db6ce"
        "9806f66b7970fdff8617187bb9fffdff"
        "5ae4df3edbd5d35e5b4f09020db03eab"
        "1e031dda2fbe03d1792170a0f3009cee"
      ),
    },
    192: {
      "key": bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
      "counter_block": NIST_CTR_COUNTER,
      "plaintext": NIST_PLAINTEXT,
      "ciphertext": bytes.fromhex(
        "1abc932417521ca24f2b0459fe7e6e0b"
        "090339ec0aa6faefd5ccc2c6f4ce8e94"
        "1e36b26bd1ebc670d1bd1d665620abf7"
        "4f78a7f6d29809585a97daec58c6b050"
      ),
    },
    256: {
      "key": bytes.fromhex(
        "603deb1015ca71be2b73aef0857d7781"
        "1f352c073b6108d72d9810a30914dff4"
      ),
      "counter_block": NIST_CTR_COUNTER,
      "plaintext": NIST_PLAINTEXT,
      "ciphertext": bytes.fromhex(
        "601ec313775789a5b7a7f504bbf3d228"
        "f443e3ca4d62b59aca84e990cacaf5c5"
        "2b0930daa23de94ce87017ba2d84988d"
        "dfc9c58db67aada613c2dd08457941a6"
      ),
    },
  },
}


# --- Example Vector ---
# from tests.nist_test.test_vectors import NIST_VECTORS
# print(NIST_VECTORS["ECB"][128]["ciphertext"].hex())
