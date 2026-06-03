import numpy as np
import matplotlib.pyplot as plt

# Dane przykładowe
ecb_aes_pcz = [384, 419, 492]
ecb_pycrypto = [0.093, 0.069, 0.105]

ctr_aes_pcz = [396, 571, 586]
ctr_pycrypto = [0.150, 0.110, 0.109]

gcm_aes_pcz = [482, 547, 673]
gcm_pycrypto = [0.435, 0.367, 0.373]

labels = [
    "128", "192", "256",
    "128", "192", "256",
    "128", "192", "256"
]

aes_pcz = (
    ecb_aes_pcz +
    ctr_aes_pcz +
    gcm_aes_pcz
)

pycrypto = (
    ecb_pycrypto +
    ctr_pycrypto +
    gcm_pycrypto
)

x = np.arange(len(labels))
width = 0.35

plt.figure(figsize=(12, 5))

plt.bar(x - width/2, aes_pcz, width, label="AES_PCZ")
plt.bar(x + width/2, pycrypto, width, label="PyCryptodome")

plt.xticks(x, labels)

# Podpisy grup
plt.text(1, -20, "ECB", ha="center")
plt.text(4, -20, "CTR", ha="center")
plt.text(7, -20, "GCM", ha="center")

plt.axvline(2.5, color='gray', linestyle='--')
plt.axvline(5.5, color='gray', linestyle='--')

# plt.yscale('log')

plt.ylabel("Czas [ms]")
plt.xlabel("Rozmiar klucza")
plt.legend()

plt.tight_layout()
plt.show()