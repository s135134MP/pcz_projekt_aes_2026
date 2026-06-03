import numpy as np
import matplotlib.pyplot as plt

# Dane przykładowe
ecb_aes_pcz = [668, 814, 1211]
ecb_pycrypto = [0.127, 0.059, 0.061]

ctr_aes_pcz = [412, 589, 565]
ctr_pycrypto = [0.109, 0.078, 0.073]

gcm_aes_pcz = [481, 560, 707]
gcm_pycrypto = [0.431, 0.357, 0.355]

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