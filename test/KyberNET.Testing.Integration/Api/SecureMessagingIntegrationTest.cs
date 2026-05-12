namespace KyberNET.Testing.Integration.Api;

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using KyberNET.Api;
using KyberNET.Keys;
using Microsoft.VisualStudio.TestTools.UnitTesting;

public class SecureMessagingIntegrationTest
{
    [TestClass]
    public class Roundtrip
        : SecureMessagingIntegrationTest
    {
        [TestMethod, TestCategory("Integration"), TestCategory("SecureMessaging")]
        public void DecryptsCorrectlyWhenMlKem768()
        {
            // Arrange
            var bobKeyPair = MlKem768.GenerateKeyPair();
            var publicKeyBytes = bobKeyPair.EncapsulationKey.FullBytes;
            var privateKeyBytes = bobKeyPair.DecapsulationKey.FullBytes;

            // Act
            var bobPublicKey = KyberEncapsulationKey.FromBytes(publicKeyBytes);
            var result = bobPublicKey.Encapsulate();

            var aliceSharedSecret = result.SharedSecretKey;
            var kemCipherText = result.CipherText;

            var message = "Attack at dawn";
            var nonce = RandomNumberGenerator.GetBytes(12);
            var plaintext = Encoding.UTF8.GetBytes(message);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16];

            using (var aes = new AesGcm(aliceSharedSecret, 16))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag);
            }

            var kemBytes = kemCipherText.FullBytes;
            var encryptedPayload = (byte[])[.. ciphertext, .. tag];

            var bobPrivateKey = KyberDecapsulationKey.FromBytes(privateKeyBytes);
            var receivedKemCipherText = KyberCipherText.FromBytes(kemBytes);
            var bobSharedSecret = bobPrivateKey.Decapsulate(receivedKemCipherText);

            var receivedCiphertext = encryptedPayload[..^16];
            var receivedTag = encryptedPayload[^16..];
            var decryptedBytes = new byte[receivedCiphertext.Length];

            using (var aes = new AesGcm(bobSharedSecret, 16))
            {
                aes.Decrypt(nonce, receivedCiphertext, receivedTag, decryptedBytes);
            }

            var decryptedMessage = Encoding.UTF8.GetString(decryptedBytes);

            // Assert
            Assert.AreEqual(message, decryptedMessage);
            CollectionAssert.AreEqual(aliceSharedSecret, bobSharedSecret);
        }

        [TestMethod, TestCategory("Integration"), TestCategory("SecureMessaging")]
        public void DecryptsCorrectlyWhenMlKem512()
        {
            // Arrange
            var bobKeyPair = MlKem512.GenerateKeyPair();
            var publicKeyBytes = bobKeyPair.EncapsulationKey.FullBytes;
            var privateKeyBytes = bobKeyPair.DecapsulationKey.FullBytes;

            // Act
            var bobPublicKey = KyberEncapsulationKey.FromBytes(publicKeyBytes);
            var result = bobPublicKey.Encapsulate();

            var message = "PQ encrypted message via ML-KEM-512.";
            var nonce = RandomNumberGenerator.GetBytes(12);
            var plaintext = Encoding.UTF8.GetBytes(message);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16];

            using (var aes = new AesGcm(result.SharedSecretKey, 16))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag);
            }

            var kemBytes = result.CipherText.FullBytes;
            var encryptedPayload = (byte[])[.. ciphertext, .. tag];

            var bobPrivateKey = KyberDecapsulationKey.FromBytes(privateKeyBytes);
            var receivedKem = KyberCipherText.FromBytes(kemBytes);
            var bobSecret = bobPrivateKey.Decapsulate(receivedKem);

            var decryptedBytes = new byte[encryptedPayload.Length - 16];

            using (var aes = new AesGcm(bobSecret, 16))
            {
                aes.Decrypt(nonce, encryptedPayload[..^16], encryptedPayload[^16..], decryptedBytes);
            }

            // Assert
            Assert.AreEqual(message, Encoding.UTF8.GetString(decryptedBytes));
        }

        [TestMethod, TestCategory("Integration"), TestCategory("SecureMessaging")]
        public void DecryptsCorrectlyWhenMlKem1024()
        {
            // Arrange
            var bobKeyPair = MlKem1024.GenerateKeyPair();
            var publicKeyBytes = bobKeyPair.EncapsulationKey.FullBytes;
            var privateKeyBytes = bobKeyPair.DecapsulationKey.FullBytes;

            // Act
            var bobPublicKey = KyberEncapsulationKey.FromBytes(publicKeyBytes);
            var result = bobPublicKey.Encapsulate();

            var message = "PQ encrypted message via ML-KEM-1024";
            var nonce = RandomNumberGenerator.GetBytes(12);
            var plaintext = Encoding.UTF8.GetBytes(message);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16];

            using (var aes = new AesGcm(result.SharedSecretKey, 16))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag);
            }

            var kemBytes = result.CipherText.FullBytes;
            var encryptedPayload = (byte[])[.. ciphertext, .. tag];

            var bobPrivateKey = KyberDecapsulationKey.FromBytes(privateKeyBytes);
            var receivedKem = KyberCipherText.FromBytes(kemBytes);
            var bobSecret = bobPrivateKey.Decapsulate(receivedKem);

            var decryptedBytes = new byte[encryptedPayload.Length - 16];

            using (var aes = new AesGcm(bobSecret, 16))
            {
                aes.Decrypt(nonce, encryptedPayload[..^16], encryptedPayload[^16..], decryptedBytes);
            }

            // Assert
            Assert.AreEqual(message, Encoding.UTF8.GetString(decryptedBytes));
        }

        [TestMethod, TestCategory("Integration"), TestCategory("SecureMessaging")]
        public void RoundtripsWhenMessageIsEmpty()
        {
            // Arrange
            var keyPair = MlKem768.GenerateKeyPair();
            var bobPublicKey = KyberEncapsulationKey.FromBytes(keyPair.EncapsulationKey.FullBytes);
            var result = bobPublicKey.Encapsulate();

            var nonce = RandomNumberGenerator.GetBytes(12);
            var plaintext = Array.Empty<byte>();
            var ciphertext = new byte[0];
            var tag = new byte[16];

            using (var aes = new AesGcm(result.SharedSecretKey, 16))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag);
            }

            // Act
            var bobPrivateKey = KyberDecapsulationKey.FromBytes(keyPair.DecapsulationKey.FullBytes);
            var bobSecret = bobPrivateKey.Decapsulate(KyberCipherText.FromBytes(result.CipherText.FullBytes));

            var decrypted = new byte[0];

            using (var aes = new AesGcm(bobSecret, 16))
            {
                aes.Decrypt(nonce, ciphertext, tag, decrypted);
            }

            // Assert
            Assert.AreEqual(0, decrypted.Length);
        }

        [TestMethod, TestCategory("Integration"), TestCategory("SecureMessaging")]
        public void RoundtripsWhenMessageIsLarge()
        {
            // Arrange
            var keyPair = MlKem768.GenerateKeyPair();
            var result = keyPair.EncapsulationKey.Encapsulate();

            var plaintext = new byte[100_000];
            RandomNumberGenerator.Fill(plaintext);
            var nonce = RandomNumberGenerator.GetBytes(12);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16];

            using (var aes = new AesGcm(result.SharedSecretKey, 16))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag);
            }

            // Act
            var bobSecret = keyPair.DecapsulationKey.Decapsulate(result.CipherText);

            var decrypted = new byte[ciphertext.Length];

            using (var aes = new AesGcm(bobSecret, 16))
            {
                aes.Decrypt(nonce, ciphertext, tag, decrypted);
            }

            // Assert
            CollectionAssert.AreEqual(plaintext, decrypted);
        }
    }

    [TestClass]
    public class Security
        : SecureMessagingIntegrationTest
    {
        [TestMethod, TestCategory("Integration"), TestCategory("SecureMessaging")]
        public void FailsDecryptionWhenWrongPrivateKeyUsed()
        {
            // Arrange
            var bobKeyPair = MlKem768.GenerateKeyPair();
            var eveKeyPair = MlKem768.GenerateKeyPair();

            var result = bobKeyPair.EncapsulationKey.Encapsulate();

            var message = "This is a secret";
            var nonce = RandomNumberGenerator.GetBytes(12);
            var plaintext = Encoding.UTF8.GetBytes(message);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16];

            using (var aes = new AesGcm(result.SharedSecretKey, 16))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag);
            }

            // Act
            var eveSecret = eveKeyPair.DecapsulationKey.Decapsulate(result.CipherText);

            // Assert
            Assert.IsFalse(result.SharedSecretKey.SequenceEqual(eveSecret));

            var eveDecrypted = new byte[ciphertext.Length];
            var threw = false;
            try
            {
                using var aes = new AesGcm(eveSecret, 16);
                aes.Decrypt(nonce, ciphertext, tag, eveDecrypted);
            }
            catch (CryptographicException)
            {
                threw = true;
            }

            Assert.IsTrue(threw, "Decryption with wrong key should throw a CryptographicException");
        }
    }
}