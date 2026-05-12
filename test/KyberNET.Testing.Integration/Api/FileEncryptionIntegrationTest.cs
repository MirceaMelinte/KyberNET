namespace KyberNET.Testing.Integration.Api;

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using KyberNET.Api;
using KyberNET.Constants;
using KyberNET.Keys;
using Microsoft.VisualStudio.TestTools.UnitTesting;

public class FileEncryptionIntegrationTest
{
    private string tempDir = null!;

    [TestInitialize]
    public void Setup()
    {
        tempDir = Path.Combine(Path.GetTempPath(), "kyber-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempDir);
    }

    [TestCleanup]
    public void Cleanup()
    {
        if (Directory.Exists(tempDir))
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    private static void EncryptFile(string inputPath, string outputPath, byte[] recipientPublicKeyBytes)
    {
        var recipientKey = KyberEncapsulationKey.FromBytes(recipientPublicKeyBytes);
        var result = recipientKey.Encapsulate();

        var sharedSecret = result.SharedSecretKey;
        var kemBytes = result.CipherText.FullBytes;
        var nonce = RandomNumberGenerator.GetBytes(12);

        var fileData = File.ReadAllBytes(inputPath);
        var ciphertext = new byte[fileData.Length];
        var tag = new byte[16];

        using (var aes = new AesGcm(sharedSecret, 16))
        {
            aes.Encrypt(nonce, fileData, ciphertext, tag);
        }

        using (var output = File.Create(outputPath))
        {
            var k = (byte)recipientKey.Parameter.K;
            output.WriteByte(k);
            output.Write(kemBytes);
            output.Write(nonce);
            output.Write(ciphertext);
            output.Write(tag);
        }
    }

    private static byte[] DecryptFile(string encryptedPath, byte[] recipientPrivateKeyBytes)
    {
        var fileBytes = File.ReadAllBytes(encryptedPath);

        var k = fileBytes[0];
        var param = k switch
        {
            2 => KyberParameter.MlKem512,
            3 => KyberParameter.MlKem768,
            4 => KyberParameter.MlKem1024,
            _ => throw new InvalidDataException("Unknown ML-KEM variant")
        };

        var privateKey = KyberDecapsulationKey.FromBytes(recipientPrivateKeyBytes);

        var offset = 1;
        var kemLen = param.CiphertextLength;
        var kemBytes = fileBytes[offset..(offset + kemLen)];
        
        offset += kemLen;
        var nonce = fileBytes[offset..(offset + 12)];
        
        offset += 12;
        var ciphertext = fileBytes[offset..^16];
        var tag = fileBytes[^16..];

        var kemCipherText = KyberCipherText.FromBytes(kemBytes);
        var sharedSecret = privateKey.Decapsulate(kemCipherText);

        var plaintext = new byte[ciphertext.Length];

        using (var aes = new AesGcm(sharedSecret, 16))
        {
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
        }

        return plaintext;
    }

    [TestClass]
    public class Encrypt
        : FileEncryptionIntegrationTest
    {
        [TestMethod, TestCategory("Integration"), TestCategory("FileEncryption")]
        public void ProducesEncryptedOutputWhenCalled()
        {
            // Arrange
            var keyPair = MlKem768.GenerateKeyPair();

            var inputPath = Path.Combine(tempDir, "report.txt");
            var encryptedPath = Path.Combine(tempDir, "report.txt.kyber");
            var originalContent = Encoding.UTF8.GetBytes("This is a confidential report about PQ crypto");
            File.WriteAllBytes(inputPath, originalContent);

            // Act
            EncryptFile(inputPath, encryptedPath, keyPair.EncapsulationKey.FullBytes);

            // Assert
            Assert.IsTrue(File.Exists(encryptedPath));
            var encryptedBytes = File.ReadAllBytes(encryptedPath);
            Assert.IsFalse(originalContent.SequenceEqual(encryptedBytes));
        }

        [TestMethod, TestCategory("Integration"), TestCategory("FileEncryption")]
        public void HasCorrectBinaryFormatWhenEncryptedWithMlKem768()
        {
            // Arrange
            var keyPair = MlKem768.GenerateKeyPair();

            var inputPath = Path.Combine(tempDir, "format-test.txt");
            var encryptedPath = Path.Combine(tempDir, "format-test.txt.kyber");
            var content = Encoding.UTF8.GetBytes("format verification");
            File.WriteAllBytes(inputPath, content);

            // Act
            EncryptFile(inputPath, encryptedPath, keyPair.EncapsulationKey.FullBytes);

            var encryptedBytes = File.ReadAllBytes(encryptedPath);

            // Assert
            Assert.AreEqual((byte)3, encryptedBytes[0]);

            var expectedLength = 1 + KyberParameter.MlKem768.CiphertextLength + 12 + content.Length + 16;
            Assert.AreEqual(expectedLength, encryptedBytes.Length);
        }
    }

    [TestClass]
    public class Decrypt
        : FileEncryptionIntegrationTest
    {
        [TestMethod, TestCategory("Integration"), TestCategory("FileEncryption")]
        public void DecryptsCorrectlyWhenMlKem768()
        {
            // Arrange
            var keyPair = MlKem768.GenerateKeyPair();
            var publicKey = keyPair.EncapsulationKey.FullBytes;
            var privateKey = keyPair.DecapsulationKey.FullBytes;

            var inputPath = Path.Combine(tempDir, "report.txt");
            var encryptedPath = Path.Combine(tempDir, "report.txt.kyber");
            var originalContent = Encoding.UTF8.GetBytes("This is a confidential report about PQ crypto");
            File.WriteAllBytes(inputPath, originalContent);
            EncryptFile(inputPath, encryptedPath, publicKey);

            // Act
            var decrypted = DecryptFile(encryptedPath, privateKey);

            // Assert
            CollectionAssert.AreEqual(originalContent, decrypted);
        }

        [TestMethod, TestCategory("Integration"), TestCategory("FileEncryption")]
        public void DecryptsCorrectlyWhenMlKem512()
        {
            // Arrange
            var keyPair = MlKem512.GenerateKeyPair();
            var publicKey = keyPair.EncapsulationKey.FullBytes;
            var privateKey = keyPair.DecapsulationKey.FullBytes;

            var inputPath = Path.Combine(tempDir, "data.bin");
            var encryptedPath = Path.Combine(tempDir, "data.bin.kyber");
            var originalContent = new byte[512];
            RandomNumberGenerator.Fill(originalContent);
            File.WriteAllBytes(inputPath, originalContent);
            EncryptFile(inputPath, encryptedPath, publicKey);

            // Act
            var decrypted = DecryptFile(encryptedPath, privateKey);

            // Assert
            CollectionAssert.AreEqual(originalContent, decrypted);
        }

        [TestMethod, TestCategory("Integration"), TestCategory("FileEncryption")]
        public void DecryptsCorrectlyWhenMlKem1024()
        {
            // Arrange
            var keyPair = MlKem1024.GenerateKeyPair();
            var publicKey = keyPair.EncapsulationKey.FullBytes;
            var privateKey = keyPair.DecapsulationKey.FullBytes;

            var inputPath = Path.Combine(tempDir, "data.bin");
            var encryptedPath = Path.Combine(tempDir, "data.bin.kyber");
            var originalContent = new byte[1024];
            RandomNumberGenerator.Fill(originalContent);
            File.WriteAllBytes(inputPath, originalContent);
            EncryptFile(inputPath, encryptedPath, publicKey);

            // Act
            var decrypted = DecryptFile(encryptedPath, privateKey);

            // Assert
            CollectionAssert.AreEqual(originalContent, decrypted);
        }

        [TestMethod, TestCategory("Integration"), TestCategory("FileEncryption")]
        public void RoundtripsWhenFileIsEmpty()
        {
            // Arrange
            var keyPair = MlKem768.GenerateKeyPair();

            var inputPath = Path.Combine(tempDir, "empty.bin");
            var encryptedPath = Path.Combine(tempDir, "empty.bin.kyber");
            File.WriteAllBytes(inputPath, Array.Empty<byte>());
            EncryptFile(inputPath, encryptedPath, keyPair.EncapsulationKey.FullBytes);

            // Act
            var decrypted = DecryptFile(encryptedPath, keyPair.DecapsulationKey.FullBytes);

            // Assert
            Assert.AreEqual(0, decrypted.Length);
        }

        [TestMethod, TestCategory("Integration"), TestCategory("FileEncryption")]
        public void RoundtripsWhenFileIsLarge()
        {
            // Arrange
            var keyPair = MlKem768.GenerateKeyPair();

            var inputPath = Path.Combine(tempDir, "large.bin");
            var encryptedPath = Path.Combine(tempDir, "large.bin.kyber");
            var originalContent = new byte[100_000];
            RandomNumberGenerator.Fill(originalContent);
            File.WriteAllBytes(inputPath, originalContent);
            EncryptFile(inputPath, encryptedPath, keyPair.EncapsulationKey.FullBytes);

            // Act
            var decrypted = DecryptFile(encryptedPath, keyPair.DecapsulationKey.FullBytes);

            // Assert
            CollectionAssert.AreEqual(originalContent, decrypted);
        }

        [TestMethod, TestCategory("Integration"), TestCategory("FileEncryption")]
        public void ThrowsWhenWrongKeyUsed()
        {
            // Arrange
            var sender = MlKem768.GenerateKeyPair();
            var attacker = MlKem768.GenerateKeyPair();

            var inputPath = Path.Combine(tempDir, "secret.txt");
            var encryptedPath = Path.Combine(tempDir, "secret.txt.kyber");
            File.WriteAllBytes(inputPath, Encoding.UTF8.GetBytes("Top secret information"));
            EncryptFile(inputPath, encryptedPath, sender.EncapsulationKey.FullBytes);

            // Act
            var threw = false;
            try
            {
                DecryptFile(encryptedPath, attacker.DecapsulationKey.FullBytes);
            }
            catch (CryptographicException)
            {
                threw = true;
            }

            // Assert
            Assert.IsTrue(threw, "Decryption with wrong key should throw a CryptographicException");
        }

        [TestMethod, TestCategory("Integration"), TestCategory("FileEncryption")]
        public void ThrowsWhenCiphertextIsTampered()
        {
            // Arrange
            var keyPair = MlKem768.GenerateKeyPair();

            var inputPath = Path.Combine(tempDir, "tamper.txt");
            var encryptedPath = Path.Combine(tempDir, "tamper.txt.kyber");
            File.WriteAllBytes(inputPath, Encoding.UTF8.GetBytes("Do not tamper with me"));
            EncryptFile(inputPath, encryptedPath, keyPair.EncapsulationKey.FullBytes);

            var encryptedBytes = File.ReadAllBytes(encryptedPath);
            var aesDataStart = 1 + KyberParameter.MlKem768.CiphertextLength + 12;
            if (aesDataStart < encryptedBytes.Length - 16)
            {
                encryptedBytes[aesDataStart] ^= 0xFF;
            }

            File.WriteAllBytes(encryptedPath, encryptedBytes);

            // Act
            var threw = false;
            try
            {
                DecryptFile(encryptedPath, keyPair.DecapsulationKey.FullBytes);
            }
            catch (CryptographicException)
            {
                threw = true;
            }

            // Assert
            Assert.IsTrue(threw, "Decryption of tampered ciphertext should throw a CryptographicException");
        }
    }
}