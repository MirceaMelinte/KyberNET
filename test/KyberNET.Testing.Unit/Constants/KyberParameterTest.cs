namespace KyberNET.Testing.Unit.Constants;

using KyberNET.Constants;
using KyberNET.Exceptions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

public class KyberParameterTest
{
    [TestClass]
    public class DerivedLengths
        : KyberParameterTest
    {
        [TestMethod, TestCategory("KyberParameter"), TestCategory("DerivedLengths")]
        public void MlKem512HasCorrectCiphertextLength()
        {
            Assert.AreEqual(768, KyberParameter.MlKem512.CiphertextLength);
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("DerivedLengths")]
        public void MlKem512HasCorrectDecryptionKeyLength()
        {
            Assert.AreEqual(768, KyberParameter.MlKem512.DecryptionKeyLength);
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("DerivedLengths")]
        public void MlKem512HasCorrectEncryptionKeyLength()
        {
            Assert.AreEqual(800, KyberParameter.MlKem512.EncryptionKeyLength);
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("DerivedLengths")]
        public void MlKem512HasCorrectEncapsulationKeyLength()
        {
            Assert.AreEqual(800, KyberParameter.MlKem512.EncapsulationKeyLength);
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("DerivedLengths")]
        public void MlKem512HasCorrectDecapsulationKeyLength()
        {
            Assert.AreEqual(1632, KyberParameter.MlKem512.DecapsulationKeyLength);
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("DerivedLengths")]
        public void MlKem768HasCorrectCiphertextLength()
        {
            Assert.AreEqual(1088, KyberParameter.MlKem768.CiphertextLength);
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("DerivedLengths")]
        public void MlKem768HasCorrectDecryptionKeyLength()
        {
            Assert.AreEqual(1152, KyberParameter.MlKem768.DecryptionKeyLength);
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("DerivedLengths")]
        public void MlKem768HasCorrectEncryptionKeyLength()
        {
            Assert.AreEqual(1184, KyberParameter.MlKem768.EncryptionKeyLength);
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("DerivedLengths")]
        public void MlKem768HasCorrectDecapsulationKeyLength()
        {
            Assert.AreEqual(2400, KyberParameter.MlKem768.DecapsulationKeyLength);
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("DerivedLengths")]
        public void MlKem1024HasCorrectCiphertextLength()
        {
            Assert.AreEqual(1568, KyberParameter.MlKem1024.CiphertextLength);
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("DerivedLengths")]
        public void MlKem1024HasCorrectDecryptionKeyLength()
        {
            Assert.AreEqual(1536, KyberParameter.MlKem1024.DecryptionKeyLength);
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("DerivedLengths")]
        public void MlKem1024HasCorrectEncryptionKeyLength()
        {
            Assert.AreEqual(1568, KyberParameter.MlKem1024.EncryptionKeyLength);
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("DerivedLengths")]
        public void MlKem1024HasCorrectDecapsulationKeyLength()
        {
            Assert.AreEqual(3168, KyberParameter.MlKem1024.DecapsulationKeyLength);
        }
    }

    [TestClass]
    public class FindByCipherTextSizeMethod
        : KyberParameterTest
    {
        [TestMethod, TestCategory("KyberParameter"), TestCategory("FindByCipherTextSize")]
        public void Returns512ForLength768()
        {
            Assert.AreSame(KyberParameter.MlKem512, KyberParameter.FindByCipherTextSize(768));
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("FindByCipherTextSize")]
        public void Returns768ForLength1088()
        {
            Assert.AreSame(KyberParameter.MlKem768, KyberParameter.FindByCipherTextSize(1088));
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("FindByCipherTextSize")]
        public void Returns1024ForLength1568()
        {
            Assert.AreSame(KyberParameter.MlKem1024, KyberParameter.FindByCipherTextSize(1568));
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("FindByCipherTextSize")]
        public void ThrowsForInvalidLength()
        {
            Assert.ThrowsExactly<UnsupportedKyberVariantException>(() => KyberParameter.FindByCipherTextSize(999));
        }
    }

    [TestClass]
    public class FindByEncryptionKeySizeMethod
        : KyberParameterTest
    {
        [TestMethod, TestCategory("KyberParameter"), TestCategory("FindByEncryptionKeySize")]
        public void Returns512ForLength800()
        {
            Assert.AreSame(KyberParameter.MlKem512, KyberParameter.FindByEncryptionKeySize(800));
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("FindByEncryptionKeySize")]
        public void Returns768ForLength1184()
        {
            Assert.AreSame(KyberParameter.MlKem768, KyberParameter.FindByEncryptionKeySize(1184));
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("FindByEncryptionKeySize")]
        public void Returns1024ForLength1568()
        {
            Assert.AreSame(KyberParameter.MlKem1024, KyberParameter.FindByEncryptionKeySize(1568));
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("FindByEncryptionKeySize")]
        public void ThrowsForInvalidLength()
        {
            Assert.ThrowsExactly<UnsupportedKyberVariantException>(() => KyberParameter.FindByEncryptionKeySize(999));
        }
    }

    [TestClass]
    public class FindByEncapsulationKeySizeMethod
        : KyberParameterTest
    {
        [TestMethod, TestCategory("KyberParameter"), TestCategory("FindByEncapsulationKeySize")]
        public void Returns512ForLength800()
        {
            Assert.AreSame(KyberParameter.MlKem512, KyberParameter.FindByEncapsulationKeySize(800));
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("FindByEncapsulationKeySize")]
        public void ThrowsForInvalidLength()
        {
            Assert.ThrowsExactly<UnsupportedKyberVariantException>(() => KyberParameter.FindByEncapsulationKeySize(999));
        }
    }

    [TestClass]
    public class FindByDecryptionKeySizeMethod
        : KyberParameterTest
    {
        [TestMethod, TestCategory("KyberParameter"), TestCategory("FindByDecryptionKeySize")]
        public void Returns512ForLength768()
        {
            Assert.AreSame(KyberParameter.MlKem512, KyberParameter.FindByDecryptionKeySize(768));
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("FindByDecryptionKeySize")]
        public void Returns768ForLength1152()
        {
            Assert.AreSame(KyberParameter.MlKem768, KyberParameter.FindByDecryptionKeySize(1152));
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("FindByDecryptionKeySize")]
        public void Returns1024ForLength1536()
        {
            Assert.AreSame(KyberParameter.MlKem1024, KyberParameter.FindByDecryptionKeySize(1536));
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("FindByDecryptionKeySize")]
        public void ThrowsForInvalidLength()
        {
            Assert.ThrowsExactly<UnsupportedKyberVariantException>(() => KyberParameter.FindByDecryptionKeySize(999));
        }
    }

    [TestClass]
    public class FindByDecapsulationKeySizeMethod
        : KyberParameterTest
    {
        [TestMethod, TestCategory("KyberParameter"), TestCategory("FindByDecapsulationKeySize")]
        public void Returns512ForLength1632()
        {
            Assert.AreSame(KyberParameter.MlKem512, KyberParameter.FindByDecapsulationKeySize(1632));
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("FindByDecapsulationKeySize")]
        public void Returns768ForLength2400()
        {
            Assert.AreSame(KyberParameter.MlKem768, KyberParameter.FindByDecapsulationKeySize(2400));
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("FindByDecapsulationKeySize")]
        public void Returns1024ForLength3168()
        {
            Assert.AreSame(KyberParameter.MlKem1024, KyberParameter.FindByDecapsulationKeySize(3168));
        }

        [TestMethod, TestCategory("KyberParameter"), TestCategory("FindByDecapsulationKeySize")]
        public void ThrowsForInvalidLength()
        {
            Assert.ThrowsExactly<UnsupportedKyberVariantException>(() => KyberParameter.FindByDecapsulationKeySize(999));
        }
    }
}