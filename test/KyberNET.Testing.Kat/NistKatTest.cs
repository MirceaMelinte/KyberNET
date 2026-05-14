namespace KyberNET.Testing.Kat;

using System.Reflection;
using System.Text.Json;
using Constants;
using Internal;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public class NistKatTest
{
    private static Dictionary<string, List<KatVector>>? cachedVectors;

    private static Dictionary<string, List<KatVector>> Vectors
    {
        get
        {
            if (cachedVectors is not null)
            {
                return cachedVectors;
            }

            var assembly = Assembly.GetExecutingAssembly();
            var resourceName = assembly
                .GetManifestResourceNames()
                .Single(n => n.EndsWith("kat-vectors.json"));

            using var stream = assembly.GetManifestResourceStream(resourceName)!;
            var document = JsonDocument.Parse(stream);
            var result = new Dictionary<string, List<KatVector>>();

            foreach (var @object in document.RootElement.EnumerateObject())
            {
                var vectors = new List<KatVector>();
                
                foreach (var element in @object.Value.EnumerateArray())
                {
                    vectors.Add(
                        new KatVector(
                            element.GetProperty("z").GetString()!,
                            element.GetProperty("d").GetString()!,
                            element.GetProperty("msg").GetString()!,
                            element.GetProperty("ek").GetString()!,
                            element.GetProperty("dk").GetString()!,
                            element.GetProperty("ct").GetString()!,
                            element.GetProperty("ss").GetString()!));
                }
                
                result[@object.Name] = vectors;
            }

            cachedVectors = result;
            
            return cachedVectors;
        }
    }

    private static byte[] HexToBytes(string hex)
    {
        var bytes = new byte[hex.Length / 2];
        
        for (var i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        
        return bytes;
    }

    private sealed record KatVector(string Z, string D, string Msg, string Ek, string Dk, string Ct, string Ss);

    [TestClass]
    public class Generate
        : NistKatTest
    {
        private void RunKeyGenVector(KyberParameter param, string paramName, int index)
        {
            // Arrange
            var vector = Vectors[paramName][index];
            var z = HexToBytes(vector.Z);
            var d = HexToBytes(vector.D);
            var expectedEk = HexToBytes(vector.Ek);
            var expectedDk = HexToBytes(vector.Dk);

            // Act
            var keyPair = KyberKeyGenerator.Generate(param, z, d);

            // Assert
            CollectionAssert.AreEqual(expectedEk, keyPair.EncapsulationKey.FullBytes);
            CollectionAssert.AreEqual(expectedDk, keyPair.DecapsulationKey.FullBytes);
        }

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_KeyGen")]
        public void MlKem512_Vector0() => RunKeyGenVector(KyberParameter.MlKem512, "MlKem512", 0);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_KeyGen")]
        public void MlKem512_Vector1() => RunKeyGenVector(KyberParameter.MlKem512, "MlKem512", 1);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_KeyGen")]
        public void MlKem512_Vector2() => RunKeyGenVector(KyberParameter.MlKem512, "MlKem512", 2);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_KeyGen")]
        public void MlKem768_Vector0() => RunKeyGenVector(KyberParameter.MlKem768, "MlKem768", 0);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_KeyGen")]
        public void MlKem768_Vector1() => RunKeyGenVector(KyberParameter.MlKem768, "MlKem768", 1);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_KeyGen")]
        public void MlKem768_Vector2() => RunKeyGenVector(KyberParameter.MlKem768, "MlKem768", 2);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_KeyGen")]
        public void MlKem1024_Vector0() => RunKeyGenVector(KyberParameter.MlKem1024, "MlKem1024", 0);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_KeyGen")]
        public void MlKem1024_Vector1() => RunKeyGenVector(KyberParameter.MlKem1024, "MlKem1024", 1);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_KeyGen")]
        public void MlKem1024_Vector2() => RunKeyGenVector(KyberParameter.MlKem1024, "MlKem1024", 2);
    }

    [TestClass]
    public class Encapsulate
        : NistKatTest
    {
        private void RunEncapsVector(KyberParameter parameter, string paramName, int index)
        {
            // Arrange
            var vector = Vectors[paramName][index];
            var z = HexToBytes(vector.Z);
            var d = HexToBytes(vector.D);
            var msg = HexToBytes(vector.Msg);
            var expectedCt = HexToBytes(vector.Ct);
            var expectedSs = HexToBytes(vector.Ss);
            var keyPair = KyberKeyGenerator.Generate(parameter, z, d);

            // Act
            var result = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, msg);

            // Assert
            CollectionAssert.AreEqual(expectedCt, result.CipherText.FullBytes);
            CollectionAssert.AreEqual(expectedSs, result.SharedSecretKey);
        }

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_Encaps")]
        public void MlKem512_Vector0() => RunEncapsVector(KyberParameter.MlKem512, "MlKem512", 0);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_Encaps")]
        public void MlKem512_Vector1() => RunEncapsVector(KyberParameter.MlKem512, "MlKem512", 1);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_Encaps")]
        public void MlKem512_Vector2() => RunEncapsVector(KyberParameter.MlKem512, "MlKem512", 2);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_Encaps")]
        public void MlKem768_Vector0() => RunEncapsVector(KyberParameter.MlKem768, "MlKem768", 0);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_Encaps")]
        public void MlKem768_Vector1() => RunEncapsVector(KyberParameter.MlKem768, "MlKem768", 1);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_Encaps")]
        public void MlKem768_Vector2() => RunEncapsVector(KyberParameter.MlKem768, "MlKem768", 2);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_Encaps")]
        public void MlKem1024_Vector0() => RunEncapsVector(KyberParameter.MlKem1024, "MlKem1024", 0);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_Encaps")]
        public void MlKem1024_Vector1() => RunEncapsVector(KyberParameter.MlKem1024, "MlKem1024", 1);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_Encaps")]
        public void MlKem1024_Vector2() => RunEncapsVector(KyberParameter.MlKem1024, "MlKem1024", 2);
    }

    [TestClass]
    public class Decapsulate
        : NistKatTest
    {
        private void RunDecapsVector(KyberParameter parameter, string paramName, int index)
        {
            // Arrange
            var vector = Vectors[paramName][index];
            var z = HexToBytes(vector.Z);
            var d = HexToBytes(vector.D);
            var msg = HexToBytes(vector.Msg);
            var expectedSs = HexToBytes(vector.Ss);
            var keyPair = KyberKeyGenerator.Generate(parameter, z, d);
            var encapsResult = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, msg);

            // Act
            var recoveredSs = keyPair.DecapsulationKey.Decapsulate(encapsResult.CipherText);

            // Assert
            CollectionAssert.AreEqual(expectedSs, recoveredSs);
        }

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_Decaps")]
        public void MlKem512_Vector0() => RunDecapsVector(KyberParameter.MlKem512, "MlKem512", 0);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_Decaps")]
        public void MlKem512_Vector1() => RunDecapsVector(KyberParameter.MlKem512, "MlKem512", 1);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_Decaps")]
        public void MlKem512_Vector2() => RunDecapsVector(KyberParameter.MlKem512, "MlKem512", 2);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_Decaps")]
        public void MlKem768_Vector0() => RunDecapsVector(KyberParameter.MlKem768, "MlKem768", 0);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_Decaps")]
        public void MlKem768_Vector1() => RunDecapsVector(KyberParameter.MlKem768, "MlKem768", 1);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_Decaps")]
        public void MlKem768_Vector2() => RunDecapsVector(KyberParameter.MlKem768, "MlKem768", 2);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_Decaps")]
        public void MlKem1024_Vector0() => RunDecapsVector(KyberParameter.MlKem1024, "MlKem1024", 0);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_Decaps")]
        public void MlKem1024_Vector1() => RunDecapsVector(KyberParameter.MlKem1024, "MlKem1024", 1);

        [TestMethod, TestCategory("KAT"), TestCategory("KAT_Decaps")]
        public void MlKem1024_Vector2() => RunDecapsVector(KyberParameter.MlKem1024, "MlKem1024", 2);
    }
}