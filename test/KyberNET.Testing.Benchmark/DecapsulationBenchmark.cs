namespace KyberNET.Testing.Benchmark;

using BenchmarkDotNet.Attributes;
using KyberNET.Keys;
using MlKem512Api = KyberNET.Api.MlKem512;
using MlKem768Api = KyberNET.Api.MlKem768;
using MlKem1024Api = KyberNET.Api.MlKem1024;

[MemoryDiagnoser]
public class DecapsulationBenchmark
{
    private KyberKEMKeyPair keyPair512 = null!;
    private KyberKEMKeyPair keyPair768 = null!;
    private KyberKEMKeyPair keyPair1024 = null!;
    private KyberCipherText cipherText512 = null!;
    private KyberCipherText cipherText768 = null!;
    private KyberCipherText cipherText1024 = null!;

    [GlobalSetup]
    public void Setup()
    {
        keyPair512 = MlKem512Api.GenerateKeyPair();
        keyPair768 = MlKem768Api.GenerateKeyPair();
        keyPair1024 = MlKem1024Api.GenerateKeyPair();

        cipherText512 = keyPair512.EncapsulationKey.Encapsulate().CipherText;
        cipherText768 = keyPair768.EncapsulationKey.Encapsulate().CipherText;
        cipherText1024 = keyPair1024.EncapsulationKey.Encapsulate().CipherText;
    }

    [Benchmark]
    public byte[] MlKem512() => keyPair512.DecapsulationKey.Decapsulate(cipherText512);

    [Benchmark]
    public byte[] MlKem768() => keyPair768.DecapsulationKey.Decapsulate(cipherText768);

    [Benchmark]
    public byte[] MlKem1024() => keyPair1024.DecapsulationKey.Decapsulate(cipherText1024);
}