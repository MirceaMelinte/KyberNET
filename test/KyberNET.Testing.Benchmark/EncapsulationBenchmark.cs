namespace KyberNET.Testing.Benchmark;

using BenchmarkDotNet.Attributes;
using KyberNET.Keys;
using MlKem512Api = KyberNET.Api.MlKem512;
using MlKem768Api = KyberNET.Api.MlKem768;
using MlKem1024Api = KyberNET.Api.MlKem1024;

[MemoryDiagnoser]
public class EncapsulationBenchmark
{
    private KyberKEMKeyPair keyPair512 = null!;
    private KyberKEMKeyPair keyPair768 = null!;
    private KyberKEMKeyPair keyPair1024 = null!;

    [GlobalSetup]
    public void Setup()
    {
        keyPair512 = MlKem512Api.GenerateKeyPair();
        keyPair768 = MlKem768Api.GenerateKeyPair();
        keyPair1024 = MlKem1024Api.GenerateKeyPair();
    }

    [Benchmark]
    public KyberEncapsulationResult MlKem512() => keyPair512.EncapsulationKey.Encapsulate();

    [Benchmark]
    public KyberEncapsulationResult MlKem768() => keyPair768.EncapsulationKey.Encapsulate();

    [Benchmark]
    public KyberEncapsulationResult MlKem1024() => keyPair1024.EncapsulationKey.Encapsulate();
}