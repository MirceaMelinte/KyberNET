namespace KyberNET.Testing.Benchmark;

using BenchmarkDotNet.Attributes;
using KyberNET.Keys;
using MlKem512Api = KyberNET.Api.MlKem512;
using MlKem768Api = KyberNET.Api.MlKem768;
using MlKem1024Api = KyberNET.Api.MlKem1024;

[MemoryDiagnoser]
public class KeyGenBenchmark
{
    [Benchmark]
    public KyberKEMKeyPair MlKem512() => MlKem512Api.GenerateKeyPair();

    [Benchmark]
    public KyberKEMKeyPair MlKem768() => MlKem768Api.GenerateKeyPair();

    [Benchmark]
    public KyberKEMKeyPair MlKem1024() => MlKem1024Api.GenerateKeyPair();
}