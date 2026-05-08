namespace KyberNET.Api
{
    using Constants;
    using Keys;

    public static class MlKem1024
    {
        public static KyberKEMKeyPair GenerateKeyPair(IRandomProvider? randomProvider = null)
            => KyberKeyGenerator.Generate(KyberParameter.MlKem1024, randomProvider);
    }
}