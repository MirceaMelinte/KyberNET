namespace KyberNET.Api
{
    using Constants;
    using Keys;

    public static class MlKem768
    {
        public static KyberKEMKeyPair GenerateKeyPair(IRandomProvider? randomProvider = null)
            => KyberKeyGenerator.Generate(KyberParameter.MlKem768, randomProvider);
    }
}