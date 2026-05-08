namespace KyberNET.Api
{
    using Constants;
    using Keys;

    public static class MlKem512
    {
        public static KyberKEMKeyPair GenerateKeyPair(IRandomProvider? randomProvider = null)
            => KyberKeyGenerator.Generate(KyberParameter.MlKem512, randomProvider);
    }
}