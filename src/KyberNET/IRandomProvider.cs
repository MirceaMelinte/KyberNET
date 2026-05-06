namespace KyberNET
{
    public interface IRandomProvider
    {
        void FillWithRandom(byte[] buffer);
    }
}