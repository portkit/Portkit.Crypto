namespace Portkit.Crypto
{
    public interface IHashAlgorithm
    {
        byte[] ComputeHash(byte[] buffer);

        byte[] ComputeHash(byte[] buffer, int offset, int count);
    }
}