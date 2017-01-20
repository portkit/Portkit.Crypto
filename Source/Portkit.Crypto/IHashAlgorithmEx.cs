namespace Portkit.Crypto
{
    public static class IHashAlgorithmEx
    {
        public static byte[] ComputeHash(this IHashAlgorithm hashAlgorithm, byte[] buffer) =>
            hashAlgorithm.ComputeHash(buffer, 0, buffer.Length);
    }
}
