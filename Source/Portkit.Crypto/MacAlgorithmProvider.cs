using System;
using System.Linq;
using System.Text;

namespace Portkit.Crypto
{
    public sealed class MacAlgorithmProvider
    {
        private const int BLOCK_SIZE = 64;

        private byte[] _key;
        private byte[] _innerPad;
        private byte[] _outerPad;
        private readonly IHashAlgorithm _hashAlgorithm;

        public MacAlgorithmProvider(string key, IHashAlgorithm hashAlgorithm)
            : this(key, hashAlgorithm, Encoding.UTF8)
        {
        }

        public MacAlgorithmProvider(string key, IHashAlgorithm hashAlgorithm, Encoding encoding)
            : this(encoding.GetBytes(key), hashAlgorithm)
        {
        }

        public MacAlgorithmProvider(byte[] key, IHashAlgorithm hashAlgorithm)
        {
            _hashAlgorithm = hashAlgorithm;
            InitializeKey(key);
        }

        public byte[] ComputeHash(string buffer)
        {
            return ComputeHash(buffer, Encoding.UTF8);
        }

        public byte[] ComputeHash(string buffer, Encoding encoding)
        {
            return ComputeHash(encoding.GetBytes(buffer));
        }

        public byte[] ComputeHash(byte[] buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer), "The input cannot be null.");
            }
            var innerPadAndBufferHash = _hashAlgorithm.Reset().ComputeHash(Concat(_innerPad, buffer));
            var finalBuffer = Concat(_outerPad, innerPadAndBufferHash);
            return _hashAlgorithm.Reset().ComputeHash(finalBuffer);
        }

        private void InitializeKey(byte[] key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key), "The Key cannot be null.");
            }

            _key = key.Length > BLOCK_SIZE ? _hashAlgorithm.Reset().ComputeHash(key) : key;
            UpdateIOPadBuffers();
        }

        private void UpdateIOPadBuffers()
        {
            if (_innerPad == null)
            {
                _innerPad = new byte[BLOCK_SIZE];
            }

            if (_outerPad == null)
            {
                _outerPad = new byte[BLOCK_SIZE];
            }

            for (int i = 0; i < BLOCK_SIZE; i++)
            {
                _innerPad[i] = 54;
                _outerPad[i] = 92;
            }

            for (int i = 0; i < _key.Length; i++)
            {
                byte[] s1 = _innerPad;
                int s2 = i;
                s1[s2] ^= _key[i];
                byte[] s3 = _outerPad;
                int s4 = i;
                s3[s4] ^= _key[i];
            }
        }

        private static byte[] Concat(byte[] left, byte[] right) =>
            left.Concat(right).ToArray();
    }
}
