using System;
using System.Linq;
using System.Text;

namespace Portkit.Crypto
{
    /// <summary>
    /// Computes a Hash-based Message Authentication Code (HMAC) using the <see cref="IHashAlgorithm" /> 
    /// </summary>
    public sealed class MacAlgorithmProvider
    {
        private const int BLOCK_SIZE = 64;
        private readonly byte[] _key;
        private readonly IHashAlgorithm _hashAlgorithm;
        private byte[] _inner;
        private byte[] _outer;

        /// <summary>
        /// Initializes a new instance of the <see cref="MacAlgorithmProvider"/> class using the supplied key with UT8 encoding.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        public MacAlgorithmProvider(string key, IHashAlgorithm hashAlgorithm)
            : this(key, hashAlgorithm, Encoding.UTF8)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="MacAlgorithmProvider"/> class using the supplied key with supplied encoding.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="encoding">The encoding used to read the key.</param>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        public MacAlgorithmProvider(string key, IHashAlgorithm hashAlgorithm, Encoding encoding)
            : this(encoding.GetBytes(key), hashAlgorithm)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="MacAlgorithmProvider"/> class the supplied key.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        public MacAlgorithmProvider(byte[] key, IHashAlgorithm hashAlgorithm)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key), "The key cannot be null.");
            }
            _key = key.Length > BLOCK_SIZE ? Sha1.Compute(key) : key;
            _hashAlgorithm = hashAlgorithm;

            UpdateIOPadBuffers();
        }

        /// <summary>
        /// Computes the hash value for the specified string (UTF8 default encoding).
        /// </summary>
        /// <param name="buffer">The input to compute the hash code for. </param>
        /// <returns>The computed hash code</returns>
        public byte[] ComputeHash(string buffer)
        {
            return ComputeHash(buffer, Encoding.UTF8);
        }

        /// <summary>
        /// Computes the hash value for the specified string.
        /// </summary>
        /// <param name="buffer">The input to compute the hash code for.</param>
        /// <param name="encoding">The encoding.</param>
        /// <returns>
        /// The computed hash code
        /// </returns>
        public byte[] ComputeHash(string buffer, Encoding encoding)
        {
            return ComputeHash(encoding.GetBytes(buffer));
        }

        /// <summary>
        /// Computes the hash value for the specified byte array.
        /// </summary>
        /// <param name="buffer">The input to compute the hash code for.</param>
        /// <returns>
        /// The computed hash code
        /// </returns>
        public byte[] ComputeHash(byte[] buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer), "The input cannot be null.");
            }
            return _hashAlgorithm.ComputeHash(_outer.Union(_hashAlgorithm.ComputeHash(_inner.Union(buffer).ToArray())).ToArray());
        }

        /// <summary>
        /// Computes the hash for the specified string (UTF8 default encoding) to base64 string.
        /// </summary>
        /// <param name="buffer">The input to compute the hash code for.</param>
        /// <returns>The computed hash code in base64 string</returns>
        public string ComputeHashToBase64String(string buffer)
        {
            return Convert.ToBase64String(ComputeHash(buffer, Encoding.UTF8));
        }

        /// <summary>
        /// Computes the hash for the specified string to base64 string.
        /// </summary>
        /// <param name="buffer">The input to compute the hash code for.</param>
        /// <param name="encoding">The encoding.</param>
        /// <returns>
        /// The computed hash code in base64 string
        /// </returns>
        public string ComputeHashToBase64String(string buffer, Encoding encoding)
        {
            return Convert.ToBase64String(ComputeHash(buffer, encoding));
        }

        /// <summary>
        /// Updates the IO pad buffers.
        /// </summary>
        private void UpdateIOPadBuffers()
        {
            if (_inner == null)
            {
                _inner = new byte[BLOCK_SIZE];
            }

            if (_outer == null)
            {
                _outer = new byte[BLOCK_SIZE];
            }

            for (int i = 0; i < BLOCK_SIZE; i++)
            {
                _inner[i] = 54;
                _outer[i] = 92;
            }

            for (int i = 0; i < _key.Length; i++)
            {
                byte[] s1 = _inner;
                int s2 = i;
                s1[s2] ^= _key[i];
                byte[] s3 = _outer;
                int s4 = i;
                s3[s4] ^= _key[i];
            }
        }

        /// <summary>
        /// Combines two array (a1 and a2).
        /// </summary>
        /// <param name="a1">The Array 1.</param>
        /// <param name="a2">The Array 2.</param>
        /// <returns>Combinaison of a1 and a2</returns>
        private byte[] Combine(byte[] a1, byte[] a2)
        {
            return a1.Union(a2).ToArray();
        }
    }
}
