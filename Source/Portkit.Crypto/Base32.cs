namespace Portkit.Crypto
{
    public static class Base32
    {
        private const byte BITS_IN_BLOCK = 5;
        private const byte BITS_IN_BYTE = 8;
        private const string ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        private const char PADDING = '=';

        public static string Encode(byte[] input)
        {
            if (input.Length == 0)
            {
                return string.Empty;
            }

            var output = new char[(int)decimal.Ceiling((input.Length / (decimal)BITS_IN_BLOCK)) * BITS_IN_BYTE];
            var position = 0;
            byte workingByte = 0, remainingBits = BITS_IN_BLOCK;

            foreach (var currentByte in input)
            {
                workingByte = (byte)(workingByte | (currentByte >> (BITS_IN_BYTE - remainingBits)));
                output[position++] = ALPHABET[workingByte];

                if (remainingBits < BITS_IN_BYTE - BITS_IN_BLOCK)
                {
                    workingByte = (byte)((currentByte >> (BITS_IN_BYTE - BITS_IN_BLOCK - remainingBits)) & 31);
                    output[position++] = ALPHABET[workingByte];
                    remainingBits += BITS_IN_BLOCK;
                }

                remainingBits -= BITS_IN_BYTE - BITS_IN_BLOCK;
                workingByte = (byte)((currentByte << remainingBits) & 31);
            }

            if (position != output.Length)
            {
                output[position++] = ALPHABET[workingByte];
            }

            while (position < output.Length)
            {
                output[position++] = PADDING;
            }

            return new string(output);
        }

        public static byte[] Decode(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return new byte[0];
            }

            input = input.TrimEnd(PADDING).ToUpperInvariant();

            var output = new byte[input.Length * BITS_IN_BLOCK / BITS_IN_BYTE];
            var position = 0;
            byte workingByte = 0, bitsRemaining = BITS_IN_BYTE;

            foreach (var currentChar in input.ToCharArray())
            {
                int mask;
                var currentCharPosition = ALPHABET.IndexOf(currentChar);

                if (bitsRemaining > BITS_IN_BLOCK)
                {
                    mask = currentCharPosition << (bitsRemaining - BITS_IN_BLOCK);
                    workingByte = (byte)(workingByte | mask);
                    bitsRemaining -= BITS_IN_BLOCK;
                }
                else
                {
                    mask = currentCharPosition >> (BITS_IN_BLOCK - bitsRemaining);
                    workingByte = (byte)(workingByte | mask);
                    output[position++] = workingByte;
                    workingByte = unchecked((byte)(currentCharPosition << (BITS_IN_BYTE - BITS_IN_BLOCK + bitsRemaining)));
                    bitsRemaining += BITS_IN_BYTE - BITS_IN_BLOCK;
                }
            }

            return output;
        }
    }
}