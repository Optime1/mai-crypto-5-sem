using System.Numerics;

namespace Dora.Crypto.RSA
{
    public static class BigIntegerExtensions
    {
        /// <summary>
        /// Returns the number of bits in the minimal two's-complement representation of this BigInteger, excluding a sign bit.
        /// Equivalent to Java's BigInteger.bitLength()
        /// </summary>
        public static int GetBitLength(this BigInteger value)
        {
            if (value == 0) return 0;
            
            value = BigInteger.Abs(value);
            
            // Find the position of the highest set bit
            int bitLength = 0;
            while (value > 0)
            {
                value >>= 1;
                bitLength++;
            }
            return bitLength;
        }
    }
}
