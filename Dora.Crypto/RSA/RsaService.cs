using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Dora.Crypto.RSA
{
    public class RsaService
    {
        private BigInteger N; // Module
        private BigInteger e; // Public exponent
        private BigInteger d; // Private exponent

        private readonly KeyGenerationService keyGenService;

        public enum PrimalityTest
        {
            FERMAT,
            MILLER_RABIN,
            SOLOVAY_STRASSEN
        }

        public class KeyGenerationService
        {
            private readonly IProbabilisticPrimality primalityTest;
            private readonly double minProbability;
            protected readonly int primeBitLength;
            protected readonly RandomNumberGenerator random;

            // Standard public exponent
            private static readonly BigInteger PUBLIC_EXPONENT = 65537;

            /// <summary>
            /// Constructor of the key generation service.
            /// </summary>
            /// <param name="test">The simplicity test used.</param>
            /// <param name="minProbability">Minimum probability of simplicity [0.5, 1).</param>
            /// <param name="primeBitLength">is the bit length for p and q.</param>
            public KeyGenerationService(PrimalityTest test, double minProbability, int primeBitLength)
            {
                this.primalityTest = GetPrimalityStrategy(test);
                this.minProbability = minProbability;
                this.primeBitLength = primeBitLength;
                this.random = RandomNumberGenerator.Create();
            }

            private static IProbabilisticPrimality GetPrimalityStrategy(PrimalityTest test)
            {
                return test switch
                {
                    PrimalityTest.FERMAT => new Tests.FermatPrimality(),
                    PrimalityTest.MILLER_RABIN => new Tests.MillerRabinPrimality(),
                    PrimalityTest.SOLOVAY_STRASSEN => new Tests.SolovayStrassenPrimality(),
                    _ => throw new ArgumentException("Unknown primality test")
                };
            }

            public KeyPair GenerateKeys()
            {
                BigInteger p, q, n, phi, d;

                while (true)
                {
                    p = GenerateProbablePrime();

                    do
                    {
                        q = GenerateProbablePrime();

                        // Farm attack is effective if |p-q| is small.
                        // We require that p and q differ by a significant amount.
                    } while (p == q || BigInteger.Abs(p - q).GetBitLength() < (primeBitLength / 2 - 100));

                    n = p * q;

                    // phi = (p-1) * (q-1)
                    phi = (p - 1) * (q - 1);

                    if (BigInteger.GreatestCommonDivisor(phi, PUBLIC_EXPONENT) != 1)
                    {
                        continue; // e is not suitable, we generate p and q again
                    }

                    d = NumberTheory.ModInverse(PUBLIC_EXPONENT, phi);

                    // Wiener's attack is effective if d is "too small",
                    // specifically d < N^(1/4)/3
                    // FIPS 186-4 requires d > 2^(nlen/2), where nlen = N.bitLength()
                    BigInteger minD = BigInteger.Pow(2, (int)(n.GetBitLength() / 2));
                    if (d <= minD)
                    {
                        continue;
                    }

                    return new KeyPair(n, PUBLIC_EXPONENT, d);
                }
            }

            protected BigInteger GenerateProbablePrime()
            {
                BigInteger p;
                do
                {
                    p = GenerateRandomBigInteger(primeBitLength);

                    if (p.GetBitLength() < primeBitLength)
                    {
                        p |= BigInteger.One << (primeBitLength - 1);
                    }

                    if ((p & 1) == 0)
                    {
                        p |= 1;
                    }
                } while (!primalityTest.IsProbablyPrime(p, minProbability));
                return p;
            }

            private BigInteger GenerateRandomBigInteger(int bitLength)
            {
                if (bitLength <= 0) return 0;

                byte[] bytes = new byte[(bitLength + 7) / 8];
                random.GetBytes(bytes);

                // Clear bits beyond bitLength
                int excessBits = bytes.Length * 8 - bitLength;
                if (excessBits > 0)
                {
                    bytes[0] &= (byte)(0xFF >> excessBits);
                }

                // Ensure positive
                bytes[bytes.Length - 1] &= 0x7F;

                return new BigInteger(bytes);
            }

            public record KeyPair(BigInteger N, BigInteger e, BigInteger d);
        }

        /// <summary>
        /// Constructor of the main RSA service.
        /// </summary>
        /// <param name="test">The simplicity test used.</param>
        /// <param name="minProbability">Minimum probability of simplicity for p and q [0.5, 1).</param>
        /// <param name="primeBitLength">is the bit length for generating p and q.</param>
        public RsaService(PrimalityTest test, double minProbability, int primeBitLength)
        {
            if (primeBitLength < 512)
            {
                throw new ArgumentException("PrimeBitLength < 512 is not secure for RSA");
            }
            this.keyGenService = new KeyGenerationService(test, minProbability, primeBitLength);
            GenerateNewKeys();
        }

        public void GenerateNewKeys()
        {
            KeyGenerationService.KeyPair pair = this.keyGenService.GenerateKeys();
            this.N = pair.N;
            this.e = pair.e;
            this.d = pair.d;
        }

        // C = M^e mod N
        public BigInteger Encrypt(BigInteger message)
        {
            if (message >= N)
            {
                throw new ArgumentException("Message must be less than N");
            }

            return NumberTheory.ModPow(message, e, N);
        }

        // M = C^d mod N
        public BigInteger Decrypt(BigInteger ciphertext)
        {
            return NumberTheory.ModPow(ciphertext, d, N);
        }

        public BigInteger GetN() => N;
        public BigInteger GetE() => e;
        public BigInteger GetD() => d;
    }
}
