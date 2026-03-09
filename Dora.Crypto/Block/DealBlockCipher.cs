using System;
using Dora.Crypto.Block;

namespace Dora.Crypto.BlockCiphers
{
    /// <summary>
    /// DEAL (Data Encryption Algorithm with Large block size)
    /// Блочный шифр с размером блока 128 бит и переменным количеством раундов:
    /// - 128-битный ключ: 6 раундов
    /// - 192-битный ключ: 8 раундов  
    /// - 256-битный ключ: 10 раундов
    /// </summary>
    public class DealBlockCipher : IBlockCipher
    {
        private const int BLOCK_SIZE = 16; // 128 бит
        private byte[] key;
        private int rounds;

        // S-boxes из DES (те же самые)
        private static readonly byte[,,] S = new byte[8, 4, 16];

        static DealBlockCipher()
        {
            InitSBoxes();
        }

        private static void InitSBoxes()
        {
            // S1
            byte[,] s1 = {
                {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
                {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
                {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
            };
            // S2
            byte[,] s2 = {
                {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
                {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
                {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
                {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
            };
            // S3
            byte[,] s3 = {
                {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
                {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
                {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
                {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
            };
            // S4
            byte[,] s4 = {
                {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
                {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
                {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
                {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
            };
            // S5
            byte[,] s5 = {
                {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
                {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
                {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
                {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
            };
            // S6
            byte[,] s6 = {
                {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
                {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
                {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
            };
            // S7
            byte[,] s7 = {
                {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
            };
            // S8
            byte[,] s8 = {
                {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
                {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
                {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
                {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
            };

            CopySBox(s1, 0);
            CopySBox(s2, 1);
            CopySBox(s3, 2);
            CopySBox(s4, 3);
            CopySBox(s5, 4);
            CopySBox(s6, 5);
            CopySBox(s7, 6);
            CopySBox(s8, 7);
        }

        private static void CopySBox(byte[,] src, int index)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 16; j++)
                    S[index, i, j] = src[i, j];
        }

        public int BlockSize() => BLOCK_SIZE;

        public void Init(byte[] key)
        {
            this.key = key;
            int keyLen = key.Length * 8;

            if (keyLen == 128)
                rounds = 6;
            else if (keyLen == 192)
                rounds = 8;
            else if (keyLen == 256)
                rounds = 10;
            else
                throw new ArgumentException($"Неверная длина ключа DEAL: {keyLen} бит. Должно быть 128, 192 или 256.");
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
            if (plaintext.Length != BLOCK_SIZE)
                throw new ArgumentException($"Длина plaintext должна быть {BLOCK_SIZE} байт");

            ulong L = GetWord(plaintext, 0);
            ulong R = GetWord(plaintext, 8);

            for (int round = 0; round < rounds; round += 2)
            {
                ulong tempL = L;
                L = R ^ F(L, round);
                R = tempL;

                ulong tempR = R;
                R = L ^ F(R, round + 1);
                L = tempR;
            }

            byte[] result = new byte[BLOCK_SIZE];
            PutWord(result, 0, L);
            PutWord(result, 8, R);
            return result;
        }

        public byte[] Decrypt(byte[] ciphertext)
        {
            if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
            if (ciphertext.Length != BLOCK_SIZE)
                throw new ArgumentException($"Длина ciphertext должна быть {BLOCK_SIZE} байт");

            ulong L = GetWord(ciphertext, 0);
            ulong R = GetWord(ciphertext, 8);

            for (int round = rounds - 2; round >= 0; round -= 2)
            {
                ulong tempR = R;
                R = L ^ F(R, round + 1);
                L = tempR;

                ulong tempL = L;
                L = R ^ F(L, round);
                R = tempL;
            }

            byte[] result = new byte[BLOCK_SIZE];
            PutWord(result, 0, L);
            PutWord(result, 8, R);
            return result;
        }

        private ulong GetWord(byte[] input, int offset)
        {
            return ((ulong)input[offset] << 56) |
                   ((ulong)input[offset + 1] << 48) |
                   ((ulong)input[offset + 2] << 40) |
                   ((ulong)input[offset + 3] << 32) |
                   ((ulong)input[offset + 4] << 24) |
                   ((ulong)input[offset + 5] << 16) |
                   ((ulong)input[offset + 6] << 8) |
                   ((ulong)input[offset + 7]);
        }

        private void PutWord(byte[] output, int offset, ulong word)
        {
            output[offset] = (byte)(word >> 56);
            output[offset + 1] = (byte)(word >> 48);
            output[offset + 2] = (byte)(word >> 40);
            output[offset + 3] = (byte)(word >> 32);
            output[offset + 4] = (byte)(word >> 24);
            output[offset + 5] = (byte)(word >> 16);
            output[offset + 6] = (byte)(word >> 8);
            output[offset + 7] = (byte)word;
        }

        private ulong F(ulong input, int round)
        {
            uint left = (uint)(input >> 32);
            uint right = (uint)(input & 0xFFFFFFFF);

            left = DesRoundFunction(left, round);
            right = DesRoundFunction(right, round);

            return ((ulong)left << 32) | right;
        }

        private uint DesRoundFunction(uint input, int round)
        {
            uint expanded = Expand(input);

            // Генерация части подключа из основного ключа
            uint keyPart = GetRoundKeyPart(round);
            uint xored = expanded ^ keyPart;

            uint sOutput = ApplySBoxes(xored);
            return PermuteP(sOutput);
        }

        private uint GetRoundKeyPart(int round)
        {
            // Упрощенная генерация подключа из основного ключа
            int offset = (round * 4) % (key.Length - 3);
            return (uint)(key[offset] << 24 | key[offset + 1] << 16 | key[offset + 2] << 8 | key[offset + 3]);
        }

        private uint Expand(uint input)
        {
            uint result = 0;
            int[] eTable = {
                31, 0, 1, 2, 3, 4,
                3, 4, 5, 6, 7, 8,
                7, 8, 9, 10, 11, 12,
                11, 12, 13, 14, 15, 16,
                15, 16, 17, 18, 19, 20,
                19, 20, 21, 22, 23, 24,
                23, 24, 25, 26, 27, 28,
                27, 28, 29, 30, 31, 0
            };

            for (int i = 0; i < 48; i++)
            {
                int bitPos = eTable[i];
                if (((input >> (31 - bitPos)) & 1) == 1)
                {
                    result |= (1u << (47 - i));
                }
            }

            return result;
        }

        private uint ApplySBoxes(uint input)
        {
            uint result = 0;
            for (int i = 0; i < 8; i++)
            {
                int bits = (int)((input >> (42 - i * 6)) & 0x3F);
                int row = ((bits & 0x20) >> 4) | (bits & 0x01);
                int col = (bits >> 1) & 0x0F;
                int sVal = S[i, row, col];
                result |= (uint)(sVal << (28 - i * 4));
            }
            return result;
        }

        private uint PermuteP(uint input)
        {
            int[] pTable = {
                15, 6, 19, 20, 28, 11, 27, 16,
                0, 14, 22, 25, 4, 17, 30, 9,
                1, 7, 23, 13, 31, 26, 2, 8,
                18, 12, 29, 5, 21, 10, 3, 24
            };

            uint result = 0;
            for (int i = 0; i < 32; i++)
            {
                if (((input >> (31 - pTable[i])) & 1) == 1)
                {
                    result |= (1u << (31 - i));
                }
            }

            return result;
        }
    }
}
