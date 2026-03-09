using System;
using Dora.Crypto.Block.Des;
using Dora.Crypto.Block;

namespace Dora.Crypto.BlockCiphers
{
    /// <summary>
    /// TripleDES (3DES) - режим EDE (Encrypt-Decrypt-Encrypt)
    /// Использует три ключа DES (или два, если первый и третий совпадают)
    /// Размер блока: 8 байт (64 бита)
    /// Размер ключа: 16 или 24 байта
    /// </summary>
    public class TripleDesBlockCipher : IBlockCipher
    {
        private const int BLOCK_SIZE = 8; // 64 бита
        
        private DesBlockCipher des1;
        private DesBlockCipher des2;
        private DesBlockCipher des3;
        
        private bool forEncryption;

        public int BlockSize() => BLOCK_SIZE;

        public TripleDesBlockCipher()
        {
            des1 = new DesBlockCipher();
            des2 = new DesBlockCipher();
            des3 = new DesBlockCipher();
        }

        public void Init(byte[] key)
        {
            int keyLen = key.Length;
            
            if (keyLen == 16)
            {
                // Двухключевой вариант: K1, K2, K1
                des1.Init(ExtractKey(key, 0, 8));
                des2.Init(ExtractKey(key, 8, 8));
                des3.Init(ExtractKey(key, 0, 8));
            }
            else if (keyLen == 24)
            {
                // Трехключевой вариант: K1, K2, K3
                des1.Init(ExtractKey(key, 0, 8));
                des2.Init(ExtractKey(key, 8, 8));
                des3.Init(ExtractKey(key, 16, 8));
            }
            else
            {
                throw new ArgumentException($"Неверная длина ключа TripleDES: {keyLen} байт. Должно быть 16 или 24.");
            }
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
            if (plaintext.Length != BLOCK_SIZE)
                throw new ArgumentException($"Длина plaintext должна быть {BLOCK_SIZE} байт");

            // Режим EDE: Encrypt -> Decrypt -> Encrypt
            byte[] temp = des1.Encrypt(plaintext);      // E1
            temp = des2.Decrypt(temp);                  // D2
            return des3.Encrypt(temp);                  // E3
        }

        public byte[] Decrypt(byte[] ciphertext)
        {
            if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
            if (ciphertext.Length != BLOCK_SIZE)
                throw new ArgumentException($"Длина ciphertext должна быть {BLOCK_SIZE} байт");

            // Обратный режим: Decrypt -> Encrypt -> Decrypt
            byte[] temp = des3.Decrypt(ciphertext);     // D3
            temp = des2.Encrypt(temp);                  // E2
            return des1.Decrypt(temp);                  // D1
        }

        private byte[] ExtractKey(byte[] key, int offset, int length)
        {
            byte[] result = new byte[length];
            Array.Copy(key, offset, result, 0, length);
            return result;
        }
    }
}
