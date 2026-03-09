using System;
using Dora.Crypto.Block;
using Dora.Crypto.Block.Des;

namespace Dora.Crypto.Test
{
    public class Program
    {
        public static void Main()
        {
            // Создаём экземпляр DES
            IBlockCipher des = new DesBlockCipher();

            // Ключ 8 байт (64 бита, включая биты чётности)
            byte[] key = new byte[] { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };

            // Открытый текст 8 байт (64 бита)
            byte[] plaintext = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

            Console.WriteLine("DES Encryption Test");
            Console.WriteLine("===================");
            Console.WriteLine($"Key:       {BitConverter.ToString(key)}");
            Console.WriteLine($"Plaintext: {BitConverter.ToString(plaintext)}");

            // Инициализация шифра
            des.Init(key);

            // Шифрование
            byte[] ciphertext = des.Encrypt(plaintext);
            Console.WriteLine($"Ciphertext: {BitConverter.ToString(ciphertext)}");

            // Дешифрование
            byte[] decrypted = des.Decrypt(ciphertext);
            Console.WriteLine($"Decrypted:  {BitConverter.ToString(decrypted)}");

            // Проверка
            bool success = true;
            for (int i = 0; i < plaintext.Length; i++)
            {
                if (plaintext[i] != decrypted[i])
                {
                    success = false;
                    break;
                }
            }

            Console.WriteLine();
            if (success)
            {
                Console.WriteLine("✓ SUCCESS: Decrypted text matches original!");
            }
            else
            {
                Console.WriteLine("✗ FAILED: Decrypted text does not match!");
            }
        }
    }
}
