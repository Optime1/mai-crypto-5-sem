using System;
using Dora.Crypto.Block;
using Dora.Crypto.Block.Des;
using Dora.Crypto.BlockCiphers;

namespace Dora.Crypto
{
    public enum CipherType
    {
        DES,
        TripleDES,
        DEAL_128, // 6 раундов
        DEAL_192, // 8 раундов
        DEAL_256  // 10 раундов
    }

    class Program
    {
        static void Main(string[] args)
        {
            // === НАСТРОЙКИ ===
            // Выберите алгоритм здесь:
            CipherType selectedCipher = CipherType.DEAL_128; 
            
            // Исходные данные (должны быть кратны размеру блока алгоритма)
            // Для DES/TripleDES: 8 байт
            // Для DEAL: 16 байт
            byte[] plainText;
            byte[] key;

            if (selectedCipher == CipherType.DES)
            {
                key = ParseHex("133457799BBCDFF1"); // 8 байт
                plainText = ParseHex("0123456789ABCDEF"); // 8 байт
            }
            else if (selectedCipher == CipherType.TripleDES)
            {
                // Ключ 16 или 24 байта. Здесь 24 байта (3 ключа DES)
                key = ParseHex("0123456789ABCDEF FEDCBA9876543210 0123456789ABCDEF"); 
                plainText = ParseHex("0123456789ABCDEF"); // 8 байт
            }
            else if (selectedCipher == CipherType.DEAL_128)
            {
                key = ParseHex("0123456789ABCDEF FEDCBA9876543210"); // 16 байт
                plainText = ParseHex("0011223344556677 8899AABBCCDDEEFF"); // 16 байт
            }
            else if (selectedCipher == CipherType.DEAL_192)
            {
                key = ParseHex("0123456789ABCDEF FEDCBA9876543210 0123456789ABCDEF"); // 24 байта
                plainText = ParseHex("0011223344556677 8899AABBCCDDEEFF"); // 16 байт
            }
            else if (selectedCipher == CipherType.DEAL_256)
            {
                key = ParseHex("0123456789ABCDEF FEDCBA9876543210 0123456789ABCDEF FEDCBA9876543210"); // 32 байта
                plainText = ParseHex("0011223344556677 8899AABBCCDDEEFF"); // 16 байт
            }
            else
            {
                throw new ArgumentException("Неизвестный тип шифра");
            }

            Console.WriteLine($"=== Тест шифрования: {selectedCipher} ===");
            Console.WriteLine($"Ключ:      {ToHex(key)}");
            Console.WriteLine($"Открытый текст: {ToHex(plainText)}");

            try
            {
                IBlockCipher cipher = CreateCipher(selectedCipher, key);
                
                // Шифрование
                byte[] cipherText = new byte[plainText.Length];
                cipherText = cipher.Encrypt(plainText);

                Console.WriteLine($"Шифротекст: {ToHex(cipherText)}");

                // Дешифрование
                byte[] decryptedText = cipher.Decrypt(cipherText);

                Console.WriteLine($"Расшифровано: {ToHex(decryptedText)}");

                // Проверка
                bool success = AreEqual(plainText, decryptedText);
                if (success)
                {
                    Console.WriteLine("\n✓ УСПЕХ: Расшифрованный текст совпадает с оригиналом!");
                }
                else
                {
                    Console.WriteLine("\n✗ ОШИБКА: Тексты не совпадают!");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n✗ ОШИБКА ВЫПОЛНЕНИЯ: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }

            // Console.WriteLine("\nНажмите любую клавишу для выхода...");
            // Console.ReadKey();
        }

        static IBlockCipher CreateCipher(CipherType type, byte[] key)
        {
            switch (type)
            {
                case CipherType.DES:
                    return new DesBlockCipher();
                case CipherType.TripleDES:
                    return new TripleDesBlockCipher();
                case CipherType.DEAL_128:
                case CipherType.DEAL_192:
                case CipherType.DEAL_256:
                    return new DealBlockCipher(key);
                default:
                    throw new ArgumentException("Неподдерживаемый шифр");
            }
        }

        // Вспомогательные методы
        static byte[] ParseHex(string hex)
        {
            hex = hex.Replace(" ", "").Replace("-", "");
            if (hex.Length % 2 != 0) throw new ArgumentException("Неверная длина HEX строки");
            
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        static string ToHex(byte[] data)
        {
            return BitConverter.ToString(data).Replace("-", " ");
        }

        static bool AreEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i]) return false;
            }
            return true;
        }
    }
}
