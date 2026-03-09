using System;
using Dora.Crypto.Core;
using Dora.Crypto.Des;

namespace Dora.Crypto
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== Тестирование алгоритма DES ===");

            // 1. Инициализация шифра
            var des = new DesBlockCipher();
            
            // 2. Подготовка ключа (8 байт)
            // Пример ключа из тестов: 13-34-57-79-9B-BC-DF-F1
            byte[] key = new byte[] 
            { 
                0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 
            };

            // 3. Подготовка данных для шифрования (8 байт - один блок)
            byte[] plainText = new byte[] 
            { 
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF 
            };

            Console.WriteLine($"Исходный текст (hex): {BitConverter.ToString(plainText)}");
            Console.WriteLine($"Ключ (hex): {BitConverter.ToString(key)}");

            // 4. Шифрование
            byte[] cipherText = new byte[8];
            des.Init(true, new DesKeySchedule(key));
            des.ProcessBlock(plainText, 0, cipherText, 0);

            Console.WriteLine($"Зашифрованный текст (hex): {BitConverter.ToString(cipherText)}");

            // 5. Расшифрование
            byte[] decryptedText = new byte[8];
            des.Init(false, new DesKeySchedule(key));
            des.ProcessBlock(cipherText, 0, decryptedText, 0);

            Console.WriteLine($"Расшифрованный текст (hex): {BitConverter.ToString(decryptedText)}");

            // 6. Проверка результата
            bool isSuccess = true;
            for (int i = 0; i < 8; i++)
            {
                if (plainText[i] != decryptedText[i])
                {
                    isSuccess = false;
                    break;
                }
            }

            if (isSuccess)
            {
                Console.WriteLine("\n[УСПЕХ] Расшифрованный текст совпадает с исходным!");
            }
            else
            {
                Console.WriteLine("\n[ОШИБКА] Тексты не совпадают!");
            }

            Console.WriteLine("\nНажмите любую клавишу для выхода...");
            Console.ReadKey();
        }
    }
}
