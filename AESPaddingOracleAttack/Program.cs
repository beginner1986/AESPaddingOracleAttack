﻿using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;

namespace AESPaddingOracleAttack
{
    class Program
    {
        static void Main(string[] args)
        {
            // get plain text from the console
            Console.WriteLine("AES CBC padding oracle attack");
            Console.WriteLine("Adam Emieljaniuk 2019");
            Console.WriteLine();
            Console.WriteLine("Tekst jawny: ");
            string plain = Console.ReadLine();
            Console.WriteLine();

            // config AES parameters
            using AesManaged aes = ConfigAes();

            // conduct plain text encryption
            byte[] encrypted = Encrypt(plain, aes.Key, aes.IV);

            // print encrypted text in console
            Console.WriteLine("Szyfrogram w ASCII: ");
            Console.WriteLine(System.Text.Encoding.UTF8.GetString(encrypted));
            Console.WriteLine();
            Console.WriteLine("Szyfrogram w hex: ");
            Console.WriteLine(BitConverter.ToString(encrypted).Replace("-", " "));
            Console.WriteLine();

            /*
            // cipher text decryption by AES
            string decrypted = Decrypt(encrypted, aes.Key, aes.IV);
            Console.WriteLine("Tekst odszyfrowany algorytmem AES: ");
            Console.WriteLine(decrypted);
            Console.WriteLine();
            */

            /*
            // DEBUG: check if padding ecxeption occures
            // createing garbage data
            byte[] garbage = { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
            IEnumerable<byte> testData = encrypted.Concat(garbage);

            // check if padding error coours during decryption try
            try
            {
                Decrypt(testData.ToArray(), aes.Key, aes.IV);
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
            }
            */

            // padding check function
            bool CheckPadding(byte[] encrypted)
            {
                try
                {
                    // if there is no padding error return true - padding correct
                    Decrypt(encrypted, aes.Key, aes.IV);
                    return true;
                }
                catch (CryptographicException e)
                {
                    // if padding error occurs return false - padding incorrect
                    if (e.Message.Contains("Padding") || e.Message.Contains("padding"))
                    {
                        return false;
                    }

                    // else return true - other exception occured
                    return true;
                }
            }

            // Oracle padding attack
            // timer for performance testing
            Stopwatch timer = new Stopwatch();
            timer.Start();
            Oracle oracle = new Oracle(CheckPadding, encrypted, 16);
            byte[] attackResult = oracle.Decrypt();
            timer.Stop();

            Console.WriteLine($"Tekst odczytany za pomocą AES Oracle Padding Attack ({attackResult.Length} bajtów): ");
            Console.WriteLine(System.Text.Encoding.UTF8.GetString(attackResult));
            Console.WriteLine();
            Console.WriteLine("Czaswykonania ataku: {0}s.", timer.Elapsed);
        }

        static AesManaged ConfigAes()
        {
            AesManaged aes = new AesManaged
            {

                // initial vector (temporary hardcoded, in future random)
                IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                // key (temporary hardcoded, in future random)
                Key = Encoding.ASCII.GetBytes("1122334455667788"),
                // set padding to PCKS7
                Padding = PaddingMode.PKCS7,
                // set cipher mode to CBC
                Mode = CipherMode.CBC,
                // set block size tp 128 bits (16 bytes)
                BlockSize = 128
            };

            return aes;
        }

        static byte[] Encrypt(string plain, byte[] key, byte[] iv)
        {
            // array to store encrypted text
            byte[] result;

            // get the configuration given in the function call to ceate encryptor
            using (AesManaged aes = new AesManaged())
            {
                ICryptoTransform encryptor = aes.CreateEncryptor(key, iv);

                // create memory streem that will be sent to crypto stream
                using (MemoryStream ms = new MemoryStream())
                {
                    // create the crypto stream that is key fpr encrptiopn / decryption
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        // write the data by the stream writer to the crypto stream
                        using (StreamWriter sw = new StreamWriter(cs))
                            sw.Write(plain);
                        // put the encrypted data to the result array
                        result = ms.ToArray();
                    }
                }
            }

            // return array of encrypted bytes
            return result;
        }

        static string Decrypt(byte[] encrypted, byte[] key, byte[] iv)
        {
            string result = null;

            // get the configuration given in the function call to ceate decryptor
            using (AesManaged aes = new AesManaged())
            {
                ICryptoTransform decryptor = aes.CreateDecryptor(key, iv);

                // create memory streem that will be sent to crypto stream
                using (MemoryStream ms = new MemoryStream(encrypted))
                {
                    // create the crypto stream that is key fpr encrptiopn / decryption
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        // read the data by the stream reader from the crypto stream
                        using (StreamReader sr = new StreamReader(cs))
                            result = sr.ReadToEnd();
                    }
                }
            }

            // return string with decrypted text
            return result;
        }
    }
}
