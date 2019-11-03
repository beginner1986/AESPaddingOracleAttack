using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AESPaddingOracleAttack
{
    class Program
    {
        static void Main(string[] args)
        {
            // plain text to encode
            string plain = "Hello World!";
            Console.WriteLine("Tekst jawny: ");
            Console.WriteLine(plain);
            Console.WriteLine();

            // config AES parameters
            AesManaged aes = ConfigAes();

            // conduct plain text encryption
            byte[] encrypted = Encrypt(plain, aes.Key, aes.IV);

            // print encrypted text in console
            Console.WriteLine("Szyfrogram: ");
            Console.WriteLine(System.Text.Encoding.UTF8.GetString(encrypted));
            Console.WriteLine();

            // conduct cipher text decryption
            string decrypted = Decrypt(encrypted, aes.Key, aes.IV);
            Console.WriteLine("Odszyfrowany tekst: ");
            Console.WriteLine(decrypted);
        }

        static AesManaged ConfigAes()
        {
            AesManaged aes = new AesManaged();

            // initial vector (temporary hardcoded, in future random)
            aes.IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            // key (temporary hardcoded, in future random)
            aes.Key = Encoding.ASCII.GetBytes("1122334455667788");
            // set padding to PCKS7
            aes.Padding = PaddingMode.PKCS7;
            // set cipher mode to CBC
            aes.Mode = CipherMode.CBC;

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
