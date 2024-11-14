using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace Lab3
{
    class Program
    {
        public static byte[] encryptedSimmetricKey, encryptedSimmetricIV, signedEncryptedMessage;
        public static RSAParameters publicKey, privateKey, publicSignedKey, signPublicKeyFile;
        public static int max_value = 2048; //Длина ключей RSA

        static void Main(string[] args)
        {
            menu();
        }

        static void menu()
        {
            while (true)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Что хотите сделать?");
                Console.ResetColor();
                Console.WriteLine("1. Шифрование и расшифрование документа");
                Console.WriteLine("2. Формирование и проверка цифровой подписи документа");
                Console.WriteLine("3. Закрыть программу");

                Console.WriteLine();
                string m_old = Console.ReadLine();
                Console.WriteLine();

                if (m_old == "1")
                {
                    symmetric_cryptoalgorithm();
                }
                else
                {
                    if (m_old == "2")
                    {
                        one_check_digital_signature();
                    }
                    else
                    {
                        if (m_old == "3")
                        {
                            break;
                        }
                        else
                        {
                            Console.WriteLine("Что-то пошло не так :)");
                        }
                    }
                }
            }
        }

        static void one_check_digital_signature()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Что хотите сделать теперь?");
            Console.ResetColor();

            Console.WriteLine("1. Подписать");
            Console.WriteLine("2. Проверить подпись");
            Console.WriteLine("3. Я тут случайно, пустите назад :'(");

            Console.WriteLine();
            string m = Console.ReadLine();
            Console.WriteLine();

            if (m == "1")
            {
                digital_signature();
            } else
            {
                if (m == "2")
                {
                    check_digital_signature();
                } else
                {
                    if (m == "3")
                    {
                        menu();
                    } else
                    {
                        Console.WriteLine("Что-то пошло не так :)");
                    }
                }
            }
        }

        //Функция проверки подписи
        static void check_digital_signature()
        {
            Console.Write("Введите название файла для проверки подписи: ");
            string file_input = Console.ReadLine(); //sign.encr
            Console.WriteLine();

            if (!File.Exists($"{file_input}.encr"))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Файла не существует.");
                Console.ResetColor();
                Console.WriteLine();
                return;
            }

            signedEncryptedMessage = File.ReadAllBytes($"{file_input}.encr");

            Console.Write("Введите название файла для RSA подписи: ");
            file_input = Console.ReadLine(); //signRSAKeys.encr
            Console.WriteLine();

            if ((!File.Exists($"{file_input}_e.encr")) || (!File.Exists($"{file_input}_n.encr")))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Файла не существует.");
                Console.ResetColor();
                Console.WriteLine();
                return;
            }

            //Считыванеи открытого ключа из файлов
            signPublicKeyFile.Modulus = File.ReadAllBytes($"{file_input}_n.encr");
            signPublicKeyFile.Exponent = File.ReadAllBytes($"{file_input}_e.encr");

            //Создание экземпляра класса RSA
            RSA signedRsa = RSA.Create(max_value);

            //Применение нужного открытого ключа (из файла) для данного экземпляра RSA
            signedRsa.ImportParameters(signPublicKeyFile);

            Console.Write("Введите название изначального файла для проверки подписи: ");
            file_input = Console.ReadLine(); //in.txt
            Console.WriteLine();

            if (!File.Exists($"{file_input}.txt"))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Файла не существует.");
                Console.ResetColor();
                Console.WriteLine();
                return;
            }

            //Считывание изначального файла для проверки подписи
            string in_txt = String.Join("\n", File.ReadAllLines($"{file_input}.txt"));
            byte[] message = Encoding.UTF8.GetBytes(in_txt);

            //Проверка подписи (входные данные: изначальный файл, подписанный файл, алгоритм хэширования, стандарт RSA)
            if (signedRsa.VerifyData(message, signedEncryptedMessage, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Подпись подошла");
                Console.ResetColor();
                Console.WriteLine();
            } else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Подпись не подошла");
                Console.ResetColor();
                Console.WriteLine();
            }
        }

        //Функция формирования подписи
        static void digital_signature()
        {
            Console.Write("Введите название файла для подписи: ");
            string file_input = Console.ReadLine(); //in.txt
            Console.WriteLine();

            if (!File.Exists($"{file_input}.txt"))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Файла не существует.");
                Console.ResetColor();
                Console.WriteLine();
                return;
            }

            string in_txt = String.Join("\n", File.ReadAllLines($"{file_input}.txt"));
            byte[] message = Encoding.UTF8.GetBytes(in_txt);

            //Создание экземпляра класса RSA
            RSA signedRsa = RSA.Create();

            //Сохранение публичного ключа
            publicSignedKey = signedRsa.ExportParameters(false);

            Console.Write("Введите название файла для сохранения RSA для подписи: ");
            file_input = Console.ReadLine(); //signRSAKeys.xml
            Console.WriteLine();

            File.WriteAllBytes($"{file_input}_n.encr", publicSignedKey.Modulus/*n*/);
            File.WriteAllBytes($"{file_input}_e.encr", publicSignedKey.Exponent/*e*/);

            //функция формирования цифровой подписи (к хэшированному сообщению)
            signedEncryptedMessage = signedRsa.SignData(message, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            Console.Write("Введите название файла для хранения подписанного документа: ");
            file_input = Console.ReadLine(); //sign.encr
            Console.WriteLine();

            File.WriteAllBytes($"{file_input}.encr", signedEncryptedMessage);
        }

        static void symmetric_cryptoalgorithm()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Что хотите сделать теперь?");
            Console.ResetColor();
            Console.WriteLine("1. Шифрование");
            Console.WriteLine("2. Расшифрование");
            Console.WriteLine("3. Я тут случайно, пустите назад :'(");

            Console.WriteLine();
            string m_old = Console.ReadLine();
            Console.WriteLine();

            if (m_old == "1")
            {
                aes_symmetric_cryptoalgorithm();
            }
            else
            {
                if (m_old == "2")
                {
                    deaes_symmetric_cryptoalgorithm();
                }
                else
                {
                    if (m_old == "3")
                    {
                        menu();
                    }
                    else
                    {
                        Console.WriteLine("Что-то пошло не так :)");
                    }
                }
            }
        }

        //Функция расшифровки документа
        static void deaes_symmetric_cryptoalgorithm()
        {
            Console.Write("Введите пароль получателя для расшифровки: ");
            string password = Console.ReadLine(); //Send/RSAKeys.bin

            //Доступ к закрытому ключу защищен паролем
            if (password == "qwerty")
            {
                //Создание экземпляра класса RSA
                RSA uploadedRSA = RSA.Create(max_value);
                Console.WriteLine();
                Console.Write("Введите название файла RSA: ");
                string file_input = Console.ReadLine(); //RSAKeys.xml
                Console.WriteLine();

                if (!File.Exists($"Secret/{file_input}.xml"))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Файла не существует.");
                    Console.ResetColor();
                    Console.WriteLine();
                    return;
                }

                //Считывание информации о сохраненных параметрах RSA (закрытого ключа) для расшифровки
                uploadedRSA.FromXmlString(File.ReadAllText($"Secret/{file_input}.xml"));
                //Присваивание переменной данных закрытого ключа из файла
                privateKey = uploadedRSA.ExportParameters(true);
                //Создание экземпляра класса RSA
                RSA rsa = RSA.Create(max_value);
                //Применение нужного закрытого ключа (из файла) для данного экземпляра RSA
                rsa.ImportParameters(privateKey);

                //Создание экземпляра класса Aes
                Aes uploadedAes = Aes.Create();

                Console.Write("Введите название файла сеансового ключа: ");
                file_input = Console.ReadLine(); //AESkey.encr
                Console.WriteLine();

                if (!File.Exists($"{file_input}.encr"))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Файла не существует.");
                    Console.ResetColor();
                    Console.WriteLine();
                    return;
                }
                //Расшифрование сеансового ключа алгоритмом RSA
                uploadedAes.Key = rsa.Decrypt(File.ReadAllBytes($"{file_input}.encr"), RSAEncryptionPadding.Pkcs1);

                Console.Write("Введите название файла вектора инициализации: ");
                file_input = Console.ReadLine(); //AESIV.encr
                Console.WriteLine();

                if (!File.Exists($"{file_input}.encr"))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Файла не существует.");
                    Console.ResetColor();
                    Console.WriteLine();
                    return;
                }

                //Расшифрование вектора инициализации алгоритмом RSA
                uploadedAes.IV = rsa.Decrypt(File.ReadAllBytes($"{file_input}.encr"), RSAEncryptionPadding.Pkcs1);

                Console.Write("Введите название файла с защифрованным сообщением: ");
                file_input = Console.ReadLine(); //shifr.encr
                Console.WriteLine();

                if (!File.Exists($"{file_input}.encr"))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Файла не существует.");
                    Console.ResetColor();
                    Console.WriteLine();
                    return;
                }

                var in_txt = File.ReadAllBytes($"{file_input}.encr");

                //Вызов функции расшифрования документа алгоритмом AES с использованием расшированных сеансового ключа и вектора инициализации
                string roundtrip = DecryptStringFromBytes_Aes(in_txt, uploadedAes.Key, uploadedAes.IV);

                Console.Write("Введите название файла для сохранения результата расшифровки: ");
                string file_out = Console.ReadLine(); //in2.txt
                Console.WriteLine();
                File.WriteAllText($"{file_out}.txt", roundtrip);

            } else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Пароль не верен. В доступе отказано.");
                Console.ResetColor();
            }
        }

        //Функция шифрования документа
        static void aes_symmetric_cryptoalgorithm()
        {
            Console.Write("Введите название файла для шифрования: ");
            string file_input = Console.ReadLine(); //in.txt
            Console.WriteLine();

            if (!File.Exists($"{file_input}.txt"))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Файла не существует.");
                Console.ResetColor();
                Console.WriteLine();
                return;
            }

            string in_txt = String.Join("\n", File.ReadAllLines($"{file_input}.txt"));

            //Создание экземпляра класса Aes
            Aes myAes = Aes.Create();

            //Запись в переменные сеансового ключа и вектора инициализации
            byte[] key = myAes.Key;
            byte[] IV = myAes.IV;

            //Вызов функции шифрования документа с использованием сеансового ключа и вектора инициализации
            byte[] encrypted = EncryptStringToBytes_Aes(in_txt, key, IV);

            //Создание экземпляра класса RSA
            RSA rsa = RSA.Create(max_value);

            //true, чтобы использовать закрытый ключ, в противном случае открытый (false)
            //Сохранение RSA ключей
            publicKey = rsa.ExportParameters(false);
            privateKey = rsa.ExportParameters(true);

            Console.Write("Введите название файла для сохранения RSA: ");
            file_input = Console.ReadLine(); //RSAKey.encr
            Console.WriteLine();

            File.WriteAllBytes($"{file_input}_n.encr", publicKey.Modulus/*n*/);
            File.WriteAllBytes($"{file_input}_e.encr", publicKey.Exponent/*e*/);

            File.WriteAllText($"Secret/{file_input}.xml", rsa.ToXmlString(true));

            //Шифрование сеансового ключа алгоритмом RSA
            encryptedSimmetricKey = rsa.Encrypt(key, RSAEncryptionPadding.Pkcs1);
            //Шифрование вектора инициализации алгоритмом RSA
            encryptedSimmetricIV = rsa.Encrypt(IV, RSAEncryptionPadding.Pkcs1);

            Console.Write("Введите название файла для сохранения сеансового ключа: ");
            file_input = Console.ReadLine(); //AESkey.encr
            Console.WriteLine();
            File.WriteAllBytes($"{file_input}.encr", encryptedSimmetricKey);

            Console.Write("Введите название файла для сохранения вектора инициализации: ");
            file_input = Console.ReadLine(); //AESIV.encr
            Console.WriteLine();
            File.WriteAllBytes($"{file_input}.encr", encryptedSimmetricIV);

            Console.Write("Введите название файла для сохранения зашифрованного сообщения: ");
            file_input = Console.ReadLine(); //shifr.encr
            Console.WriteLine();
            File.WriteAllBytes($"{file_input}.encr", encrypted);

        }

        //Функция шифрования алгоритмом AES
        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Создание переменной для записи зашифрованного текста
            byte[] encrypted;

            // Создание экземпляра класса AES
            using (Aes aesAlg = Aes.Create())
            {
                // Использование конкретных сеансового ключа и вектора инициализации для данного экземпляра AES
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Создание шифратора
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Создание потоков, используемых для шифрования
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            // Запись зашифрованной строки в байтовый массив
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            
            return encrypted;
        }

        //Функция расшифрования алгоритмом AES
        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Создание переменной для записи расшифрованного текста
            string plaintext = null;

            // Создание экземпляра класса AES
            using (Aes aesAlg = Aes.Create())
            {
                // Использование конкретных сеансового ключа и вектора инициализации для данного экземпляра AES
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Создание дешифратора
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Создание потоков, используемых для дешифрования
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Запись расшифрованных байтов в строку
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    }
}