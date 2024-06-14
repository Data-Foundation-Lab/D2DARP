using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace D2DARP.Common
{
    public class Tools
    {
        public class AES256
        {
            public static void Encrypt(byte[] key, byte[] iv, byte[] data, out byte[] encryptedData)
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Padding = PaddingMode.PKCS7;  // Ensure padding is used

                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV); 

                    encryptedData = encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }

            public static void Decrypt(byte[] key, byte[] iv, byte[] data, out byte[] decryptedData)
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Padding = PaddingMode.PKCS7;  // Ensure padding is used

                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    decryptedData = decryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        public class RSA
        {
            public static System.Security.Cryptography.RSAParameters LoadRSAParametersFromString(string rsaKey, bool isPrivate)
            {
                using (System.Security.Cryptography.RSA rsa = System.Security.Cryptography.RSA.Create())
                {
                    rsa.ImportFromPem(rsaKey.ToCharArray());
                    return rsa.ExportParameters(isPrivate ? true : false);
                }
            }

            private static IEnumerable<byte[]> ChunkData(byte[] data, int chunkSize)
            {
                for (int i = 0; i < data.Length; i += chunkSize)
                {
                    int size = Math.Min(chunkSize, data.Length - i);
                    byte[] chunk = new byte[size];
                    Array.Copy(data, i, chunk, 0, size);
                    yield return chunk;
                }
            }

            public static byte[] DoubleEncrypt(byte[] data, RSAParameters pubKey1, RSAParameters pubKey2)
            {
                const int paddingOverhead = 11;
                using (System.Security.Cryptography.RSA rsa1 = System.Security.Cryptography.RSA.Create())
                using (System.Security.Cryptography.RSA rsa2 = System.Security.Cryptography.RSA.Create())
                {
                    rsa1.ImportParameters(pubKey1);
                    rsa2.ImportParameters(pubKey2);

                    int maxSingleEncryptSize = rsa1.KeySize / 8 - paddingOverhead;
                    List<byte[]> encryptedChunks = new List<byte[]>();
                    int chunkCount = 0;

                    foreach (var chunk in ChunkData(data, maxSingleEncryptSize))
                    {
                        byte[] encryptedChunk;
                        if (chunkCount % 2 == 0)
                        {
                            encryptedChunk = rsa1.Encrypt(chunk, RSAEncryptionPadding.Pkcs1);
                        }
                        else
                        {
                            encryptedChunk = rsa2.Encrypt(chunk, RSAEncryptionPadding.Pkcs1);
                        }
                        encryptedChunks.Add(encryptedChunk);
                        chunkCount++;
                    }

                    byte[] chunkCountBytes = BitConverter.GetBytes(chunkCount);
                    List<byte> finalEncryptedValue = new List<byte>(chunkCountBytes);
                    foreach (var encryptedChunk in encryptedChunks)
                    {
                        finalEncryptedValue.AddRange(encryptedChunk);
                    }

                    return finalEncryptedValue.ToArray();
                }
            }

            public static byte[] DoubleRSADecrypt(byte[] encryptedData, RSAParameters privKey1, RSAParameters privKey2)
            {
                const int paddingOverhead = 11;
                using (System.Security.Cryptography.RSA rsa1 = System.Security.Cryptography.RSA.Create())
                using (System.Security.Cryptography.RSA rsa2 = System.Security.Cryptography.RSA.Create())
                {
                    rsa1.ImportParameters(privKey1);
                    rsa2.ImportParameters(privKey2);

                    int maxSingleDecryptSize = rsa1.KeySize / 8;
                    int chunkCount = BitConverter.ToInt32(encryptedData, 0);
                    byte[] encryptedChunks = new byte[encryptedData.Length - 4];
                    Array.Copy(encryptedData, 4, encryptedChunks, 0, encryptedChunks.Length);

                    List<byte> decryptedData = new List<byte>();

                    for (int i = 0; i < chunkCount; i++)
                    {
                        int chunkStart = i * maxSingleDecryptSize;
                        byte[] encryptedChunk = new byte[maxSingleDecryptSize];
                        Array.Copy(encryptedChunks, chunkStart, encryptedChunk, 0, maxSingleDecryptSize);

                        byte[] decryptedChunk;
                        if (i % 2 == 0)
                        {
                            decryptedChunk = rsa1.Decrypt(encryptedChunk, RSAEncryptionPadding.Pkcs1);
                        }
                        else
                        {
                            decryptedChunk = rsa2.Decrypt(encryptedChunk, RSAEncryptionPadding.Pkcs1);
                        }
                        decryptedData.AddRange(decryptedChunk);
                    }

                    return decryptedData.ToArray();
                }
            }
        }

        public static (RSAParameters privKey, RSAParameters pubKey) GenerateOrLoadRSAKeys(string baseFilePath, string baseKeyFileName)
        {
            string privateKeyFilePath = Path.Combine(baseFilePath, $"{baseKeyFileName}_ida_rsa");
            string publicKeyFilePath = Path.Combine(baseFilePath, $"{baseKeyFileName}_ida_rsa.pub");

            if (!Directory.Exists(baseFilePath))
                Directory.CreateDirectory(baseFilePath);

            if (File.Exists(privateKeyFilePath) && File.Exists(publicKeyFilePath))
            {
                // Read the existing keys
                string existingPrivateKey = File.ReadAllText(privateKeyFilePath);
                string existingPublicKey = File.ReadAllText(publicKeyFilePath);

                using (System.Security.Cryptography.RSA rsa = System.Security.Cryptography.RSA.Create())
                {
                    rsa.ImportFromPem(existingPrivateKey.ToCharArray());
                    RSAParameters privKey = rsa.ExportParameters(true);

                    rsa.ImportFromPem(existingPublicKey.ToCharArray());
                    RSAParameters pubKey = rsa.ExportParameters(false);

                    return (privKey, pubKey);
                }
            }
            else
            {
                using (System.Security.Cryptography.RSA rsa = System.Security.Cryptography.RSA.Create(2048))
                {
                    RSAParameters privKey = rsa.ExportParameters(true);
                    RSAParameters pubKey = rsa.ExportParameters(false);

                    // Export keys to PEM format
                    string privateKeyPem = ExportToPem(privKey, true);
                    string publicKeyPem = ExportToPem(pubKey, false);

                    // Write keys to files
                    File.WriteAllText(privateKeyFilePath, privateKeyPem);
                    File.WriteAllText(publicKeyFilePath, publicKeyPem);

                    return (privKey, pubKey);
                }
            }
        }

        public static string ExportToPem(RSAParameters parameters, bool isPrivate)
        {
            using (System.Security.Cryptography.RSA rsa = System.Security.Cryptography.RSA.Create())
            {
                rsa.ImportParameters(parameters);
                return isPrivate ? rsa.ExportRSAPrivateKeyPem() : rsa.ExportRSAPublicKeyPem();
            }
        }
    }
}