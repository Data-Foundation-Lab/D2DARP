using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using D2DARP.Common;
using D2DARP.CustomDNS;

namespace D2DARP.Simulators
{
    internal class ClientSimulator
    {
        private class ClientD2DARPCache
        {
            public string LastCachedDDeviceIP { get; set; }
            public string DDevicePrivateSignature { get;set; }
            public byte[] NewIPDecryptionKey { get; set; }
            public string Base6416ByteIV { get; set; }
        }

        //[       Client Identifier      ].[       DDevice Identifier     ].[Main].[TLD]
        private string _subSubDomainToQuery = ""; //Set in the constructor.

        private const string DDEVICE_IP = "127.0.0.1"; //Predefined IP for DDevice. Using Local IP for POC.

        private const int DDEVICE_PORT = 8671;
        private const int VPS_PORT = 8053;

        private const string PRESHARED_PREGENERATED_DDEVICE_TCP_AES_KEY = "U3iNdrlT78n3a6h6wqsvsP5HOGvn2UaK";
        private static byte[] PRESHARED_PREGENERATED_DDEVICE_TCP_AES_IV = { 0x9F, 0xB2, 0x67, 0x12, 0x3D, 0xA4, 0x5B, 0xC1, 0xE8, 0x76, 0x2A, 0x9D, 0xF3, 0x45, 0x1C, 0x7E };

        private string _identifier;
        private (RSAParameters PrivateKey, RSAParameters PublicKey) _rsaKeys;

        private static readonly object _cacheFileLock = new object();
        private string _d2darpCacheFilePath => $"{Directory.GetCurrentDirectory()}/{_identifier}_D2DARPCache.json";
        private ClientD2DARPCache _d2darpCache;

        private static Logger Logger = new Logger(ConsoleColor.Cyan);

        public ClientSimulator(string identifier)
        {
            _rsaKeys = Tools.GenerateOrLoadRSAKeys($"{Directory.GetCurrentDirectory()}/Keys", identifier);
            _identifier = identifier;

            _subSubDomainToQuery = $"{_identifier}.50faa4b1c4a48b62ddfa9f66a5c08022.d2darp.local";
        }

        public void Start()
        {
            Logger.Log($"[ClientSimulator - {_identifier}]: Starting client...");
            Logger.Log($"[ClientSimulator - {_identifier}]: Loading or initializing D2DARP cache...");
            LoadOrInitializeD2DARPCache();

            Logger.Log($"[ClientSimulator - {_identifier}]: Establishing initial connection to DDevice for client...");
            Task.Run(() => EstablishInitialConnectionToDDeviceAsync());

            Logger.Log($"[ClientSimulator - {_identifier}]: Setting up IP change simulation handler...");
            Task.Run(() => HandleIPChange());
        }

        private async Task EstablishInitialConnectionToDDeviceAsync()
        {
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    Logger.Log($"[ClientSimulator - {_identifier}]: Initially connecting to DDevice with pre-known IP at {DDEVICE_IP}");

                    await client.ConnectAsync(DDEVICE_IP, DDEVICE_PORT);
                    NetworkStream stream = client.GetStream();

                    Logger.Log($"[ClientSimulator - {_identifier}]: Successfully opened TCP channel to DDevice.");

                    string connReqMessage = $"CLIENT {_identifier} CONN RQ";

                    Tools.AES256.Encrypt(
                        Encoding.UTF8.GetBytes(PRESHARED_PREGENERATED_DDEVICE_TCP_AES_KEY),
                        PRESHARED_PREGENERATED_DDEVICE_TCP_AES_IV,
                        Encoding.ASCII.GetBytes(connReqMessage),
                        out byte[] encryptedConnReqMessageBuffer
                    );
                    string encryptedConnReqMessage = Convert.ToBase64String(encryptedConnReqMessageBuffer);
                    await stream.WriteAsync(Encoding.UTF8.GetBytes(encryptedConnReqMessage), 0, encryptedConnReqMessage.Length);

                    Logger.Log($"[ClientSimulator - {_identifier}]: Sent connection request to DDevice.");

                    byte[] ddeviceResponseBuffer = new byte[4028];
                    int bytesRead = await stream.ReadAsync(ddeviceResponseBuffer, 0, ddeviceResponseBuffer.Length);
                    string ddeviceResponse = Encoding.UTF8.GetString(ddeviceResponseBuffer, 0, bytesRead);

                    Tools.AES256.Decrypt(
                        Encoding.UTF8.GetBytes(PRESHARED_PREGENERATED_DDEVICE_TCP_AES_KEY),
                        PRESHARED_PREGENERATED_DDEVICE_TCP_AES_IV,
                        Convert.FromBase64String(ddeviceResponse),
                        out byte[] decryptedDDeviceMessageBuffer
                    );
                    string decryptedDDeviceResponse = Encoding.UTF8.GetString(decryptedDDeviceMessageBuffer);

                    if (Regex.IsMatch(decryptedDDeviceResponse, @"^DDEVICE [0-9A-Fa-f]{32} PRIVSIG -----BEGIN RSA PRIVATE KEY-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END RSA PRIVATE KEY-----$"))
                    {
                        Logger.Log($"[ClientSimulator - {_identifier}]: Successfully connected to DDevice. Waiting for DDevice's private signature...");

                        string ddevicePrivateSignature = Regex.Match(decryptedDDeviceResponse, @"-----BEGIN RSA PRIVATE KEY-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END RSA PRIVATE KEY-----").Value;
                        _d2darpCache.DDevicePrivateSignature = ddevicePrivateSignature;
                        SaveCache(_d2darpCache);

                        Logger.Log($"[ClientSimulator - {_identifier}]: Received DDevice private signature.");

                        string responseMessage = $"CLI {_identifier} PUBSIG {Tools.ExportToPem(_rsaKeys.PublicKey, false)}";
                        Tools.AES256.Encrypt(
                            Encoding.UTF8.GetBytes(PRESHARED_PREGENERATED_DDEVICE_TCP_AES_KEY),
                            PRESHARED_PREGENERATED_DDEVICE_TCP_AES_IV,
                            Encoding.UTF8.GetBytes(responseMessage),
                            out byte[] encryptedResponseMessageBuffer
                        );
                        string encryptedResponseMessage = Convert.ToBase64String(encryptedResponseMessageBuffer);

                        Logger.Log($"[ClientSimulator - {_identifier}]: Sending public signature...");

                        await stream.WriteAsync(Encoding.UTF8.GetBytes(encryptedResponseMessage), 0, encryptedResponseMessage.Length);
                        Logger.Log($"[ClientSimulator - {_identifier}]: Sent public key to DDevice. Waiting for IP address decryption key...");

                        ddeviceResponseBuffer = new byte[1024];
                        bytesRead = await stream.ReadAsync(ddeviceResponseBuffer, 0, ddeviceResponseBuffer.Length);
                        ddeviceResponse = Encoding.UTF8.GetString(ddeviceResponseBuffer, 0, bytesRead);

                        Tools.AES256.Decrypt(
                            Encoding.UTF8.GetBytes(PRESHARED_PREGENERATED_DDEVICE_TCP_AES_KEY),
                            PRESHARED_PREGENERATED_DDEVICE_TCP_AES_IV,
                            Convert.FromBase64String(ddeviceResponse),
                            out byte[] decryptedNewDDeviceMessageBuffer
                        );
                        string decryptedNewDDeviceMessage = Encoding.UTF8.GetString(decryptedNewDDeviceMessageBuffer);

                        Regex ddeviceMessageRegex = new Regex(@"DDEVICE IPDEC IV (?<IV>[A-Za-z0-9+/=]{344,348}) KEY (?<decryptionKey>[A-Za-z0-9+/=]{344,348})");
                        Match match = ddeviceMessageRegex.Match(decryptedNewDDeviceMessage);

                        if (match.Success)
                        {
                            Logger.Log($"[ClientSimulator - {_identifier}]: Received IP decryption key and IV.");

                            string iv = match.Groups["IV"].Value;
                            string decryptionKey = match.Groups["decryptionKey"].Value;

                            byte[] ivBeforeRSADecryptionBase64 = Convert.FromBase64String(iv);
                            byte[] decryptionKeyBeforeRSADecryptionBase64 = Convert.FromBase64String(decryptionKey);

                            byte[] doubleDecryptedIVBuffer = Tools.RSA.DoubleRSADecrypt(
                                ivBeforeRSADecryptionBase64,
                                Tools.RSA.LoadRSAParametersFromString(ddevicePrivateSignature, true),
                                _rsaKeys.PrivateKey
                            );
                            byte[] doubleDecryptedDecryptionKeyBuffer = Tools.RSA.DoubleRSADecrypt(
                                decryptionKeyBeforeRSADecryptionBase64,
                                Tools.RSA.LoadRSAParametersFromString(ddevicePrivateSignature, true),
                                _rsaKeys.PrivateKey
                            );

                            _d2darpCache.NewIPDecryptionKey = doubleDecryptedDecryptionKeyBuffer;
                            _d2darpCache.Base6416ByteIV = Convert.ToBase64String(doubleDecryptedIVBuffer);

                            SaveCache(_d2darpCache);
                        }
                        else
                        {
                            Logger.Log($"[ClientSimulator - {_identifier}]: Received invalid response from DDevice for client {_identifier}. Closing connection.");
                        }
                    }
                    else
                    {
                        Logger.Log($"[ClientSimulator - {_identifier}]: Received invalid response from DDevice for client {_identifier}. Closing connection.");
                    }

                    stream.Close();
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"[ClientSimulator - {_identifier}]: Error establishing initial connection to DDevice." +
                                  $"\n{ex}");
            }
        }


        private Task HandleIPChange()
        {
            while (!Program.IsSimulatingIPChange) { }

            Logger.Log($"[ClientSimulator - {_identifier}]: Detected IP change simulation. Querying DDNRS through VPS via {_subSubDomainToQuery}...");

            byte[] query = CreateDnsQuery(_subSubDomainToQuery);

            using (UdpClient udpClient = new UdpClient())
            {
                udpClient.Connect("127.0.0.1", VPS_PORT);
                udpClient.Send(query, query.Length);

                IPEndPoint remoteEP = null;
                byte[] response = udpClient.Receive(ref remoteEP);

                ProcessDnsResponse(response);
            }

            return Task.CompletedTask;
        }

        private void ProcessDnsResponse(byte[] response)
        {
            DnsMessage dnsMessage = new DnsMessage(response);

            byte[] txtBuffer = new byte[] { };
            foreach (var answer in dnsMessage.Answers)
            {
                if (answer.Type == DnsRecordType.TXT)
                {
                    txtBuffer = answer.Data;
                }
            }

            if(txtBuffer.Length == 0)
            {
                Logger.Log($"[ClientSimulator - {_identifier}]: Failed to process TXT record. Buffer's length is 0.");
                return;
            }

            string encryptedIP = Encoding.UTF8.GetString(txtBuffer).Substring(1); //Somehow UDP adds a random character at the first index, so remove it.

            try
            {
                // Decode the base64-encoded decryption key and IV
                byte[] decodedDecryptionKey = Convert.FromBase64String(Encoding.UTF8.GetString(_d2darpCache.NewIPDecryptionKey));
                byte[] decodedIV = Convert.FromBase64String(_d2darpCache.Base6416ByteIV);

                // Decode the base64-encoded encrypted IP
                byte[] encryptedIPBytes = Convert.FromBase64String(encryptedIP);

                Tools.AES256.Decrypt(decodedDecryptionKey, decodedIV, encryptedIPBytes, out byte[] decryptedDDeviceMessageBuffer);
                string decryptedIP = Encoding.UTF8.GetString(decryptedDDeviceMessageBuffer);

                Logger.Log($"[ClientSimulator - {_identifier}]: Successfully queried DDevice's new IP address now at {decryptedIP}.");
            }
            catch (Exception ex)
            {
                Logger.Log($"[ClientSimulator - {_identifier}]: Error decrypting TXT record." +
                                  $"\n{ex}");
            }
        }

        private byte[] CreateDnsQuery(string domain)
        {
            try
            {
                // Header
                byte[] header = new byte[12];
                header[0] = 0x12; // Transaction ID
                header[1] = 0x34; // Transaction ID
                header[2] = 0x01; // Flags
                header[5] = 0x01; // Question Count

                // Question
                byte[] question = CreateDnsQuestion(domain);

                // Combine header and question
                byte[] query = new byte[header.Length + question.Length];
                Buffer.BlockCopy(header, 0, query, 0, header.Length);
                Buffer.BlockCopy(question, 0, query, header.Length, question.Length);

                return query;
            }
            catch(Exception ex)
            {
                Logger.Log($"[ClientSimulator - {_identifier}]: Error creating DNS Query." +
                                  $"\n{ex}");
                return new byte[] { };
            }
        }

        private byte[] CreateDnsQuestion(string domain)
        {
            string[] labels = domain.Split('.');
            byte[] question = new byte[domain.Length + 2 + 4]; // domain + null byte + QTYPE + QCLASS

            int index = 0;
            foreach (string label in labels)
            {
                question[index++] = (byte)label.Length;
                byte[] labelBytes = Encoding.ASCII.GetBytes(label);
                Buffer.BlockCopy(labelBytes, 0, question, index, labelBytes.Length);
                index += labelBytes.Length;
            }
            question[index++] = 0x00; // Null byte to end the domain part
            question[index++] = 0x00; // QTYPE (A)
            question[index++] = 0x01;
            question[index++] = 0x00; // QCLASS (IN)
            question[index++] = 0x01;

            return question;
        }

        private void LoadOrInitializeD2DARPCache()
        {
            try
            {
                if(!File.Exists(_d2darpCacheFilePath))
                {
                    Logger.Log($"[ClientSimulator - {_identifier}]: No D2DARP cache found. Initializing cache.");

                    _d2darpCache = new ClientD2DARPCache
                    {
                        LastCachedDDeviceIP = DDEVICE_IP,
                        DDevicePrivateSignature = "",
                        NewIPDecryptionKey = new byte[] {},
                        Base6416ByteIV = ""
                    };

                    string d2darpCacheJson = JsonSerializer.Serialize(_d2darpCache);
                    File.WriteAllText(_d2darpCacheFilePath, d2darpCacheJson);

                    Logger.Log($"[ClientSimulator - {_identifier}]: D2DARP cache initialized.");
                }
                else
                {
                    string cacheJSONString = File.ReadAllText(_d2darpCacheFilePath);
                    _d2darpCache = JsonSerializer.Deserialize<ClientD2DARPCache>(cacheJSONString);
                    Logger.Log($"[ClientSimulator - {_identifier}]: D2DARP cache loaded.");
                }
            }
            catch(Exception ex)
            {
                Logger.Log($"[ClientSimulator - {_identifier}]: Error loading or initializing D2DARP cache." +
                                  $"\n{ex}");
            }
        }

        private void SaveCache(ClientD2DARPCache cache)
        {
            lock(_cacheFileLock)
            {
                try
                {
                    string d2darpCacheJson = JsonSerializer.Serialize(cache);
                    File.WriteAllText(_d2darpCacheFilePath, d2darpCacheJson);
                }
                catch(Exception ex)
                {
                    Logger.Log($"[ClientSimulator - {_identifier}]: Error saving cache." +
                                      $"\n{ex}");
                }
            }
        }
    }
}