using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Net;
using System.Net.Sockets;
using D2DARP.Common;
using System.Text.Unicode;
using System.Text;
using System.Text.RegularExpressions;

namespace D2DARP.Engines
{
    internal class DDeviceEngine
    {        
        private const string SYNTHETIC_DOMAIN_IDENTIFIER = "50faa4b1c4a48b62ddfa9f66a5c08022";

        private const string PRESHARED_PREGENERATED_CLIENT1_TCP_AES_KEY = "U3iNdrlT78n3a6h6wqsvsP5HOGvn2UaK";
        private static byte[] PRESHARED_PREGENERATED_CLIENT1_TCP_AES_IV = { 0x9F, 0xB2, 0x67, 0x12, 0x3D, 0xA4, 0x5B, 0xC1, 0xE8, 0x76, 0x2A, 0x9D, 0xF3, 0x45, 0x1C, 0x7E };

        private const string DDNRS_TCP_AES_KEY = "fkHuPhu8QskMsQAoyosJjTjElFDG7qGB";
        private static byte[] DDNRS_TCP_AES_IV = { 0x3A, 0xBF, 0x74, 0x91, 0x5E, 0xD0, 0x2C, 0x8F, 0x47, 0x12, 0x6B, 0xE3, 0x9A, 0xFD, 0x5F, 0x33 };

        private const int CLIENT_TCP_PORT = 8671;
        private const int DDNRS_PORT = 6513;

        private const string IP_ADDRESS_SIMULATING = "10.0.0.1"; 

        private static readonly object _cacheFileLock = new object();
        private static string D2DARPCacheFilePath = $"{Directory.GetCurrentDirectory()}/DDeviceD2DARPCache.json";

        private (RSAParameters PrivateKey, RSAParameters PublicKey) _rsaKeys;
        private DDeviceD2DARPCache _d2darpCache = new DDeviceD2DARPCache() { LastCachedIP = null, AllowedClients = null };

        private static List<string> ReconnectionRevokedClients = new List<string> { "452f24f61652351a75d22574c1f14aa8" };

        private string RuntimeGeneratedIPEncryptionKey = "";
        private byte[] RuntimeGeneratedIPEncryptionIV = new byte[] { };

        private static readonly Logger Logger = new Logger(ConsoleColor.Magenta);

        private class DDeviceD2DARPCacheClient
        {
            public string? Identifier { get; set; }
            public string? PublicSignature { get; set; }
            public DateTime LastReconnectionCheckTime { get; set; }
            public bool IsConnected { get; set; }
        }

        private class DDeviceD2DARPCache
        {
            public string? LastCachedIP { get; set; }
            public List<DDeviceD2DARPCacheClient>? AllowedClients { get; set; }
        }

        public DDeviceEngine()
        {
            _rsaKeys = Tools.GenerateOrLoadRSAKeys($"{Directory.GetCurrentDirectory()}/Keys", "ddevice");
        }

        public void Start()
        {
            Logger.Log("[DDeviceEngine]: Starting engine...");

            Logger.Log("[DDeviceEngine]: Loading or initializing D2DARP cache...");
            LoadOrInitializeD2DARPCache();

            if(_d2darpCache.AllowedClients?.Count == 0)
            {
                Logger.Log("[DDeviceEngine]: No clients in D2DARP cache. Waiting for clients to connect...");
                Task.Run(() => StartClientTCPListner());
            }

            Logger.Log($"[DDeviceEngine]: Setting up IP change simulation handler...");
            Task.Run(() => HandleIPChange());
        }

        private void StartClientTCPListner()
        {
            try
            {
                TcpListener listener = new TcpListener(IPAddress.Any, CLIENT_TCP_PORT);
                listener.Start();

                Logger.Log($"[DDeviceEngine]: Listening for clients on port {DDNRS_PORT}.");

                while(true)
                {
                    TcpClient client = listener.AcceptTcpClient();
                    Task.Run(() => HandleClientConnectionAsync(client));
                }
            }
            catch(Exception ex)
            {
                Logger.Log($"[DDeviceEngine]: Error starting client TCP listener." +
                                  $"\n{ex}");
            }
        }

        private void HandleIPChange()
        {
            while (true)
            {
                try
                {
                    string localIP = GetLocalIP();
                    if (_d2darpCache.LastCachedIP != localIP && _d2darpCache.AllowedClients?.Count > 0)
                    {
                        Logger.Log($"[DDeviceEngine]: Local IP address changed from {_d2darpCache.LastCachedIP} to {localIP}. Updating D2DARP cache.");
                        _d2darpCache.LastCachedIP = localIP;
                        SaveCache(_d2darpCache);

                        // Notify DDNRS of the IP change. For now, we will only notify the first client (allowed) in the cache for POC.
                        string clientIdentifier = _d2darpCache.AllowedClients.FirstOrDefault()?.Identifier;

                        Tools.AES256.Encrypt(
                            Convert.FromBase64String(RuntimeGeneratedIPEncryptionKey),
                            RuntimeGeneratedIPEncryptionIV,
                            Encoding.UTF8.GetBytes(localIP),
                            out byte[] encryptedIPAddressBuffer
                        );

                        Logger.Log("[DDeviceEngine]: Encrypted the new IP address. Notifying DDNRS...");

                        string message = $"DDEVICE {SYNTHETIC_DOMAIN_IDENTIFIER} IPCHG {clientIdentifier} {Convert.ToBase64String(encryptedIPAddressBuffer)}";

                        Tools.AES256.Encrypt(
                            Encoding.UTF8.GetBytes(DDNRS_TCP_AES_KEY),
                            DDNRS_TCP_AES_IV,
                            Encoding.UTF8.GetBytes(message),
                            out var encryptedMessageBuffer
                        );
                        string encryptedMessage = Convert.ToBase64String(encryptedMessageBuffer);

                        // Send the message to DDNRS using TCP with port DDNRS_PORT
                        using (TcpClient client = new TcpClient("127.0.0.1", DDNRS_PORT))
                        {
                            NetworkStream stream = client.GetStream();
                            byte[] encryptedMessageBytes = Encoding.UTF8.GetBytes(encryptedMessage);
                            stream.Write(encryptedMessageBytes, 0, encryptedMessageBytes.Length);
                        }

                        Logger.Log("[DDeviceEngine]: Notified DDNRS of the IP change.");
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log($"[DDeviceEngine]: Error handling IP change." +
                                      $"\n{ex}");
                }
            }
        }

        private async Task HandleClientConnectionAsync(TcpClient tcpClient)
        {
            try
            {
                NetworkStream stream = tcpClient.GetStream();
                byte[] clientMessageBuffer = new byte[2048];
                int bytesRead = await stream.ReadAsync(clientMessageBuffer, 0, clientMessageBuffer.Length);
                string clientMessage = Encoding.UTF8.GetString(clientMessageBuffer, 0, bytesRead);

                Logger.Log("[DDeviceEngine]: Received data from potential client. Decrypting...");

                Tools.AES256.Decrypt(
                    Encoding.UTF8.GetBytes(PRESHARED_PREGENERATED_CLIENT1_TCP_AES_KEY),
                    PRESHARED_PREGENERATED_CLIENT1_TCP_AES_IV,
                    Convert.FromBase64String(clientMessage),
                    out var decryptedMessageBuffer
                );
                string decryptedMessage = Encoding.UTF8.GetString(decryptedMessageBuffer);

                if (Regex.IsMatch(decryptedMessage, @"^CLIENT [0-9A-Fa-f]{32} CONN RQ$"))
                {
                    string clientIdentifier = Regex.Match(decryptedMessage, @"[0-9A-Fa-f]{32}").Value;
                    Logger.Log($"[DDeviceEngine]: Client connection request received from {clientIdentifier}.");

                    if (Program.IsSimulatingIPChange)
                    {
                        if (ReconnectionRevokedClients.Contains(clientIdentifier))
                        {
                            Logger.Log($"[DDeviceEngine]: Client {clientIdentifier} is not allowed to connect.");
                            stream.Close();
                            return;
                        }

                        if (_d2darpCache.AllowedClients.Any(c => c.Identifier == clientIdentifier))
                        {
                            Logger.Log($"[DDeviceEngine]: Allowing verified client {clientIdentifier} to reconnect.");
                            stream.Close();
                            return;
                        }
                    }

                    string responseMessage = $"DDEVICE {SYNTHETIC_DOMAIN_IDENTIFIER} PRIVSIG {Tools.ExportToPem(_rsaKeys.PrivateKey, true)}";
                    Tools.AES256.Encrypt(
                        Encoding.UTF8.GetBytes(PRESHARED_PREGENERATED_CLIENT1_TCP_AES_KEY),
                        PRESHARED_PREGENERATED_CLIENT1_TCP_AES_IV,
                        Encoding.UTF8.GetBytes(responseMessage),
                        out var encryptedResponseMessageBuffer
                    );
                    string encryptedResponseMessage = Convert.ToBase64String(encryptedResponseMessageBuffer);

                    await stream.WriteAsync(Encoding.UTF8.GetBytes(encryptedResponseMessage), 0, encryptedResponseMessage.Length);
                    Logger.Log($"[DDeviceEngine]: Sent private signature to client {clientIdentifier}. Waiting for public signature...");

                    clientMessageBuffer = new byte[2048];
                    bytesRead = await stream.ReadAsync(clientMessageBuffer, 0, clientMessageBuffer.Length);
                    clientMessage = Encoding.UTF8.GetString(clientMessageBuffer, 0, bytesRead);

                    Tools.AES256.Decrypt(
                        Encoding.UTF8.GetBytes(PRESHARED_PREGENERATED_CLIENT1_TCP_AES_KEY),
                        PRESHARED_PREGENERATED_CLIENT1_TCP_AES_IV,
                        Convert.FromBase64String(clientMessage),
                        out decryptedMessageBuffer
                    );
                    decryptedMessage = Encoding.UTF8.GetString(decryptedMessageBuffer);

                    if (Regex.IsMatch(decryptedMessage, @"^CLI [0-9A-Fa-f]{32} PUBSIG -----BEGIN RSA PUBLIC KEY-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END RSA PUBLIC KEY-----$"))
                    {
                        Logger.Log($"[DDeviceEngine]: Public signature received successfully for client {clientIdentifier}.");

                        string clientPublicSignature = Regex.Match(decryptedMessage, @"-----BEGIN RSA PUBLIC KEY-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END RSA PUBLIC KEY-----").Value;

                        Logger.Log($"[DDeviceEngine]: Adding client {clientIdentifier} to D2DARP cache.");
                        _d2darpCache.AllowedClients.Add(new DDeviceD2DARPCacheClient
                        {
                            Identifier = clientIdentifier,
                            PublicSignature = clientPublicSignature,
                            LastReconnectionCheckTime = DateTime.Now,
                            IsConnected = true
                        });
                        SaveCache(_d2darpCache);
                        Logger.Log($"[DDeviceEngine]: Client {clientIdentifier} added to D2DARP cache.");

                        if (ReconnectionRevokedClients.Contains(clientIdentifier))
                        {
                            Logger.Log($"[DDeviceEngine]: Client {clientIdentifier} is not allowed to have IP encryption key and IV generated.");
                            stream.Close();
                            return;
                        }

                        Logger.Log("[DDeviceEngine]: Generating IP encryption key and IV...");
                        using (Aes aes = Aes.Create())
                        {
                            aes.KeySize = 256;
                            aes.GenerateKey();
                            aes.GenerateIV();

                            RuntimeGeneratedIPEncryptionKey = Convert.ToBase64String(aes.Key);
                            RuntimeGeneratedIPEncryptionIV = aes.IV;

                            Logger.Log($"[DDeviceEngine]: Generated IP encryption key and IV. Key: {RuntimeGeneratedIPEncryptionKey} IV: {Convert.ToBase64String(RuntimeGeneratedIPEncryptionIV)}");
                        }

                        Logger.Log($"[DDeviceEngine]: Sending client {clientIdentifier} the IP encryption key and IV...");

                        byte[] doubleEncryptedIV = Tools.RSA.DoubleEncrypt(
                            RuntimeGeneratedIPEncryptionIV,
                            _rsaKeys.PublicKey,
                            Tools.RSA.LoadRSAParametersFromString(clientPublicSignature, false)
                        );
                        byte[] doubleEncryptedKey = Tools.RSA.DoubleEncrypt(
                            Encoding.UTF8.GetBytes(RuntimeGeneratedIPEncryptionKey),
                            _rsaKeys.PublicKey,
                            Tools.RSA.LoadRSAParametersFromString(clientPublicSignature, false)
                        );

                        string message = $"DDEVICE IPDEC IV {Convert.ToBase64String(doubleEncryptedIV)} KEY {Convert.ToBase64String(doubleEncryptedKey)}";
                        Tools.AES256.Encrypt(
                            Encoding.UTF8.GetBytes(PRESHARED_PREGENERATED_CLIENT1_TCP_AES_KEY),
                            PRESHARED_PREGENERATED_CLIENT1_TCP_AES_IV,
                            Encoding.UTF8.GetBytes(message),
                            out var encryptedMessageBuffer
                        );
                        string encryptedMessage = Convert.ToBase64String(encryptedMessageBuffer);

                        await stream.WriteAsync(Encoding.UTF8.GetBytes(encryptedMessage), 0, encryptedMessage.Length);
                        Logger.Log($"[DDeviceEngine]: Sent IP encryption info to client {clientIdentifier}.");
                    }
                    else
                    {
                        Logger.Log("[DDeviceEngine]: Invalid message received from client.");
                        stream.Close();
                    }
                }
                else
                {
                    Logger.Log("[DDeviceEngine]: Invalid message received from client.");
                    stream.Close();
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"[DDeviceEngine]: Error handling client connection: {ex.Message}");
            }
        }

        private void LoadOrInitializeD2DARPCache()
        {
            try
            {
                if(!File.Exists(D2DARPCacheFilePath))
                {
                    Logger.Log("[DDeviceEngine]: No D2DARP cache found. Initializing cache.");

                    _d2darpCache = new DDeviceD2DARPCache
                    {
                        LastCachedIP = GetLocalIP(),
                        AllowedClients = new List<DDeviceD2DARPCacheClient>{}
                    };

                    string d2darpCacheJson = JsonSerializer.Serialize(_d2darpCache);
                    File.WriteAllText(D2DARPCacheFilePath, d2darpCacheJson);

                    Logger.Log("[DDeviceEngine]: D2DARP cache initialized.");
                }
                else
                {
                    string cacheJSONString = File.ReadAllText(D2DARPCacheFilePath);
                    _d2darpCache = JsonSerializer.Deserialize<DDeviceD2DARPCache>(cacheJSONString);
                    Logger.Log("[DDeviceEngine]: D2DARP cache loaded.");
                }
            }
            catch(Exception ex)
            {
                Logger.Log($"[DDeviceEngine]: Error loading or initializing D2DARP cache: {ex.Message}");
            }
        }

        private void SaveCache(DDeviceD2DARPCache cache)
        {
            lock(_cacheFileLock)
            {
                string d2darpCacheJson = JsonSerializer.Serialize(cache);
                File.WriteAllText(D2DARPCacheFilePath, d2darpCacheJson);
            }
        }

        private string? GetLocalIP()
        {
            if(Program.IsSimulatingIPChange)
                return IP_ADDRESS_SIMULATING;

            string? localIP = string.Empty;

            try
            {
                var host = Dns.GetHostEntry(Dns.GetHostName());
                localIP = host.AddressList.FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip))?.ToString();
                
                if (string.IsNullOrEmpty(localIP))
                    throw new Exception("[DDeviceEngine]: No network adapters with an IPv4 address in the system!");
            }
            catch (Exception ex)
            {
                Logger.Log($"[DDeviceEngine]: Error getting local IP address: {ex.Message}");
            }

            return localIP;
        }
    }
}