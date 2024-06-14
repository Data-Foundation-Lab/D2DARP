using D2DARP.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace D2DARP.Engines
{
    internal class DDNRSEngine
    {
        private class DNSCache
        {
            public string SyntheticSubdomainIdentifier { get; set; }
            public string ClientIdentifier { get; set; }
            public string EncryptedNewIPAddress { get; set; }
        }

        private const string DDEVICE_TCP_AES_KEY = "fkHuPhu8QskMsQAoyosJjTjElFDG7qGB";
        private static byte[] DDEVICE_TCP_AES_IV = { 0x3A, 0xBF, 0x74, 0x91, 0x5E, 0xD0, 0x2C, 0x8F, 0x47, 0x12, 0x6B, 0xE3, 0x9A, 0xFD, 0x5F, 0x33 };

        private const string VPS_TCP_AES_KEY = "fpScoSv42I2L6R6J7t0E8Qe0iDdGeJfX";
        private static byte[] VPS_TCP_AES_IV = { 0x4D, 0xA2, 0x6E, 0x85, 0xF4, 0x1B, 0x39, 0xD7, 0x56, 0xC0, 0x7A, 0x91, 0xE5, 0x2F, 0x43, 0xBC };

        private const int VPS_PORT = 7624;
        private const int DDEVICE_PORT = 6513;

        private const int PURGE_WINDOW_MINUTES = 60;

        private List<DNSCache> _inMemoryDNSCaches = new List<DNSCache>();
        private DateTime _lastGarbageCollectionTime = default(DateTime);

        private static readonly Logger Logger = new Logger(ConsoleColor.Yellow);

        internal DDNRSEngine()
        {
        }

        public void Start()
        {
            Logger.Log("[DDNRSEngine]: Starting engine...");

            Logger.Log("[DDNRSEngine]: Setting up TCP connection handler...");
            Task.Run(() => HandleTcpConnections());

            Logger.Log("[DDNRSEngine]: Setting up TCP connection garbage collection handler...");
            Task.Run(() => HandleDNSCacheGarbageCollection());
        }

        public async Task HandleTcpConnections()
        {
            TcpListener ddeviceListener = new TcpListener(IPAddress.Any, DDEVICE_PORT);
            ddeviceListener.Start();
            Logger.Log($"[DDNRSEngine]: Listening for DDevice tcp connections on port {DDEVICE_PORT}.");

            TcpListener vpsListener = new TcpListener(IPAddress.Any, VPS_PORT);
            vpsListener.Start();
            Logger.Log($"[DDNRSEngine]: Listening for VPS tcp connections on port {VPS_PORT}.");

            Task ddeviceTask = AcceptConnectionsAsync(ddeviceListener, HandleDDeviceConnection);
            Task vpsTask = AcceptConnectionsAsync(vpsListener, HandleVPSConnection);

            await Task.WhenAll(ddeviceTask, vpsTask);
        }

        private async Task AcceptConnectionsAsync(TcpListener listener, Func<TcpClient, Task> handleConnection)
        {
            while (true)
            {
                TcpClient client = await listener.AcceptTcpClientAsync();
                if (client.Connected)
                {
                    Task.Run(() => handleConnection(client));
                }
            }
        }

        private async Task HandleDDeviceConnection(TcpClient tcpClient)
        {
            Logger.Log("[DDNRSEngine]: A DDevice has connected.");

            NetworkStream stream = tcpClient.GetStream();
            byte[] ddeviceMessageBuffer = new byte[1024];
            int bytesRead = await stream.ReadAsync(ddeviceMessageBuffer, 0, ddeviceMessageBuffer.Length);
            string ddeviceMessage = Encoding.UTF8.GetString(ddeviceMessageBuffer, 0, bytesRead);

            Tools.AES256.Decrypt(
                Encoding.UTF8.GetBytes(DDEVICE_TCP_AES_KEY),
                DDEVICE_TCP_AES_IV,
                Convert.FromBase64String(ddeviceMessage),
                out var decryptedMessageBuffer
            );
            string decryptedMessage = Encoding.UTF8.GetString(decryptedMessageBuffer);

            var regex = new Regex(@"^DDEVICE (?<ddeviceIdentifier>[0-9A-Fa-f]{32}) IPCHG (?<clientIdentifier>[0-9A-Fa-f]{32})");
            var match = regex.Match(decryptedMessage);

            if (match.Success)
            {
                string ddeviceIdentifier = match.Groups["ddeviceIdentifier"].Value;
                string clientIdentifier = match.Groups["clientIdentifier"].Value;
                int startIndex = match.Index + match.Length + 1; // +1 to account for the space
                string encryptedIPAddress = decryptedMessage.Substring(startIndex);

                Logger.Log($"[DDNRSEngine]: DDevice {ddeviceIdentifier} notified IP change for client {clientIdentifier}.");

                var inMemQuery = _inMemoryDNSCaches
                    .Where(c => c.SyntheticSubdomainIdentifier.Equals(ddeviceIdentifier) && c.ClientIdentifier.Equals(clientIdentifier));

                if (!inMemQuery.Any())
                {
                    _inMemoryDNSCaches.Add(new DNSCache()
                    {
                        SyntheticSubdomainIdentifier = ddeviceIdentifier,
                        ClientIdentifier = clientIdentifier,
                        EncryptedNewIPAddress = encryptedIPAddress
                    });

                    Logger.Log($"[DDNRSEngine]: Added DNS cache for DDevice {ddeviceIdentifier} to be queried by {clientIdentifier}");
                }
                else if (inMemQuery.Count() == 1)
                {
                    var dnsCache = inMemQuery.First();
                    Logger.Log("[DDNRSEngine]: Found existing DNS cache. Updating record...");

                    if (dnsCache.ClientIdentifier != clientIdentifier)
                        dnsCache.ClientIdentifier = clientIdentifier;

                    if (dnsCache.EncryptedNewIPAddress != encryptedIPAddress)
                        dnsCache.EncryptedNewIPAddress = encryptedIPAddress;
                }

                stream.Close();
            }
            else
            {
                Logger.Log("[DDNRSEngine]: Received invalid DDevice message. Dropping connection.");
                tcpClient.Close();
            }
        }

        private async Task HandleVPSConnection(TcpClient tcpClient)
        {
            Logger.Log("[DDNRSEngine]: VPS has connected.");

            NetworkStream stream = tcpClient.GetStream();
            byte[] vpsMessageBuffer = new byte[1024];
            int bytesRead = await stream.ReadAsync(vpsMessageBuffer, 0, vpsMessageBuffer.Length);
            string vpsMessage = Encoding.UTF8.GetString(vpsMessageBuffer, 0, bytesRead);

            Tools.AES256.Decrypt(
                Encoding.UTF8.GetBytes(VPS_TCP_AES_KEY),
                VPS_TCP_AES_IV,
                Convert.FromBase64String(vpsMessage),
                out var decryptedVPSMessageBuffer
            );
            string decryptedVPSMessage = Encoding.UTF8.GetString(decryptedVPSMessageBuffer);

            var regex = new Regex(@"^DNS QRY FROM CLI (?<clientIdentifier>[0-9A-Za-z]{32}) FOR (?<ddeviceSubdomainIdentifier>[0-9A-Za-z]{32})$");
            var match = regex.Match(decryptedVPSMessage);

            if (match.Success)
            {
                string clientIdentifier = match.Groups["clientIdentifier"].Value;
                string ddeviceSubdomainIdentifier = match.Groups["ddeviceSubdomainIdentifier"].Value;

                Logger.Log($"[DDNRSEngine]: VPS requested DNS query from client {clientIdentifier} for DDevice {ddeviceSubdomainIdentifier}");

                string responseMessage = "0.0.0.0";
                var dnsCacheQuery = _inMemoryDNSCaches
                    .Where(c => c.SyntheticSubdomainIdentifier == ddeviceSubdomainIdentifier && c.ClientIdentifier == clientIdentifier);

                if (dnsCacheQuery.Count() == 1)
                {
                    responseMessage = dnsCacheQuery.First().EncryptedNewIPAddress;
                }

                Tools.AES256.Encrypt(
                    Encoding.UTF8.GetBytes(VPS_TCP_AES_KEY),
                    VPS_TCP_AES_IV,
                    Encoding.UTF8.GetBytes(responseMessage),
                    out var encryptedResponseMessageBuffer
                );
                string encryptedResponseMessage = Convert.ToBase64String(encryptedResponseMessageBuffer);

                await stream.WriteAsync(Encoding.UTF8.GetBytes(encryptedResponseMessage), 0, encryptedResponseMessage.Length);

                if (responseMessage == "0.0.0.0")
                {
                    Logger.Log("[DDNRSEngine]: Failed to find valid client identifier and ddevice identifier from the DNS cache. Sending masked result back to VPS.");
                }
                else
                {
                    Logger.Log($"[DDNRSEngine]: Sent query result back to VPS from client {clientIdentifier} for DDevice {ddeviceSubdomainIdentifier}");
                }
            }
            else
            {
                Logger.Log("[DDNRSEngine]: VPS DNS query message was not in the correct format. Dropping the packet.");
                stream.Close();
            }
        }

        private Task HandleDNSCacheGarbageCollection()
        {
            while (true)
            {
                if (_inMemoryDNSCaches.Count == 0)
                    continue;

                if ((DateTime.Now - _lastGarbageCollectionTime).TotalMinutes == PURGE_WINDOW_MINUTES)
                {
                    Logger.Log("[DDRNSEngine]: Running garbage collection for dns caches as per purging window.");
                    _inMemoryDNSCaches.Clear();
                }
            }
        }
    }
}