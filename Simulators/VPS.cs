using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using D2DARP.CustomDNS;
using D2DARP.Common;
using System.IO;
using System.Text.RegularExpressions;

namespace D2DARP.Simulators
{
    internal class VPS
    {
        private const string DDNRS_TCP_AES_KEY = "fpScoSv42I2L6R6J7t0E8Qe0iDdGeJfX";
        private static readonly byte[] DDNRS_TCP_AES_IV = { 0x4D, 0xA2, 0x6E, 0x85, 0xF4, 0x1B, 0x39, 0xD7, 0x56, 0xC0, 0x7A, 0x91, 0xE5, 0x2F, 0x43, 0xBC };

        private const int DDNRS_TCP_PORT = 7624;

        public static UdpClient udpClient;

        private static readonly Logger Logger = new Logger(ConsoleColor.Green);

        internal VPS()
        {
            udpClient = new UdpClient();
            udpClient.ExclusiveAddressUse = false;
            udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, 8053));
        }

        public void Start()
        {
            Logger.Log("[VPS]: Starting VPS as a public DNS server...");
            Task.Run(() => HostDNSServer());
        }

        private async Task HostDNSServer()
        {
            while (true)
            {
                try
                {
                    UdpReceiveResult result = await udpClient.ReceiveAsync();
                    Logger.Log($"[VPS]: Received DNS query from {result.RemoteEndPoint}");
                    await Task.Run(() => HandleQuery(result.Buffer, result.RemoteEndPoint));
                }
                catch (Exception ex)
                {
                    Logger.Log($"[VPS]: Error receiving DNS query data. " +
                                      $"\n{ex}");
                }
            }
        }

        private async Task<string> QueryDDNRS(string ddeviceSubdomainIdentifier, string clientIdentifier)
        {
            string queryMessage = $"DNS QRY FROM CLI {clientIdentifier} FOR {ddeviceSubdomainIdentifier}";

            Tools.AES256.Encrypt(
                Encoding.UTF8.GetBytes(DDNRS_TCP_AES_KEY),
                DDNRS_TCP_AES_IV,
                Encoding.UTF8.GetBytes(queryMessage),
                out var encryptedQueryMessageBuffer
            );

            string encryptedQueryMessage = Convert.ToBase64String(encryptedQueryMessageBuffer);

            using (TcpClient client = new TcpClient("127.0.0.1", DDNRS_TCP_PORT))
            {
                NetworkStream stream = client.GetStream();
                Logger.Log($"[VPS]: Querying DDNRS for DDevice {ddeviceSubdomainIdentifier} requested from client {clientIdentifier}");

                byte[] encryptedQueryMessageBytes = Encoding.UTF8.GetBytes(encryptedQueryMessage);
                await stream.WriteAsync(encryptedQueryMessageBytes, 0, encryptedQueryMessageBytes.Length);

                byte[] ddnrsResponseMessageBuffer = new byte[2048];
                int bytesRead = await stream.ReadAsync(ddnrsResponseMessageBuffer, 0, ddnrsResponseMessageBuffer.Length);
                string ddnrsResponseMessage = Encoding.UTF8.GetString(ddnrsResponseMessageBuffer, 0, bytesRead);

                Tools.AES256.Decrypt(
                    Encoding.UTF8.GetBytes(DDNRS_TCP_AES_KEY),
                    DDNRS_TCP_AES_IV,
                    Convert.FromBase64String(ddnrsResponseMessage),
                    out var decryptedDdnrsResponseMessageBuffer
                );

                string decryptedDdnrsResponseMessage = Encoding.UTF8.GetString(decryptedDdnrsResponseMessageBuffer);

                return decryptedDdnrsResponseMessage;
            }
        }

        private async Task HandleQuery(byte[] query, IPEndPoint remoteEP)
        {
            try
            {
                Logger.Log($"[VPS]: Handling DNS query from {remoteEP} with DNS data length: {query.Length}");

                if (query.Length < 12)
                {
                    Logger.Log("[VPS]: Received data is too short to be a valid DNS query.");
                    return;
                }

                var request = new DnsMessage(query);
                var response = await CreateResponse(request, query);

                udpClient.Send(response.ToArray(), response.ToArray().Length, remoteEP);
                Logger.Log("[VPS]: Responded to DNS query with a result from DDRNS.");
            }
            catch (Exception ex)
            {
                Logger.Log($"[VPS]: Error handling DNS query." +
                                  $"\n{ex}");
            }
        }

        private async Task<DnsMessage> CreateResponse(DnsMessage request, byte[] data)
        {
            Logger.Log($"[VPS]: Creating response for DNS request {request.Questions.First().Name}");

            var response = new DnsMessage(new byte[512]) { Header = request.Header };
            response.Header.Flags = 0x8180;
            response.Questions.AddRange(request.Questions);

            var regex = new Regex(@"^(?<clientIdentifier>[0-9A-Za-z]{32})\.(?<ddeviceSubdomainIdentifier>[0-9A-Za-z]{32})\.d2darp\.local$");

            foreach (var question in request.Questions)
            {
                var match = regex.Match(question.Name);

                if (match.Success)
                {
                    string ddeviceSubdomainIdentifier = match.Groups["ddeviceSubdomainIdentifier"].Value;
                    string clientIdentifier = match.Groups["clientIdentifier"].Value;

                    Logger.Log($"[VPS]: DNS query matched the valid format.");
                    var ddnrsQueryResult = await QueryDDNRS(ddeviceSubdomainIdentifier, clientIdentifier);

                    if (!ddnrsQueryResult.Equals("0.0.0.0"))
                    {
                        Logger.Log("[VPS]: DDNRS query result returned valid domain query.");
                        AddTxtRecordsToResponse(response, question.Name, ddnrsQueryResult);
                    }
                    else
                    {
                        Logger.Log($"[VPS]: DDNRS query result returned invalid domain query. Returning masked IP address.");
                        AddMaskedIpRecord(response, question.Name);
                    }
                }
                else
                {
                    Logger.Log($"[VPS]: DNS query was not a valid D2DARP query format. Returning masked IP address.");
                    AddMaskedIpRecord(response, question.Name);
                }
            }

            response.Header.AnswerCount = (ushort)response.Answers.Count;
            response.Header.AuthorityCount = (ushort)response.Authorities.Count;
            response.Header.AdditionalCount = (ushort)response.Additionals.Count;

            Logger.Log($"[VPS]: DNS response created with total of {response.Answers.Count} answers");
            return response;
        }

        private void AddTxtRecordsToResponse(DnsMessage response, string name, string ddnrsQueryResult)
        {
            var txtRecords = SplitIntoTxtRecords(ddnrsQueryResult, 255);

            foreach (var record in txtRecords)
            {
                byte[] txtData = Encoding.UTF8.GetBytes(record);
                byte[] answerData = new byte[txtData.Length + 1];
                answerData[0] = (byte)txtData.Length;
                Buffer.BlockCopy(txtData, 0, answerData, 1, txtData.Length);
                response.Answers.Add(new DnsResourceRecord(name, DnsRecordType.TXT, DnsClass.IN, 60, answerData));
            }
        }

        private void AddMaskedIpRecord(DnsMessage response, string name)
        {
            byte[] txtData = Encoding.UTF8.GetBytes("0.0.0.0");
            byte[] answerData = new byte[txtData.Length + 1];
            answerData[0] = (byte)txtData.Length;
            Buffer.BlockCopy(txtData, 0, answerData, 1, txtData.Length);
            response.Answers.Add(new DnsResourceRecord(name, DnsRecordType.TXT, DnsClass.IN, 60, answerData));
        }

        private static List<string> SplitIntoTxtRecords(string utf8String, int maxLength = 255)
        {
            byte[] utf8Bytes = Encoding.UTF8.GetBytes(utf8String);
            List<string> records = new List<string>();

            for (int i = 0; i < utf8Bytes.Length; i += maxLength)
            {
                int length = Math.Min(maxLength, utf8Bytes.Length - i);
                byte[] chunk = new byte[length];
                Array.Copy(utf8Bytes, i, chunk, 0, length);
                records.Add(Encoding.UTF8.GetString(chunk));
            }

            return records;
        }
    }
}