using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace D2DARP.CustomDNS
{
    public struct DnsHeader
    {
        public ushort TransactionID;
        public ushort Flags;
        public ushort QuestionCount;
        public ushort AnswerCount;
        public ushort AuthorityCount;
        public ushort AdditionalCount;

        public DnsHeader(byte[] data)
        {
            if (data.Length < 12)
            {
                throw new ArgumentException("Invalid DNS header length");
            }

            TransactionID = (ushort)((data[0] << 8) | data[1]);
            Flags = (ushort)((data[2] << 8) | data[3]);
            QuestionCount = (ushort)((data[4] << 8) | data[5]);
            AnswerCount = (ushort)((data[6] << 8) | data[7]);
            AuthorityCount = (ushort)((data[8] << 8) | data[9]);
            AdditionalCount = (ushort)((data[10] << 8) | data[11]);
        }

        public void WriteTo(byte[] data)
        {
            data[0] = (byte)(TransactionID >> 8);
            data[1] = (byte)(TransactionID & 0xFF);
            data[2] = (byte)(Flags >> 8);
            data[3] = (byte)(Flags & 0xFF);
            data[4] = (byte)(QuestionCount >> 8);
            data[5] = (byte)(QuestionCount & 0xFF);
            data[6] = (byte)(AnswerCount >> 8);
            data[7] = (byte)(AnswerCount & 0xFF);
            data[8] = (byte)(AuthorityCount >> 8);
            data[9] = (byte)(AuthorityCount & 0xFF);
            data[10] = (byte)(AdditionalCount >> 8);
            data[11] = (byte)(AdditionalCount & 0xFF);
        }
    }

    public struct DnsQuestion
    {
        public string Name;
        public DnsRecordType Type;
        public DnsClass Class;

        public DnsQuestion(string name, DnsRecordType type, DnsClass @class)
        {
            Name = name;
            Type = type;
            Class = @class;
        }

        public DnsQuestion(byte[] data, ref int offset)
        {
            Name = ReadName(data, ref offset);
            if (offset + 4 > data.Length)
            {
                throw new ArgumentException("Invalid DNS question length");
            }
            Type = (DnsRecordType)((data[offset] << 8) | data[offset + 1]);
            offset += 2;
            Class = (DnsClass)((data[offset] << 8) | data[offset + 1]);
            offset += 2;
        }

        public static string ReadName(byte[] data, ref int offset)
        {
            var name = new StringBuilder();
            while (data[offset] != 0)
            {
                int length = data[offset++];
                if (offset + length > data.Length)
                {
                    throw new ArgumentException("Invalid DNS name length");
                }
                name.Append(Encoding.UTF8.GetString(data, offset, length));
                offset += length;
                if (data[offset] != 0)
                {
                    name.Append(".");
                }
            }
            offset++;
            return name.ToString();
        }

        public void WriteTo(byte[] data, ref int offset)
        {
            WriteName(data, ref offset, Name);
            data[offset++] = (byte)((ushort)Type >> 8);
            data[offset++] = (byte)((ushort)Type & 0xFF);
            data[offset++] = (byte)((ushort)Class >> 8);
            data[offset++] = (byte)((ushort)Class & 0xFF);
        }

        public static void WriteName(byte[] data, ref int offset, string name)
        {
            var labels = name.Split('.');
            foreach (var label in labels)
            {
                data[offset++] = (byte)label.Length;
                Encoding.UTF8.GetBytes(label, 0, label.Length, data, offset);
                offset += label.Length;
            }
            data[offset++] = 0;
        }
    }

    public struct DnsResourceRecord
    {
        public string Name;
        public DnsRecordType Type;
        public DnsClass Class;
        public uint TTL;
        public ushort DataLength;
        public byte[] Data;

        public DnsResourceRecord(string name, DnsRecordType type, DnsClass @class, uint ttl, byte[] data)
        {
            Name = name;
            Type = type;
            Class = @class;
            TTL = ttl;
            DataLength = (ushort)data.Length;
            Data = data;
        }

        public DnsResourceRecord(byte[] data, ref int offset)
        {
            Name = DnsQuestion.ReadName(data, ref offset);
            if (offset + 10 > data.Length)
            {
                throw new ArgumentException("Invalid DNS resource record length");
            }
            Type = (DnsRecordType)((data[offset] << 8) | data[offset + 1]);
            offset += 2;
            Class = (DnsClass)((data[offset] << 8) | data[offset + 1]);
            offset += 2;
            TTL = (uint)((data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]);
            offset += 4;
            DataLength = (ushort)((data[offset] << 8) | data[offset + 1]);
            offset += 2;
            if (offset + DataLength > data.Length)
            {
                throw new ArgumentException("Invalid DNS resource record data length");
            }
            Data = new byte[DataLength];
            Buffer.BlockCopy(data, offset, Data, 0, DataLength);
            offset += DataLength;
        }

        public void WriteTo(byte[] data, ref int offset)
        {
            DnsQuestion.WriteName(data, ref offset, Name);
            data[offset++] = (byte)((ushort)Type >> 8);
            data[offset++] = (byte)((ushort)Type & 0xFF);
            data[offset++] = (byte)((ushort)Class >> 8);
            data[offset++] = (byte)((ushort)Class & 0xFF);
            data[offset++] = (byte)(TTL >> 24);
            data[offset++] = (byte)(TTL >> 16);
            data[offset++] = (byte)(TTL >> 8);
            data[offset++] = (byte)(TTL & 0xFF);
            data[offset++] = (byte)(DataLength >> 8);
            data[offset++] = (byte)(DataLength & 0xFF);
            Buffer.BlockCopy(Data, 0, data, offset, DataLength);
            offset += DataLength;
        }
    }
}
