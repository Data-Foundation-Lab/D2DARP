using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace D2DARP.CustomDNS
{
    public class DnsMessage
    {
        public DnsHeader Header;
        public List<DnsQuestion> Questions;
        public List<DnsResourceRecord> Answers;
        public List<DnsResourceRecord> Authorities;
        public List<DnsResourceRecord> Additionals;

        public DnsMessage(byte[] data)
        {
            Header = new DnsHeader(data);
            Questions = new List<DnsQuestion>();
            Answers = new List<DnsResourceRecord>();
            Authorities = new List<DnsResourceRecord>();
            Additionals = new List<DnsResourceRecord>();

            int offset = 12;
            for (int i = 0; i < Header.QuestionCount; i++)
            {
                Questions.Add(new DnsQuestion(data, ref offset));
            }
            for (int i = 0; i < Header.AnswerCount; i++)
            {
                Answers.Add(new DnsResourceRecord(data, ref offset));
            }
            for (int i = 0; i < Header.AuthorityCount; i++)
            {
                Authorities.Add(new DnsResourceRecord(data, ref offset));
            }
            for (int i = 0; i < Header.AdditionalCount; i++)
            {
                Additionals.Add(new DnsResourceRecord(data, ref offset));
            }
        }

        public byte[] ToArray()
        {
            int estimatedSize = 512 + Answers.Sum(a => a.DataLength) + Authorities.Sum(a => a.DataLength) + Additionals.Sum(a => a.DataLength);
            byte[] data = new byte[estimatedSize];
            Header.WriteTo(data);

            int offset = 12;
            foreach (var question in Questions)
            {
                question.WriteTo(data, ref offset);
            }
            foreach (var answer in Answers)
            {
                answer.WriteTo(data, ref offset);
            }
            foreach (var authority in Authorities)
            {
                authority.WriteTo(data, ref offset);
            }
            foreach (var additional in Additionals)
            {
                additional.WriteTo(data, ref offset);
            }

            Array.Resize(ref data, offset);

            return data;
        }
    }
}
