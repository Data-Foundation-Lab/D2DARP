using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace D2DARP.Common
{
    /// <summary>
    /// Basic Logger
    /// </summary>
    internal class Logger
    {
        private ConsoleColor _consoleColor;

        public Logger(ConsoleColor color)
        {
            _consoleColor = color;
        }

        public void Log(object message)
        {
            var tmp = Console.ForegroundColor;
            Console.ForegroundColor = _consoleColor;

            Console.WriteLine(message);

            Console.ForegroundColor = tmp;
        }
    }
}
