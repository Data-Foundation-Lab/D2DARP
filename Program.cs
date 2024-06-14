using D2DARP.Common;
using D2DARP.Engines;
using D2DARP.Simulators;
using System.Security.Cryptography;
using System.Text;

namespace D2DARP
{
    public class Program
    {
        public static bool IsSimulatingIPChange = false;

        public static async Task Main(string[] args)
        {
            var vpsTask = Task.Run(() =>
            {
                VPS vps = new VPS();
                vps.Start();
            });

            var ddnrsEngineTask = Task.Run(() =>
            {
                DDNRSEngine dDNRSEngine = new DDNRSEngine();
                dDNRSEngine.Start();
            });

            var ddeviceTask = Task.Run(() =>
            {
                DDeviceEngine engine = new DDeviceEngine();
                engine.Start();
            });

            await Task.Delay(2000);

            var client1SimulatorTask = Task.Run(() =>
            {
                ClientSimulator client1Simulator = new ClientSimulator("8d781da7812048f70b1ed40e9aabd33d");
                client1Simulator.Start();
            });

            await Task.Delay(2000);

            var client2SimulatorTask = Task.Run(() =>
            {
                ClientSimulator client2Simulator = new ClientSimulator("452f24f61652351a75d22574c1f14aa8");
                client2Simulator.Start();
            });

            var timer = new System.Timers.Timer(10000);
            timer.Elapsed += (sender, e) => SimulateIPChange();
            timer.AutoReset = false;
            timer.Start();

            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                Environment.Exit(0);
            };

            await Task.WhenAll(vpsTask, ddnrsEngineTask, ddeviceTask, client1SimulatorTask, client2SimulatorTask);

            // Keep the main thread running
            while (true)
                await Task.Delay(100);
        }

        private static void SimulateIPChange()
        {
            Console.WriteLine("D2DARP: Simulating IP Change for DDevice");
            IsSimulatingIPChange = true;
        }
    }
}