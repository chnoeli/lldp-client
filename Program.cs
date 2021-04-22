using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.Npcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace lldp_client
{
    class Program
    {
        static void Main(string[] appArguments)
        {
            //https://www.codeproject.com/Articles/1705/IP-Multicasting-in-C
            // Print SharpPcap version
            string ver = SharpPcap.Version.VersionString;
            Console.WriteLine("SharpPcap {0}, Example3.BasicCap.cs", ver);

            // Retrieve the device list
            var devices = CaptureDeviceList.Instance;

            // If no devices were found print an error
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
                return;
            }

            Console.WriteLine();
            Console.WriteLine("The following devices are available on this machine:");
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine();

            int i = 0;

            // Print out the devices
            foreach (var dev in devices)
            {
                /* Description */
                Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                i++;
            }

            Console.WriteLine();
            Console.Write("-- Please choose a device to capture: ");
            i = int.Parse(Console.ReadLine());

            var device = devices[i];

            // Register our handler function to the 'packet arrival' event
            device.OnPacketArrival +=
                new PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            if (device is NpcapDevice)
            {
                var nPcap = device as NpcapDevice;
                nPcap.Open(SharpPcap.Npcap.OpenFlags.DataTransferUdp | SharpPcap.Npcap.OpenFlags.NoCaptureLocal, readTimeoutMilliseconds);
            }
            else if (device is LibPcapLiveDevice)
            {
                var livePcapDevice = device as LibPcapLiveDevice;
                livePcapDevice.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);
            }
            else
            {
                throw new InvalidOperationException("unknown device type of " + device.GetType().ToString());
            }

            Console.WriteLine();
            Console.WriteLine("-- Listening on {0} {1}, hit 'Enter' to stop...",
                device.Name, device.Description);

            // Start the capturing process
            device.StartCapture();

            // Wait for 'Enter' from the user.
            Console.ReadLine();

            // Stop the capturing process
            device.StopCapture();

            Console.WriteLine("-- Capture stopped.");

            // Print out the device statistics
            Console.WriteLine(device.Statistics.ToString());

            // Close the pcap device
            device.Close();

        }

        static List<string> LLDP_MAC_LIST = new List<string> { "01:80:c2:00:00:0e", "01:80:c2:00:00:03", "01:80:c2:00:00:00" };


        /// <summary>
        /// Prints the time and length of each received packet
        /// </summary>
        private static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            var time = e.Packet.Timeval.Date;
            var len = e.Packet.Data.Length;
            byte[] data = e.Packet.Data;
            //byte[] srcMAC = { 0,0,0,0,0,0 };


            List<byte> lis = convertToList(data);
            string dstMAC = convertToHexSting(lis.GetRange(0, 6));
            string srcMAC = convertToHexSting(lis.GetRange(7, 6));
            string etherType = convertToHexSting(lis.GetRange(12, 2), "");

            //Check if packet is LLDP Packet
            if (LLDP_MAC_LIST.Contains(dstMAC) && etherType == "88cc")
            {
                List<TLVEntry> tlvs = getTLVValue(lis.GetRange(14, lis.Count - 14));
                foreach (TLVEntry entry in tlvs)
                {
                    if (TLV_MAPPING.ContainsKey(entry.key) && entry.key != 127)
                    {
                        TLV_MAPPING tm = new TLV_MAPPING(entry.key);
                        Console.Write(tm.getAsString() + ":\t");
                        Console.WriteLine(System.Text.Encoding.Default.GetString(entry.value.ToArray()));
                    }
                }
                Console.WriteLine("\n---------------------\n\n\n");
                //Console.WriteLine("{0}:{1}:{2},{3} Len={4}", time.Hour, time.Minute, time.Second, time.Millisecond, len);

            }


        }

        private static List<byte> convertToList(byte[] arr)
        {
            var res = new List<byte>();
            foreach (var item in arr)
            {
                res.Add(item);
            }

            return res;
        }

        private static string convertToHexSting(List<byte> lis, string delimiter = ":")
        {
            String res = "";
            foreach (var item in lis)
            {
                res += item.ToString("X2") + delimiter;
            }
            if (delimiter != "")
            {
                res = res.EndsWith(delimiter) ? res.Substring(0, res.Length - 1) : res;
            }
            return res.ToLower();
        }

        private static List<TLVEntry> getTLVValue(List<byte> lis)
        {
            List<TLVEntry> res = new List<TLVEntry>();

            int type;
            int length;
            int offset = 0;

            do
            {
                int meta = (lis[offset + 0] * 0x0100) + lis[offset + 1];
                type = meta >> 9;
                length = meta & 0x1FF;
                var value = lis.GetRange(offset + 2, length);
                res.Add(new TLVEntry(type, length, value));

                offset = offset + 2 + length;
                //TODO Catch 127 Values

            } while (type != 00 && length != 00);



            return res;
        }
    }
}
