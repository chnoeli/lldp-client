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

        private static List<string> LLDP_MAC_LIST = new List<string> { "01:80:c2:00:00:0e", "01:80:c2:00:00:03", "01:80:c2:00:00:00" };
        //static Dictionary<int, string> TLV_MAPPING = new Dictionary<int, string>() {
        //    { 1, "Chassis ID" },
        //    { 2, "Port ID" },
        //    { 3, "TTL" },
        //    { 4, "Port Description" },
        //    { 5, "System name" },
        //    { 6, "System description" },
        //    { 7, "System capabilities" },
        //    { 8, "Management address" },
        //    { 127, "Custom TLV" }
        // };

        /// <summary>
        /// Prints the time and length of each received packet
        /// </summary>
        private static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            var time = e.Packet.Timeval.Date;
            var len = e.Packet.Data.Length;
            byte[] data = e.Packet.Data;


            List<byte> lis = convertToList(data);
            string dstMAC = convertToHexString(lis.GetRange(0, 6));
            string srcMAC = convertToHexString(lis.GetRange(7, 6));
            string etherType = convertToHexString(lis.GetRange(12, 2), "");

            //Check if packet is LLDP Packet
            if (LLDP_MAC_LIST.Contains(dstMAC) && etherType == "88cc")
            {
                List<TLVEntry> tlvs = getTLVValues(lis.GetRange(14, lis.Count - 14));
                foreach (TLVEntry entry in tlvs)
                {
                    string tmpValue;
                    //if (TLV_MAPPING.TryGetValue(entry.key, out tmpValue) && entry.key != 127)
                    //{
                    Console.Write(entry.key.ToString() + "\t" + entry.description + ":\t");
                    if (entry.key == 127) Console.Write(entry.subType + "\t" + entry.oui + "\t" + entry.customDescription + "\t");
                    Console.WriteLine(entry.value);
                    //Console.WriteLine(System.Text.Encoding.Default.GetString(entry.value.ToArray()));
                    //}
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

        public static string convertToHexString(List<byte> lis, string delimiter = ":")
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

        private static List<TLVEntry> getTLVValues(List<byte> data)
        {
            List<TLVEntry> res = new List<TLVEntry>();

            int type;
            int length;
            int offset = 0;

            do
            {
                int meta = (data[offset + 0] * 0x0100) + data[offset + 1];
                type = meta >> 9;
                length = meta & 0x1FF;
                if (length > 1)
                {
                    List<byte> value;
                    value = data.GetRange(offset + 2, length);

                    res.Add(new TLVEntry(type, length, value));
                    offset = offset + 2 + length;

                }


            } while (type != 00 && length != 00);



            return res;
        }
    }
}
