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
    class LLDP_client
    {

        private static List<string> LLDP_MAC_LIST = new List<string> { "01:80:c2:00:00:0e", "01:80:c2:00:00:03", "01:80:c2:00:00:00" };
        private DETAILS_OPTION option;
        public enum DETAILS_OPTION
        {
            basic,
            minimal,
            all
        }


        public LLDP_client(ICaptureDevice device, DETAILS_OPTION option)
        {
            this.option = option;

            // Register our handler function to the 'packet arrival' event
            device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);

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
            Console.WriteLine("Listening on {0}, hit 'Enter' to stop...", device.Description);

            // Start the capturing process
            device.StartCapture();

            // Wait for 'Enter' from the user.
            Console.ReadLine();

            // Stop the capturing process
            device.StopCapture();

            Console.WriteLine("App stopped.");

            // Close the pcap device
            device.Close();
        }

        public static ICaptureDevice GetCaptureDeviceByDescription(string name)
        {
            var devices = CaptureDeviceList.Instance;
            foreach (var dev in devices)
            {
                Console.WriteLine("==" + dev.Description + "==");
                Console.WriteLine("==" + name + "==");
                if (dev.Description == name)
                {

                    return dev;
                }

            }
            Console.WriteLine("ERROR: No matching network adapter found for: {0} ", name);
            return null;
        }


        public static ICaptureDevice getCaptureDeviceBySelection()
        {
            CaptureDeviceList devices = getCaptureDeviceList();

            Console.WriteLine();
            Console.Write("Please choose a device to capture: ");
            int i = int.Parse(Console.ReadLine());

            ICaptureDevice device = devices[i];

            return device;

        }

        private static CaptureDeviceList getCaptureDeviceList()
        {
            var devices = CaptureDeviceList.Instance;

            // If no devices were found print an error
            if (devices.Count < 1)
            {
                Console.WriteLine("ERROR: No devices were found on this machine.");
                return null;
            }
            else
            {
                return devices;
            }
        }

        public static void printAdapters()
        {
            var devices = getCaptureDeviceList();

            int i = 0;
            Console.WriteLine("Available Devices:");
            // Print out the devices
            foreach (var dev in devices)
            {
                Console.WriteLine("{0}) {1}", i, dev.Description);
                i++;
            }
        }

        private void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            var time = e.Packet.Timeval.Date;
            var len = e.Packet.Data.Length;
            byte[] data = e.Packet.Data;

            List<byte> lis = convertToList(data);
            string dstMAC = TLVEntry.convertToHexString(lis.GetRange(0, 6));
            string srcMAC = TLVEntry.convertToHexString(lis.GetRange(7, 6));
            string etherType = TLVEntry.convertToHexString(lis.GetRange(12, 2), "");

            //Check if packet is LLDP Packet
            if (LLDP_MAC_LIST.Contains(dstMAC) && etherType == "88cc")
            {
                List<TLVEntry> tlvs = getTLVValues(lis.GetRange(14, lis.Count - 14));

                if (option == DETAILS_OPTION.basic)
                {
                    var chassisId = getTLVByKey(tlvs, 1);
                    var portId = getTLVByKey(tlvs, 2);
                    var systemName = getTLVByKey(tlvs, 5);
                    Console.WriteLine("{0}: {1}", chassisId.description, chassisId.value);
                    Console.WriteLine("{0}\t{1} ", systemName.description, portId.description);
                    Console.WriteLine("{0}\t{1} ", systemName.value, portId.value);
                    Console.WriteLine();
                }
                else if (option == DETAILS_OPTION.minimal)
                {
                    var portId = getTLVByKey(tlvs, 2);
                    var systemName = getTLVByKey(tlvs, 5);
                    Console.WriteLine("{0}:\t{1}", systemName.description, systemName.value);
                    Console.WriteLine("{0}:\t{1}", portId.description, portId.value);
                }
                else if (option == DETAILS_OPTION.all)
                {
                    Console.WriteLine("=====================================");
                    foreach (var entry in tlvs)
                    {
                        Console.Write(entry.description + ":\t");
                        if (entry.key == 127) Console.Write(entry.customDescription + ":\t");
                        Console.WriteLine(entry.value);
                    }
                    Console.WriteLine("=====================================\n");
                }                                            

            }


        }

        private TLVEntry getTLVByKey(List<TLVEntry> tlvs, int key)
        {
            foreach (TLVEntry entry in tlvs)
            {
                if (entry.key == key)
                {
                    return entry;
                }
            }

            return null;
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
