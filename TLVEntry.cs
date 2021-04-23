using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;

namespace lldp_client
{
    class TLVEntry
    {
        public int key { get; }
        public int length { get; }
        private int subType;
        public List<byte> value { get; }

        private int[] TLVhasSubtype = { 0x01, 0x02 };

        public TLVEntry(int key, int length, List<byte> value)
        {
            this.key = key;
            this.length = length;
            if (TLVhasSubtype.Contains(key))
            {
                this.subType = value[0];
                this.value = value.GetRange(1, value.Count - 1);

            }
            else
            {
                this.subType = 0;
                this.value = value;
            }
        }

        public string getValue()
        {
            switch (this.key)
            {
                // Chassis ID
                case 0x01:
                    return getBySubType();
                //Port ID
                case 0x02:
                    return getBySubType();
                //Time To live
                case 0x03:
                    int ttl = this.value[0] * 0x0100 + this.value[1];
                    return ttl.ToString();
                //Port Description
                case 0x04:
                    return convertToString(this.value);
                //System Name
                case 0x05:
                    return convertToString(this.value);
                //System Description
                case 0x06:
                    return convertToString(this.value);
                //System Capabilities
                case 0x07:
                    return getCapabilities(this.value);
                //Management Address
                case 0x08:
                    return getManagementAddress(this.value);
                default:
                    return convertToString(this.value);
            }

        }

        private string getBySubType()
        {
            switch (subType)
            {
                //Format int
                case 0x00:
                    return convertToInteger(this.value);
                //Format MAC Address
                case 0x04:
                    return convertToHexSting(this.value);
                //Format string
                case 0x05:
                    return convertToString(this.value);
                default:
                    return convertToString(this.value);
            }

        }

        public static string convertToHexSting(List<byte> lis, string delimiter = ":")
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

        public static string convertToString(List<byte> lis, string delimiter = "")
        {
            string result = "";
            foreach (var item in lis)
            {
                result += Encoding.ASCII.GetString(new[] { item }) + delimiter;
            }
            if (delimiter != "")
            {
                result = result.EndsWith(delimiter) ? result.Substring(0, result.Length - 1) : result;
            }
            return result;
        }

        public static string convertToInteger(List<byte> lis)
        {
            int listSize = lis.Count() - 1;
            int result = 0;
            for (int i = 0; i < lis.Count(); i++)
            {
                result += lis[i] * (0x100 * (listSize - i));
            }
            return result.ToString();
        }

        private string getCapabilities(List<byte> lis)
        {
            int availableCaps = lis[0] * 0x100 + lis[1];
            int enabledCaps = lis[2] * 0x100 + lis[3];
            string availableCapsStr = mapCapabilities(availableCaps);
            string enabledCapsStr = mapCapabilities(enabledCaps);
            return enabledCapsStr;

        }

        private string mapCapabilities(int caps)
        {
            string res = "";
            bool FLAG_other = (caps & 0b_0000_0001) > 0 ? true : false;
            bool FLAG_Repeater = (caps & 0b_0000_0010) > 0 ? true : false;
            bool FLAG_Bridge = (caps & 0b_0000_0100) > 0 ? true : false;
            bool FLAG_WLAN = (caps & 0b_0000_1000) > 0 ? true : false;
            bool FLAG_Router = (caps & 0b_0001_0000) > 0 ? true : false;
            bool FLAG_Telephone = (caps & 0b_0010_0001) > 0 ? true : false;
            bool FLAG_DOCSIS = (caps & 0b_0100_0001) > 0 ? true : false;
            bool FLAG_Staion = (caps & 0b_1000_0001) > 0 ? true : false;

            if (FLAG_Staion) res += "S "; else res += "- ";
            if (FLAG_DOCSIS) res += "C "; else res += "- ";
            if (FLAG_Telephone) res += "T "; else res += "- ";
            if (FLAG_Router) res += "R "; else res += "- ";
            if (FLAG_WLAN) res += "W "; else res += "- ";
            if (FLAG_Bridge) res += "B "; else res += "- ";
            if (FLAG_Repeater) res += "P "; else res += "- ";
            if (FLAG_other) res += "O "; else res += "- ";


            return res;

        }

        private string getManagementAddress(List<byte> lis)
        {
            int ipLength = lis[0] - 1;
            int ipSubtype = lis[1];
            string ipAddress;
            switch (ipSubtype)
            {
                //ipV4
                case 1:
                    ipAddress = getIp(lis.GetRange(2, ipLength));
                    break;
                default:
                    ipAddress = convertToString(lis.GetRange(2, ipLength), ":");
                    break;
            }
            //TODO Handle Interface Subtpypes
            return ipAddress;


        }

        private string getIp(List<byte> lis, string delimiter = ".")
        {
            string result = "";
            foreach (var item in lis)
            {
                result += item.ToString() + delimiter;
            }
            if (delimiter != "")
            {
                result = result.EndsWith(delimiter) ? result.Substring(0, result.Length - 1) : result;
            }
            return result;
        }

    }
}
