using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace lldp_client
{
    class TLVEntry
    {
        public int key { get; }
        public int length { get; }
        public int subType { get; }
        public string description { get; }
        public List<byte> valueLis { get; }
        public string value { get; }
        public string oui { get; }
        public string customDescription { get; set; }



        private static int[] TLVhasSubtype = { 0x01, 0x02 };


        private static Dictionary<int, string> TLV_MAPPING = new Dictionary<int, string>() {
            { 1, "Chassis ID" },
            { 2, "Port ID" },
            { 3, "TTL" },
            { 4, "Port Description" },
            { 5, "System name" },
            { 6, "System description" },
            { 7, "System capabilities" },
            { 8, "Management address" },
            { 127, "Custom TLV" }
         };

        public TLVEntry(int key, int length, List<byte> value)
        {
            this.key = key;
            this.length = length;

            //set Subtype and value if available            
            if (TLVhasSubtype.Contains(key))
            {
                // TODO Implement correct subtype mapping according to IEEE standard
                this.subType = value[0];
                this.valueLis = value.GetRange(1, value.Count - 1);

            }
            //Custom vendor specific TLVs
            else if (this.key == 127)
            {
                this.oui = convertToHexString(value.GetRange(0, 3));
                this.subType = value[3];
                this.valueLis = value.GetRange(4, value.Count - 4);
            }
            else
            {
                this.subType = 0;
                this.valueLis = value;
            }

            //Set description
            string tmpDescription;
            if (TLV_MAPPING.TryGetValue(this.key, out tmpDescription))
            {
                this.description = tmpDescription;
            }
            else
            {
                this.description = "n/a";
            }

            this.value = getValue();
        }


        private string getValue()
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
                    int ttl = this.valueLis[0] * 0x0100 + this.valueLis[1];
                    return ttl.ToString();
                //Port Description
                case 0x04:
                    return convertToString(this.valueLis);
                //System Name
                case 0x05:
                    return convertToString(this.valueLis);
                //System Description
                case 0x06:
                    return convertToString(this.valueLis);
                //System Capabilities
                case 0x07:
                    return getCapabilities(this.valueLis);
                //Management Address
                case 0x08:
                    return getManagementAddress(this.valueLis);
                //Custom values
                case 0x7F:
                    return getValueForCustomTLV(this.valueLis);                
                default:
                    return convertToHexString(this.valueLis);
            }

        }

        private string getBySubType()
        {
            switch (subType)
            {
                //Format int
                case 0x00:
                    return convertToInteger(this.valueLis);
                //Format MAC Address
                case 0x04:
                    return convertToHexString(this.valueLis);
                //Format string
                case 0x05:
                    return convertToString(this.valueLis);
                default:
                    return convertToString(this.valueLis);
            }

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

        public static string convertToString(List<byte> lis, string delimiter = "")
        {
            string result = "";
            foreach (var item in lis)
            {
                if (item == 0x0a) result += "\\n";
                else result += Encoding.ASCII.GetString(new[] { item }) + delimiter;

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

        private string getValueForCustomTLV(List<byte> data)
        {
            string result = "";
            // Telecommunications Industry Association TR-41 Committee
            if (this.oui == "00:12:bb")
            {
                switch (subType)
                {
                    // LLDP-MED Cap
                    case 1:
                        this.customDescription = "LLDP-MED Cap";
                        return convertToHexString(data);
                    // Network Policy
                    case 2:
                        this.customDescription = "Network Policy";
                        return convertToHexString(data);
                    //Location Identifier
                    case 3:
                        //TODO implement Location Identifier
                        this.customDescription = "Location Identifier";
                        return convertToHexString(data);
                    // Inventory - Hardware Revision
                    case 5:
                        this.customDescription = "Inventory - Hardware Revision";
                        return convertToString(data);
                    // Inventory - Firmware Revision
                    case 6:
                        this.customDescription = "Inventory - Firmware Revision";
                        return convertToString(data);
                    // Inventory - Software Revision
                    case 7:
                        this.customDescription = "Inventory - Software Revision";
                        return convertToString(data);
                    // Inventory - Serial Number
                    case 8:
                        this.customDescription = "Inventory - Serial Number";
                        return convertToHexString(data);
                    // Inventory - Manufacturer Name
                    case 9:
                        this.customDescription = "Inventory - Manufacturer Name";
                        return convertToString(data);
                    // Inventory - Model Name
                    case 10:
                        this.customDescription = "Inventory - Model Name";
                        return convertToString(data);
                    default:
                        this.customDescription = "n/a";
                        return convertToHexString(data);
                }
            }
            //IEEE 802.1 Working Group
            if (this.oui == "00:80:c2")
            {
                switch (this.subType)
                {
                    //VLAN ID
                    case 1:
                        this.customDescription = "VLAN ID";
                        int vlanID = data[0] * 0x100 + data[1];
                        return vlanID.ToString();
                    default:
                        break;
                }
            }
            //IEEE 802.3
            if (this.oui == "00:12:0f")
            {
                switch (this.subType)
                {
                    //MAC/PHY Configuration/Status
                    case 1:
                        this.customDescription = "MAC/PHY Configuration/Status";
                        //TODO Implement MAC/PHY Configuration/Status 
                        return convertToHexString(data);
                    default:
                        return convertToHexString(data);
                }
            }

            return result;
        }
    }
}
