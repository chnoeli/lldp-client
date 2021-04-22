using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace lldp_client
{
    class TLV_MAPPING
    {
        static Dictionary<int, string> tlvTypes = new Dictionary<int, string>() {
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

        private int type;
        private string format;
        private List<byte> value;

        public TLV_MAPPING(int tlvType, List<byte> value)
        {
            switch (tlvType)
            {
                case 1:
                    type = tlvType;
                    format = "number";
                    break;
                case 2:
                    type = tlvType;
                    format = "number";
                    break;
                case 3:
                    type = tlvType;
                    format = "number";
                    break;
                case 4:
                    type = tlvType;
                    format = "number";
                    break;
                case 5:
                    type = tlvType;
                    format = "number";
                    break;
                case 6:
                    type = tlvType;
                    format = "number";
                    break;
                case 7:
                    type = tlvType;
                    format = "number";
                    break;
                case 8:
                    type = tlvType;
                    format = "number";
                    break;
                case 127:
                    type = tlvType;
                    format = "special";
                    break;

                default:
                    break;
            }
            this.value = value;
            
        }

        public string getAsString()
        {
            string res = this.value.ToString();
            return res;
        }
    }
}
