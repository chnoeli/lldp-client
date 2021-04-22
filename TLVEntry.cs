using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace lldp_client
{
    class TLVEntry
    {
        public int key { get; }
        public int length { get; }
        public List<byte> value { get; }

        public TLVEntry(int key, int length, List<byte> value)
        {
            this.key = key;
            this.length = length;
            this.value = value;
        }
    }
}
