using CommandLine;
using SharpPcap;
using System.Collections.Generic;
using System.Linq;


namespace lldp_client
{
    class Program
    {
        public class Options
        {
            [Option('a', "adapter", Required = false, HelpText = "Netowrk adapter where to listen for LLDP packets.")]
            public IEnumerable<string> adapter { get; set; }
            [Option('d', "details", Required = false, HelpText = "(Default=basic) What kind of LLDP information to display. ['minimal', 'basic', 'all']")]
            public IEnumerable<LLDP_client.DETAILS_OPTION> details { get; set; }
            [Option('l', "list", Required = false, HelpText = "List available network adapters")]
            public bool list { get; set; }            
        }

        static void Main(string[] appArguments)
        {
            Parser.Default.ParseArguments<Options>(appArguments)
                  .WithParsed<Options>(o =>
                  {
                      LLDP_client.DETAILS_OPTION option = LLDP_client.DETAILS_OPTION.basic;
                      if (o.details.Any())
                      {
                          option = o.details.First();
                      }
                      //List all Network available adapters
                      if (o.list)
                      {
                          LLDP_client.printAdapters();
                          return;
                      }

                      if (o.adapter.Any())
                      {
                          string networkAdapter = "";
                          foreach (var word in o.adapter)
                          {
                              networkAdapter += word + " ";
                          }
                          networkAdapter = networkAdapter.Trim();
                          ICaptureDevice device = LLDP_client.GetCaptureDeviceByDescription(networkAdapter);

                          if (device != null)
                          {
                              LLDP_client lc = new LLDP_client(device, option);
                          }
                      }
                      else
                      {
                          LLDP_client.printAdapters();
                          ICaptureDevice device = LLDP_client.getCaptureDeviceBySelection();
                          if (device != null)
                          {
                              LLDP_client lc = new LLDP_client(device, option);
                          }
                      }
                  });



        }
    }
}
