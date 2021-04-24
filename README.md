# lldp-client
A command line tool to get get information about the LLDP neighbour.


# Basic Usage
To start you can just run ``.\lldp-client.exe`` the application will ask you to choose a network adapter.

The parameter ``-a`` let you add the network adapter as a argument.

```.\lldp-client.exe -a "Ethernet 1"```

The adapter must match a existing adapter on your machine.


To get a list of available network adapter run:

```.\lldp-client.exe -l```

The ``-d`` details parameter lets you choose how detailed the output should be. Allowed values are ``minimal, basic and all`` Default value is ``basic``.

```.\lldp-client.exe -a "Ethernet 1" -d all```


   

# TODOs
- Implement correct mapping for subtype according to IEEE standard
- Implement mapping for Location Identifier on custom TLVs 
- Implement management interface subtype handling
- Improve implemented custom TLVs
- Add more vendors custom TLVs 

# Links
- [IEEE OUIs](http://standards-oui.ieee.org/oui/oui.txt)
