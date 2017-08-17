# DNS notes #

### Module ###

The module only supports three record types at the moment:
* A/CNAME
* PRIVATE
* NULL

When the client mode has been started, it starts to do auto-tuning through the DNS server. Test the following things in this order:
* Checking whether the connection can be made
* Looking for the best rate by checking different encodings for the A record name
* Looking for the maximum length that can be used for upstream
* Mapping out the usable record types. The first that works is the best (checking in prioritized order)
* Looking for the best downstream rate with different encodings
* Looking for the maximum length that can be used for downstream

After authentication the client will send a message to the server to change the 5 properties. From that point the tunnel will use those encodings, lengths and records.

### Basic setup ###

After you registered your own domain that you want to use specifically (or mostly) for DNS tunneling, you need to:
* Set the NS records pointing to the XFLTReaT server. (When that is done, all requests about your domain will be directed to your server, where the XFLTReaT server will listen.)
* The configuration must be changed
    * [DNS] section **has to be** added with the "enabled = yes" line. Please see the xfltreat.conf
    * The "nameserver" can be specified in the config, otherwise it will use the system default from the /etc/resolv.conf.
    * The "hostname" **has to be** specified in the configuration file.
    * Additionally a zonefile can be specified that is RFC1035/BIND9 standard/compliant zonefile.

### Zonefile setup ###
The standard RFC1035 or BIND9 zonefile can be copied to the directory and specified in the xfltreat.conf configuration file. If the file is in a good format then all records that are supported by the XFLTReaT server will be read and used when the server is queried.
Unlike other DNS tunnelling solutions, it acts like a DNS server and answers predefined queries.


### Tested/Bugs ###

The module was tested with the newest Bind9 DNS server. Other implementations can behave differently, may not work at all.
Unfortunately this module is still in a proof of concept state because of the diversity of the implementations and many record types.
Please note that most of the edge cases are not handled, so this module can be easily crashed.
In case you found any problems with the module, please create an issue on the Github page and let me know about this with all the information that you can gather.
