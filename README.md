# Scanner for SLP services (CVE-2019-5544 CVE-2020-3992)
Python script that implements SRVLOC/SLP protocol to scan for enabled OpenSLP services.

You may find it handy while searching for systems impacted by CVE-2019-5544 and CVE-2020-3992

More info on the VMware vulnerability you may find for instance here: https://blog.rapid7.com/2020/11/11/vmware-esxi-openslp-remote-code-execution-vulnerability-cve-2020-3992-and-cve-2019-5544-what-you-need-to-know/

The script does not detect, whether the service is vulnerable or not, but it reports the remote VMWare version and build

## Requirements

You will require python3 and scapy library installed, i.e. `pip3 install scapy`

## Usage

```
./check_slp.py <file_with_targets>
```

where argument is a file with ip address or networks in CIDR notation.

## Output
```
2020-12-01 15:03:15,654 - INFO - [ip_removed] Sending packet via Unicast UDP
2020-12-01 15:03:15,778 - INFO - [ip_removed] SLP Service detected
2020-12-01 15:03:16,032 - INFO - [ip_removed] ATTR    service:VMwareInfrastructure://[fqdn_removed]      (product="VMware ESXi 6.5.0 build-17097218"),(hardwareUuid="30313436-3631-584D-5133-343230505032")
2020-12-01 15:03:16,292 - INFO - [ip_removed] ATTR    service:wbem:https://[fqdn_removed]:5989   (MultipleOperationsSupported=false),(AuthenticationMechanismsSupported=Basic),(Namespace=root/interop,interop,root/hpq,root/cimv2,root/config,vmware/esxv2),(Namespace=root/cimv2,root/interop,root/config,vmware/esxv2),(Classinfo=0,0,0,0),(ProtocolVersion=1.0),(RegisteredProfilesSupported=DMTF:Sensors,DMTF:Base Server,DMTF:Power State Management,DMTF:CPU,DMTF:Software Inventory,DMTF:Record Log,DMTF:System Memory,DMTF:Physical Asset,DMTF:Fan,DMTF:Power Supply,DMTF:Profile Registration,DMTF:Battery,)

```
