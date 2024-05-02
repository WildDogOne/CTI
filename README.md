# CTI

Public Repository of my CTI

## Kusto Queries
### Domains

```
let indicators = (externaldata(domain:string, score:int)
[@"https://raw.githubusercontent.com/WildDogOne/CTI/main/domains.csv"] with (format="csv"));
DeviceEvents
| where ActionType startswith "Dns"
| extend dnsquery = tolower(parse_json(AdditionalFields)["DnsQueryString"])
| where isnotempty( dnsquery)
| join kind=inner indicators on $left.dnsquery == $right.domain
| project DeviceName, dnsquery, score
```