# CTI

Public Repository of my CTI

## Kusto Queries
### Domains

```
let indicators = (externaldata(domain:string, score:int, description:string)
[@"https://raw.githubusercontent.com/WildDogOne/CTI/main/domains.csv"] with (format="csv", ignoreFirstRecord=true));
DeviceEvents
| where ActionType startswith "Dns"
| extend dnsquery = tolower(parse_json(AdditionalFields)["DnsQueryString"])
| where isnotempty( dnsquery)
| join kind=inner indicators on $left.dnsquery == $right.domain
| project DeviceName, dnsquery, score, description
```

### IPv4

```
let indicators = (externaldata(ipv4:string, score:int, description:string)
[@"https://raw.githubusercontent.com/WildDogOne/CTI/main/ipv4.csv"] with (format="csv", ignoreFirstRecord=true));
DeviceNetworkEvents
| where isnotempty(RemoteIP)
| join kind=inner indicators on $left.RemoteIP == $right.ipv4
| project DeviceName, RemoteIP, score, description
```

Or being a bit recursive to try and weed out false positives from CDN
```
let indicators = (externaldata(ipv4:string, score:int, description:string)
[@"https://raw.githubusercontent.com/WildDogOne/CTI/main/ipv4.csv"] with (format="csv", ignoreFirstRecord=true));
let indicatorsv2 = DeviceNetworkEvents
| where Timestamp > ago(1d)
| where isnotempty(RemoteIP)
| where ipv4_is_private(RemoteIP) == false
| join kind=inner indicators on $left.RemoteIP == $right.ipv4
// Check if the Same IP has been seen with many Domains
// This can indicate a CDN, which makes it nearly impossible to use IP IOCs
| summarize x = count_distinct(RemoteUrl) by RemoteIP, description
| where x < 2;
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where isnotempty(RemoteIP)
| join kind=inner indicatorsv2 on $left.RemoteIP == $right.RemoteIP
| distinct Timestamp,
    DeviceName,
    DeviceId,
    RemoteIP,
    RemoteUrl,
    description,
    ReportId,
    InitiatingProcessFileName,
    InitiatingProcessAccountName,
    InitiatingProcessParentFileName
```

### URLs

```
let indicators = (externaldata(url:string, score:int, description:string)
[@"https://raw.githubusercontent.com/WildDogOne/CTI/main/urls.csv"] with (format="csv", ignoreFirstRecord=true));
DeviceNetworkEvents
| where isnotempty(RemoteUrl)
| extend lowerURL = tolower(RemoteUrl)
| join kind=inner indicators on $left.lowerURL == $right.url
```

Or plain ignore if it's http/s

```
let indicators = (externaldata(url:string, score:int, description:string)
[@"https://raw.githubusercontent.com/WildDogOne/CTI/main/urls.csv"] with (format="csv", ignoreFirstRecord=true))
| extend url = replace_string(url, "http://","")
| extend url = replace_string(url, "https://","");
DeviceNetworkEvents
| where isnotempty(RemoteUrl)
| extend lowerURL = tolower(RemoteUrl)
| extend lowerURL = replace_string(lowerURL,"http://","")
| extend lowerURL = replace_string(lowerURL,"https://","")
| join kind=inner indicators on $left.lowerURL == $right.url
```

### Hashes
#### MD5
```
let indicators = (externaldata(md5:string,sha1:string,sha256:string,score:int,description:string,name:string,additional_names:string)
[@"https://raw.githubusercontent.com/WildDogOne/CTI/main/hashes.csv"] with (format="csv", ignoreFirstRecord=true));
DeviceFileEvents
| where Timestamp > ago(24h)
| where isnotempty(MD5)
| join kind=inner indicators on $left.MD5 == $right.md5
```
#### SHA256
```
let indicators = (externaldata(md5:string,sha1:string,sha256:string,score:int,description:string,name:string,additional_names:string)
[@"https://raw.githubusercontent.com/WildDogOne/CTI/main/hashes.csv"] with (format="csv", ignoreFirstRecord=true));
DeviceFileEvents
| where Timestamp > ago(24h)
| where isnotempty(SHA256)
| join kind=inner indicators on $left.SHA256 == $right.sha256
```