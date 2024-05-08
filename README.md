# CTI

Public Repository of my CTI

## Kusto Queries
### Domains

```
let indicators = (externaldata(created_at:string,
                                entity_type:string,
                                objectLabel:string,
                                objectMarking:string,
                                observable_value:string,
                                updated_at:string,
                                value:string,
                                x_opencti_description:string,
                                x_opencti_score:int)
[@"https://raw.githubusercontent.com/WildDogOne/CTI/main/domain-name_24h.csv"] with (format="csv", ignoreFirstRecord=true));
DeviceEvents
| where Timestamp > ago(1d)
| where ActionType startswith "Dns"
| extend dnsquery = tolower(parse_json(AdditionalFields)["DnsQueryString"])
| where isnotempty( dnsquery)
| join kind=inner indicators on $left.dnsquery == $right.value
```

### IPv4

```
let indicators = (externaldata(created_at:string,
                                entity_type:string,
                                objectLabel:string,
                                objectMarking:string,
                                observable_value:string,
                                updated_at:string,
                                value:string,
                                x_opencti_description:string,
                                x_opencti_score:int)
[@"https://github.com/WildDogOne/CTI/raw/main/IPv4-Addr_24h.csv"] with (format="csv", ignoreFirstRecord=true));
DeviceNetworkEvents
| where isnotempty(RemoteIP)
| join kind=inner indicators on $left.RemoteIP == $right.value
| project DeviceName, RemoteIP, x_opencti_score, x_opencti_description
```

Or being a bit recursive to try and weed out false positives from CDN
```
let indicators = (externaldata(created_at:string,
                                entity_type:string,
                                objectLabel:string,
                                objectMarking:string,
                                observable_value:string,
                                updated_at:string,
                                value:string,
                                x_opencti_description:string,
                                x_opencti_score:int)
[@"https://github.com/WildDogOne/CTI/raw/main/IPv4-Addr_24h.csv"] with (format="csv", ignoreFirstRecord=true));
let indicatorsv2 = DeviceNetworkEvents
| where Timestamp > ago(1d)
| where isnotempty(RemoteIP)
| where ipv4_is_private(RemoteIP) == false
| join kind=inner indicators on $left.RemoteIP == $right.value
// Check if the Same IP has been seen with many Domains
// This can indicate a CDN, which makes it nearly impossible to use IP IOCs
| summarize x = count_distinct(RemoteUrl) by RemoteIP, x_opencti_description
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
    x_opencti_description,
    ReportId,
    InitiatingProcessFileName,
    InitiatingProcessAccountName,
    InitiatingProcessParentFileName
```

### URLs

```
let indicators = (externaldata(created_at:string,
                                entity_type:string,
                                objectLabel:string,
                                objectMarking:string,
                                observable_value:string,
                                updated_at:string,
                                value:string,
                                x_opencti_description:string,
                                x_opencti_score:int)
[@"https://raw.githubusercontent.com/WildDogOne/CTI/main/url_24h.csv"] with (format="csv", ignoreFirstRecord=true));
DeviceNetworkEvents
| where isnotempty(RemoteUrl)
| extend lowerURL = tolower(RemoteUrl)
| join kind=inner indicators on $left.lowerURL == $right.value
```

Or plain ignore if it's http/s

```
let indicators = (externaldata(created_at:string,
                                entity_type:string,
                                objectLabel:string,
                                objectMarking:string,
                                observable_value:string,
                                updated_at:string,
                                value:string,
                                x_opencti_description:string,
                                x_opencti_score:int)
[@"https://raw.githubusercontent.com/WildDogOne/CTI/main/url_24h.csv"] with (format="csv", ignoreFirstRecord=true))
| extend url = tolower(value)
| extend url = replace_string(url, "http://","")
| extend url = replace_string(url, "https://","");
DeviceNetworkEvents
| where Timestamp > ago(3h)
| where isnotempty(RemoteUrl)
| extend lowerURL = tolower(RemoteUrl)
| extend lowerURL = replace_string(lowerURL,"http://","")
| extend lowerURL = replace_string(lowerURL,"https://","")
| join kind=inner indicators on $left.lowerURL == $right.url
```

### Hashes
#### MD5
```
let indicators = (externaldata(created_at:string,
                                decryption_key:string,
                                encryption_algorithm:string,
                                entity_type:string,
                                hashes:string,
                                objectLabel:string,
                                objectMarking:string,
                                observable_value:string,
                                payload_bin:string,
                                updated_at:string,
                                url:string,
                                x_opencti_description:string,
                                x_opencti_score:int,
                                hashes_MD5:string,
                                hashes_SHA1:string,
                                hashes_SHA256:string,
                                hashes_SHA512:string,
                                hashes_SSDEEP:string)
[@"https://raw.githubusercontent.com/WildDogOne/CTI/main/Artifact_24h.csv"] with (format="csv", ignoreFirstRecord=true));
DeviceFileEvents
| where Timestamp > ago(24h)
| where isnotempty(MD5)
| join kind=inner indicators on $left.MD5 == $right.hashes_MD5
```
#### SHA256
```
let indicators = (externaldata(created_at:string,
                                decryption_key:string,
                                encryption_algorithm:string,
                                entity_type:string,
                                hashes:string,
                                objectLabel:string,
                                objectMarking:string,
                                observable_value:string,
                                payload_bin:string,
                                updated_at:string,
                                url:string,
                                x_opencti_description:string,
                                x_opencti_score:int,
                                hashes_MD5:string,
                                hashes_SHA1:string,
                                hashes_SHA256:string,
                                hashes_SHA512:string,
                                hashes_SSDEEP:string)
[@"https://raw.githubusercontent.com/WildDogOne/CTI/main/Artifact_24h.csv"] with (format="csv", ignoreFirstRecord=true));
DeviceFileEvents
| where Timestamp > ago(24h)
| where isnotempty(SHA256)
| join kind=inner indicators on $left.SHA256 == $right.hashes_SHA256
```