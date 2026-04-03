# AbuseIPDB Check Endpoint — mtc_checkendpoint.c

## Overview

The check endpoint accepts a single IP address (v4 or v6). Optionally you may set the `maxAgeInDays` parameter to only return reports within the last x amount of days.

## Response Data

The desired data is stored in the `data` property. Here you can inspect details regarding the IP address queried, such as version, country of origin, usage type, ISP, and domain name. And of course, there is the valuable abusive reports.

Geolocation, usage type, ISP, and domain name are sourced from IPinfo. If you're looking for a performant IP database for geolocation, then use their product directly.

### isWhitelisted

The `isWhitelisted` property reflects whether the IP is spotted in any of our whitelists. Our whitelists give the benefit of the doubt to many IPs, so it generally should not be used as a basis for action. The `abuseConfidenceScore` is a better basis for action, because it is nonbinary and allows for nuance. The `isWhitelisted` property may be null if a whitelist lookup was not performed.

### usageType

The `usageType` is a string that describes the general usage of this address. Possible values are:

- Commercial
- Organization
- Government
- Military
- University/College/School
- Library
- Content Delivery Network
- Fixed Line ISP
- Mobile ISP
- Data Center/Web Hosting/Transit
- Search Engine Spider
- Reserved

### maxAgeInDays

The `maxAgeInDays` parameter determines how far back in time we go to fetch reports. In this example, we ask for reports no older than 90 days. The default is 30.

### totalReports

The `totalReports` property is a sum of the reports within `maxAgeInDays`.

### Reports (verbose mode)

Reports are included in this response because the verbose flag was added. Omitting the verbose flag will exclude reports and the country name field. If you want to keep your response payloads light, this is recommended. The reports array is limited to 10,000 elements. Only reports within the timeframe of `maxAgeInDays` are considered.

## Notes

The IP address should be url-encoded, because IPv6 addresses use colons, which are reserved characters in URIs.

## Check Parameters

| field | required | default | min | max |
|-------|----------|---------|-----|-----|
| ipAddress | yes | | | |
| maxAgeInDays | no | 30 | 1 | 365 |
| verbose | no | | | |

## REPORTS Endpoint

## Appendix: Calling Example Using curl

```bash
# The -G option will convert form parameters (-d options) into query parameters.
# The CHECK endpoint is a GET request.
curl -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=118.25.6.39" \
  -d maxAgeInDays=90 \
  -d verbose \
  -H "Key: YOUR_OWN_API_KEY" \
  -H "Accept: application/json"
```

### Python Example

```python
import requests
import json

# Defining the api-endpoint
url = 'https://api.abuseipdb.com/api/v2/check'

querystring = {
    'ipAddress': '118.25.6.39',
    'maxAgeInDays': '90'
}

headers = {
    'Accept': 'application/json',
    'Key': 'YOUR_OWN_API_KEY'
}

response = requests.request(method='GET', url=url, headers=headers, params=querystring)

# Formatted output
decodedResponse = json.loads(response.text)
print json.dumps(decodedResponse, sort_keys=True, indent=4)
```

### Sample Response

This will yield the following JSON response:

```json
{
  "data": {
    "ipAddress": "118.25.6.39",
    "isPublic": true,
    "ipVersion": 4,
    "isWhitelisted": false,
    "abuseConfidenceScore": 100,
    "countryCode": "CN",
    "countryName": "China",
    "usageType": "Data Center/Web Hosting/Transit",
    "isp": "Tencent Cloud Computing (Beijing) Co. Ltd",
    "domain": "tencent.com",
    "hostnames": [],
    "isTor": false,
    "totalReports": 1,
    "numDistinctUsers": 1,
    "lastReportedAt": "2018-12-20T20:55:14+00:00",
    "reports": [
      {
        "reportedAt": "2018-12-20T20:55:14+00:00",
        "comment": "Dec 20 20:55:14 srv206 sshd[13937]: Invalid user oracle from 118.25.6.39",
        "categories": [
          18,
          22
        ],
        "reporterId": 1,
        "reporterCountryCode": "US",
        "reporterCountryName": "United States"
      }
    ]
  }
}
```

### Error Response

```json
{
  "errors": [
    {
      "detail": "The max age in days must be between 1 and 365.",
      "status": 422
    }
  ]
}
```

### API Key

The key argument `'Key': 'YOUR_OWN_API_KEY'` is stored in `/home/ubuntu/.env` as `ABUSEIPDB_KEY`.
