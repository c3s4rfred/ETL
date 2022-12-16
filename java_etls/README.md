# TWTransformationService

TWTransformationService is an API to consume data from a configured feed, transform it
to threat winds format and insert it via threat winds endpoint. **_Current version is 1.0.0_**

## Contents
- [Project Structure](#project-structure)
  - [Project Environment Variables](#project-environment-variables)
  - [Feed Types](#feed-types)
  - [Variables needed according to Feed Types](#variables-needed-according-to-feed-types)
- [Building for production](#building-for-production)
  - [Packaging as jar](#packaging-as-jar) 
- [Using Docker](#using-docker)

## Project Structure

`/src/*` structure follows default Java structure.

### Project Environment Variables

The project have a couple of variables used to work at runtime, according to the feed you are processing.
Variables will be explained as follows:

- `FEED_URL` - (`Required`) Represents the URL of the feed to be executed (Ex: https://www.circl.lu/doc/misp/feed-osint/)

- `FEED_FORMAT` - (`Required`) Represents the name of the feed to be executed, must be the same defined in (see `Feed Types` section)

- `FEED_BASE_REPUTATION` - (`Optional`) Represents the base reputation used for the feeds
that don't have a field to get the reputation. Must be a value between -3 and 0, any other value used will default to -1.

- `LINK_PATTERN` - (`Optional`) Represents a pattern to include links that match in case the `FEED_URL` holds many file links and have to scrap them 
(Ex: For OSINT CIRCL is `(.+)-(.+)-(.+)-(.+)-(.+)\.json`)

- `GITHUB_BRANCH_NAME` - (`Optional`) Represents the base `github branch` to scan for files (Ex: `master`). Only (`Required`) for `GITHUB_YARA` feed format

- `THREAD_POOL_SIZE` - (`Optional`) Represents the concurrent process that can be executed, must be a positive Integer > 0, if you don't provide a value or is < 1, defaults to 8.

- `TW_API_URL` - (`Required`) Represents the threatwinds endpoints base URL (Without ending `/` and `/api/{TW_API_VERSION}` ), (Ex: https://api.sandbox.threatwinds.com)

- `TW_AUTHENTICATION` - (`Optional`) Represents the `Authentication` key to access threatwinds endpoints URL (`TW_API_URL`). 
This value is Bearer authentication token without `Bearer` keyword.
It's `Required` only if `TW_API_KEY` and/or `TW_API_SECRET` are not defined
(Ex: aUPcne0pfLNmBs8Va43FpVekt2uWIAMJ5lUM51VBzi6K8RLucLZ76oSSyNtZQekW)

- `TW_API_KEY` - (`Optional`) Represents the access key to the threatwinds endpoints URL (`TW_API_URL`).
It's `Required` only if `TW_AUTHENTICATION` is not defined.

- `TW_API_SECRET` - (`Optional`) Represents the access secret for threatwinds endpoints URL (`TW_API_URL`).
It's `Required` only if `TW_AUTHENTICATION` is not defined.

- `TW_API_ENTITY_BASE_TYPE` - (`Optional`) Represents the base `type` field definition for a top level entity in case you don't have a field from origin to use (Ex: `threat`). 
Defaults to `threat` if not defined.

- `TW_API_VERSION` - (`Optional`) Represents the base `version` of the endpoint api, defaults to `v1` if not defined  (Ex: `v1`)

### Feed Types

If you don't provide a value for `FEED_FORMAT` variable that match with any Feed Type as follows, the process gets executed
but nothing will happen

#### v1.0.0

- `OSINT_CIRCL` - Type for feed: https://www.circl.lu/doc/misp/feed-osint/
- `OSINT_BOTVRIJ` - Type for feed: https://www.botvrij.eu/data/feed-osint/
- `OSINT_DIJITAL_SIDE` - Type for feed: https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/
- `GITHUB_YARA` - Type for any github repository that holds yara rules. Used in this version for feed: https://github.com/Yara-Rules/rules
- `RFXN_YARA` - Type for feed: https://www.rfxn.com/downloads/rfxn.yara
- `GENERIC_IP_LIST` - Type for any feed that comes from a single raw file
and holds only separated lines of IP addresses or segments, without comments or header, 
see tested list below:
  - https://rules.emergingthreats.net/blockrules/compromised-ips.txt
  - https://www.dan.me.uk/torlist/?exit
  - https://www.dan.me.uk/torlist/
  - https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt
  - https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt
  - https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt
  - https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt
  - https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt
  - https://raw.githubusercontent.com/stamparm/ipsum/master/levels/6.txt
  - https://raw.githubusercontent.com/stamparm/ipsum/master/levels/7.txt
  - https://raw.githubusercontent.com/stamparm/ipsum/master/levels/8.txt
- `ABUSE_SSLIP_BLACKLIST` - Type for feed: https://sslbl.abuse.ch/blacklist/sslipblacklist.csv
- `REPUTATION_ALIEN_VAULT` - Type for feed: https://reputation.alienvault.com/reputation.generic
- `COMMENT_IP_LIST` - Type for any feed that comes from a single raw file
  and holds only separated lines of IP addresses or segments, with comments (lines beginning with `#`),
  see tested list below:
  - https://home.nuug.no/~peter/pop3gropers.txt
  - https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset
- `FEODOTRACKER_IP_BLOCKLIST` - Type for feed: https://feodotracker.abuse.ch/downloads/ipblocklist.csv
- `CYBERCURE_AI_IP` - Type for feed: https://api.cybercure.ai/feed/get_ips?type=csv
- `MALSILO_IP_LIST` - Type for feed: https://malsilo.gitlab.io/feeds/dumps/ip_list.txt
- `GENERIC_URL_LIST` - Type for any feed that comes from a single raw file
  and holds only separated lines of URLs, without comments or header,
  see tested list below:
  - https://cybercrime-tracker.net/all.php
  - https://openphish.com/feed.txt
  - https://cybercrime-tracker.net/ccamgate.php
  - https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list.txt?inline=false
  - https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list_optional.txt?inline=false
  - https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list_browser.txt?inline=false
- `PHISHTANK_ONLINE_URL_LIST` - Type for feed: https://data.phishtank.com/data/online-valid.csv
- `DIAMOND_FOX_URL_LIST` - Type for feed: https://raw.githubusercontent.com/pan-unit42/iocs/master/diamondfox/diamondfox_panels.txt
- `VXVAULT_URL_LIST` - Type for feed: http://vxvault.net/URL_List.php
- `CYBERCURE_AI_URL_LIST` - Type for feed: https://api.cybercure.ai/feed/get_url?type=csv
- `MALSILO_URL_LIST` - Type for feed: https://malsilo.gitlab.io/feeds/dumps/url_list.txt
- `BENKOW_CC_URL_LIST` - Type for feed: https://benkow.cc/export.php
- `ZIP_HAUS_ABUSE_URL_LIST` - Type for feed: https://urlhaus.abuse.ch/downloads/csv/
- `GENERIC_CVE_LIST` - Type for any feed that comes from a single raw file
  and holds only separated lines of CVE identifiers, without comments or header,
  see tested list below:
  - https://feeds.ecrimelabs.net/data/metasploit-cve
- `MALSILO_DOMAIN_LIST` - Type for feed: https://malsilo.gitlab.io/feeds/dumps/domain_list.txt
- `ZIP_WITH_GENERIC_MD5_LIST` - Type for any feed that comes from a single zip file, with single file inside
  and holds only separated lines of MD5 hashes, without header, can have comments (lines beginning with `#`)
  see tested list below:
  - https://bazaar.abuse.ch/export/txt/md5/full/
- `MALSHARE_CURRENT_DAILY_SHA256_LIST` - Type for feed: https://malshare.com/daily/malshare.current.all.txt

### Variables needed according to Feed Types

Following variables must be set to avoid execution errors,
optionals are marked as `Optional`, if not assume that the variable is `Required`. `COMMON FOR ALL FEEDS` represents common variables for all feeds.

#### v1.0.0

- `COMMON FOR ALL FEEDS`
  - `FEED_URL` - Value is according to `FEED_FORMAT`
  - `FEED_FORMAT` - See specific `FEED_FORMAT` values below
  - `THREAD_POOL_SIZE` - Example value: `8`
  - `TW_API_URL` - Example value: https://api.sandbox.threatwinds.com
  - `TW_AUTHENTICATION` - (`Optional`) - Example value: aUPcne0pfLNmBs8Va43FpVekt2uWIAMJ5lUM51VBzi6K8RLucLZ76oSSyNtZQekW
  - `TW_API_KEY` - (`Optional`) - Too long to show an example
  - `TW_API_SECRET` - (`Optional`) - Too long to show an example
  - Remember that for all feeds you must define `TW_AUTHENTICATION` or (`TW_API_KEY` and `TW_API_SECRET`) values to authenticate to `TW_API_URL`
- `OSINT_CIRCL`
  - `FEED_URL` - Value: https://www.circl.lu/doc/misp/feed-osint/
  - `FEED_FORMAT` - Value: `OSINT_CIRCL`
  - `LINK_PATTERN` - Value: `(.+)-(.+)-(.+)-(.+)-(.+)\.json`
  - `TW_API_ENTITY_BASE_TYPE` - Example value: `threat`
- `OSINT_BOTVRIJ` - Same as `OSINT_CIRCL` except for the variables below
  - `FEED_URL` - Value: https://www.botvrij.eu/data/feed-osint/
  - `FEED_FORMAT` - Value: `OSINT_BOTVRIJ`
- `OSINT_DIJITAL_SIDE` - Same as `OSINT_CIRCL` except for the variables below
  - `FEED_URL` - Value: https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/
  - `FEED_FORMAT` - Value: `OSINT_DIJITAL_SIDE`
- `GITHUB_YARA` - It's important to know in this case, that with `GITHUB_YARA` feed format you can process any github "repository" URL, even if it's more specific like: https://github.com/Yara-Rules/rules/tree/master/deprecated, in which case the value of the branch in the URL and `GITHUB_BRANCH_NAME` value must match, otherwise you will get wrong results. Only `.yar` and `.yara` links are processed.
  - `FEED_URL` - Value: https://github.com/Yara-Rules/rules
  - `FEED_FORMAT` - Value: `GITHUB_YARA`
  - `GITHUB_BRANCH_NAME` - Value: `master`
- `RFXN_YARA`
  - `FEED_URL` - Value: https://www.rfxn.com/downloads/rfxn.yara
  - `FEED_FORMAT` - Value: `RFXN_YARA`
- `GENERIC_IP_LIST`
  - `FEED_URL` - Value: Any in the list of `GENERIC_IP_LIST` in [Feed Types](#feed-types) above
  - `FEED_FORMAT` - Value: `GENERIC_IP_LIST`
  - `FEED_BASE_REPUTATION` - (`Optional`) Value: Any value between -3 and 0 as you determine, any other value used will default to -1.
- `ABUSE_SSLIP_BLACKLIST`
  - `FEED_URL` - Value: https://sslbl.abuse.ch/blacklist/sslipblacklist.csv
  - `FEED_FORMAT` - Value: `ABUSE_SSLIP_BLACKLIST`
  - `FEED_BASE_REPUTATION` - (`Optional`) Value: Any value between -3 and 0 as you determine, any other value used will default to -1.
- `COMMENT_IP_LIST`
  - `FEED_URL` - Value: Any in the list of `COMMENT_IP_LIST` in [Feed Types](#feed-types) above
  - `FEED_FORMAT` - Value: `COMMENT_IP_LIST`
  - `FEED_BASE_REPUTATION` - (`Optional`) Value: Any value between -3 and 0 as you determine, any other value used will default to -1.
- `REPUTATION_ALIEN_VAULT`
  - `FEED_URL` - Value: https://reputation.alienvault.com/reputation.generic
  - `FEED_FORMAT` - Value: `REPUTATION_ALIEN_VAULT`
  - `FEED_BASE_REPUTATION` - (`Optional`) Value: Any value between -3 and 0 as you determine, any other value used will default to -1.
- `FEODOTRACKER_IP_BLOCKLIST`
  - `FEED_URL` - Value: https://feodotracker.abuse.ch/downloads/ipblocklist.csv
  - `FEED_FORMAT` - Value: `FEODOTRACKER_IP_BLOCKLIST`
  - `FEED_BASE_REPUTATION` - (`Optional`) Value: Any value between -3 and 0 as you determine, any other value used will default to -1.
- `CYBERCURE_AI_IP`
  - `FEED_URL` - Value: https://api.cybercure.ai/feed/get_ips?type=csv
  - `FEED_FORMAT` - Value: `CYBERCURE_AI_IP`
  - `FEED_BASE_REPUTATION` - (`Optional`) Value: Any value between -3 and 0 as you determine, any other value used will default to -1.
- `MALSILO_IP_LIST`
  - `FEED_URL` - Value: https://malsilo.gitlab.io/feeds/dumps/ip_list.txt
  - `FEED_FORMAT` - Value: `MALSILO_IP_LIST`
  - `FEED_BASE_REPUTATION` - (`Optional`) Value: Any value between -3 and 0 as you determine, any other value used will default to -1.
- `GENERIC_URL_LIST`
  - `FEED_URL` - Value: Any in the list of `GENERIC_URL_LIST` in [Feed Types](#feed-types) above
  - `FEED_FORMAT` - Value: `GENERIC_URL_LIST`
  - `FEED_BASE_REPUTATION` - (`Optional`) Value: Any value between -3 and 0 as you determine, any other value used will default to -1.
- `PHISHTANK_ONLINE_URL_LIST`
  - `FEED_URL` - Value: https://data.phishtank.com/data/online-valid.csv
  - `FEED_FORMAT` - Value: `PHISHTANK_ONLINE_URL_LIST`
  - `FEED_BASE_REPUTATION` - (`Optional`) Value: Any value between -3 and 0 as you determine, any other value used will default to -1.
- `DIAMOND_FOX_URL_LIST`
  - `FEED_URL` - Value: https://raw.githubusercontent.com/pan-unit42/iocs/master/diamondfox/diamondfox_panels.txt
  - `FEED_FORMAT` - Value: `DIAMOND_FOX_URL_LIST`
  - `FEED_BASE_REPUTATION` - (`Optional`) Value: Any value between -3 and 0 as you determine, any other value used will default to -1.
- `VXVAULT_URL_LIST`
  - `FEED_URL` - Value: http://vxvault.net/URL_List.php
  - `FEED_FORMAT` - Value: `VXVAULT_URL_LIST`
  - `FEED_BASE_REPUTATION` - (`Optional`) Value: Any value between -3 and 0 as you determine, any other value used will default to -1.
- `CYBERCURE_AI_URL_LIST`
  - `FEED_URL` - Value: https://api.cybercure.ai/feed/get_url?type=csv
  - `FEED_FORMAT` - Value: `CYBERCURE_AI_URL_LIST`
  - `FEED_BASE_REPUTATION` - (`Optional`) Value: Any value between -3 and 0 as you determine, any other value used will default to -1.
- `MALSILO_URL_LIST`
  - `FEED_URL` - Value: https://malsilo.gitlab.io/feeds/dumps/url_list.txt
  - `FEED_FORMAT` - Value: `MALSILO_URL_LIST`
  - `FEED_BASE_REPUTATION` - (`Optional`) Value: Any value between -3 and 0 as you determine, any other value used will default to -1.
- `BENKOW_CC_URL_LIST`
  - `FEED_URL` - Value: https://benkow.cc/export.php
  - `FEED_FORMAT` - Value: `BENKOW_CC_URL_LIST`
  - `FEED_BASE_REPUTATION` - (`Optional`) Value: Any value between -3 and 0 as you determine, any other value used will default to -1.
- `ZIP_HAUS_ABUSE_URL_LIST`
  - `FEED_URL` - Value: https://urlhaus.abuse.ch/downloads/csv/
  - `FEED_FORMAT` - Value: `ZIP_HAUS_ABUSE_URL_LIST`
  - `FEED_BASE_REPUTATION` - (`Optional`) Value: Any value between -3 and 0 as you determine, any other value used will default to -1.
- `GENERIC_CVE_LIST`
  - `FEED_URL` - Value: Any in the list of `GENERIC_CVE_LIST` in [Feed Types](#feed-types) above
  - `FEED_FORMAT` - Value: `GENERIC_CVE_LIST`
  - `FEED_BASE_REPUTATION` - (`Optional`) Value: Any value between -3 and 0 as you determine, any other value used will default to -1.
- `MALSILO_DOMAIN_LIST`
  - `FEED_URL` - Value: https://malsilo.gitlab.io/feeds/dumps/domain_list.txt
  - `FEED_FORMAT` - Value: `MALSILO_DOMAIN_LIST`
  - `FEED_BASE_REPUTATION` - (`Optional`) Value: Any value between -3 and 0 as you determine, any other value used will default to -1.
- `ZIP_WITH_GENERIC_MD5_LIST`
  - `FEED_URL` - Value: Any in the list of `ZIP_WITH_GENERIC_MD5_LIST` in [Feed Types](#feed-types) above
  - `FEED_FORMAT` - Value: `ZIP_WITH_GENERIC_MD5_LIST`
  - `FEED_BASE_REPUTATION` - (`Optional`) Value: Any value between -3 and 0 as you determine, any other value used will default to -1.
- `MALSHARE_CURRENT_DAILY_SHA256_LIST`
  - `FEED_URL` - Value: https://malshare.com/daily/malshare.current.all.txt
  - `FEED_FORMAT` - Value: `MALSHARE_CURRENT_DAILY_SHA256_LIST`
  - `FEED_BASE_REPUTATION` - (`Optional`) Value: Any value between -3 and 0 as you determine, any other value used will default to -1.

## Building for production

### Packaging as jar

To package the API as a jar in order to deploy it to an application server, run:

```
mvn -Pprod clean compile assembly:single
```

To ensure everything worked, run:

```
java -jar target/utmtw-transformation-api-${VERSION}-jar-with-dependencies.jar
```

## Using Docker

To run the application on docker you must build it based on the Dockerfile located at the root of the application files,
then run `docker build` command Ex: `docker build -t thi/etl:1.0 -f Dockerfile .`, then
you can run the image using `docker run` command and passing all the variables according to the `Feed Type`
Ex: `docker run -m 1024mb --name thietl -it -e FEED_URL=https://www.circl.lu/doc/misp/feed-osint/ -e FEED_FORMAT=OSINT_CIRCL -e LINK_PATTERN=(.+)-(.+)-(.+)-(.+)-(.+)\.json -e TW_API_URL=https://api.sandbox.threatwinds.com -e TW_API_KEY=ToLargeToPutItHere -e TW_API_SECRET=ToLargeToPutItHere -e TW_API_ENTITY_BASE_TYPE=threat -e THREAD_POOL_SIZE=8 -d fe73d77ebbf5`
