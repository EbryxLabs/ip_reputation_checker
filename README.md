# IP Reputation Checker Tool


### Description:
* **What it is**: A quick and dirty script to gather IP OSINT and reputation statistics.
* **How we do it**: 
  * OSINt details for location (country & continent) are extracted via Maxmind Geo IP Lite database.
  * Reputation details are gathered via public API of Virus Total.


### Folder Hierarchy
* **config**: Folder containing a config file. It contains secrets related stuff like API keys etc. See sample_config.json for more details.
* **.input**: Folder containing files that contain one IP per line.
* **.output**: Folder containing files that will be generated as an output to tool execution.
   

### Planned Expansions
* **OTX TI Integration**
* **Expansion to Domains**
* **Expansion to Hashes**
* **More output formats with detailed output**