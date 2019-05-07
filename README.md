<p align="center"><a href="https://twitter.com/th3_protoCOL" target="_blank"><img src="https://img.shields.io/badge/Twitter%3A-%40th3__protoCOL-blue.svg" alt="Twitter" /></a></p>

# viper-plugins
These are my plugins for [the Viper Framework](https://github.com/viper-framework/viper), still in development!

### Plugins
* Similarity Analysis
* Tracking Template
* Timestamp Heat Map


## Similarity Analysis w/ [Neo4j](https://neo4j.com/)
Performs Similarity analysis to cluster and visualize collections of malware. Currently supports comparing by strings, windows pe imports and exif data.
```
usage: similarity [-h] [-t THRESHOLD] [-o OUTFILE] [-p] [-s] [-i] [-m MIN]
                  [-e] [-c]

Analyze all samples for code similarity

optional arguments:
  -h, --help            show this help message and exit
  -t THRESHOLD, --threshold THRESHOLD
                        Jaccard index threshold (default is 0.7)
  -o OUTFILE, --output OUTFILE
                        Output file name for the graph image.
  -p, --pdb             Add path debug information label on nodes
  -s, --strings         Compare samples using strings
  -i, --imports         Compare samples using imports
  -m MIN, --min MIN     Set minimum string length for search
  -e, --exif            Compare samples using ExifData
  -c, --cli             Command line only, no graphs
```
### Requirements
* The Viper Framework 
* pefile
* exiftool
* Neo4j
* [py2neo](https://py2neo.org/v4/)
* neomodel

#### Add to viper.conf
Update to match your environment

```
[similarity]
url = http://localhost:7474/db/data
user = neo4j
pwd = 
```

### Examples
<img src="https://github.com/colincowie/viper-plugins/raw/master/screenshots/one.png" alt="Ryuk Strings Similarity" width="400"/> <img src="https://github.com/colincowie/viper-plugins/raw/master/screenshots/two.png" alt="Ryuk Imports Similarity" width="400"/>

### Development
* Add web ui support
* Add linux and mac based malware support

## Tracking Template
This is a template that can be used to create custom modules for tracking malware.
```
viper > template -h
usage: template [-h] [-a] [-s SEARCH_STRING]

Template module for tracking malware

optional arguments:
  -h, --help            show this help message and exit
  -a, --all             Run the module on all samples
  -s SEARCH_STRING, --search SEARCH_STRING
                        Search for a specifc string

viper > template -a -s InternetOpen
+------------------+------------------------------------------------------------------------------+
| Key              | Value                                                                        |
+------------------+------------------------------------------------------------------------------+
| Name             | 46fb27f4cff2d33baae3b1c199797d1f0929bc03166cebd092081e4fe2f9ea6e             |
+------------------+------------------------------------------------------------------------------+
| MD5              | bc041eb3eeb75312288557c23e919caa                                             |
+------------------+------------------------------------------------------------------------------+
| Timestamp        | 2018:10:13                                                                   |
+------------------+------------------------------------------------------------------------------+
| CodeSize         | 87040                                                                        |
+------------------+------------------------------------------------------------------------------+
| PDB Path         | C:\Users\Admin\Documents\Visual Studio 2015\Projects\ConsoleApplication54new |
|                  | crypted\x64\Release\ConsoleApplication54.pdb                                 |
+------------------+------------------------------------------------------------------------------+
| Search Results:  | ['\x0c\x0bInternetOpenUrlA']                                                 |
+------------------+------------------------------------------------------------------------------+

+------------------+------------------------------------------------------------------------------+
| Key              | Value                                                                        |
+------------------+------------------------------------------------------------------------------+
| Name             | 1b465c0e12523747f892b48fa92a30f82e5027199a2aff06587c5269bd99f69a             |
+------------------+------------------------------------------------------------------------------+
| MD5              | cce28fefb5e16f4a9d0cc01fd5ad817c                                             |
+------------------+------------------------------------------------------------------------------+
| Timestamp        | 2018:10:09                                                                   |
+------------------+------------------------------------------------------------------------------+
| CodeSize         | 86528                                                                        |
+------------------+------------------------------------------------------------------------------+
| PDB Path         | C:\Users\Admin\Documents\Visual Studio 2015\Projects\ConsoleApplication54new |
|                  | crypted\x64\Release\ConsoleApplication54.pdb                                 |
+------------------+------------------------------------------------------------------------------+
| Search Results:  | ['\x0c\x0bInternetOpenUrlA']                                                 |
+------------------+------------------------------------------------------------------------------+

```

## Timestamp Heat Map
_Coming soon..._
