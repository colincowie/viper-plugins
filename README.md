<p align="center"><img src="https://img.shields.io/badge/Twitter%3A-%40th3__protoCOL-blue.svg" alt="Twitter" /></p>

# viper-plugins
These are my plugins for [the Viper Framework](https://github.com/viper-framework/viper), still in development!

### Plugins
* Similarity Analysis
* Timestamp Heat Map

## Similarity Analysis
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
* networkx 
* exiftool
* fdp (to do: remove this) 

### Examples
<img src="https://github.com/colincowie/viper-plugins/raw/master/screenshots/30_strings_73_exif.png" alt="Ryuk Strings Similarity" width="400"/> <img src="https://github.com/colincowie/viper-plugins/raw/master/screenshots/100_imports_99.png" alt="Ryuk Imports Similarity" width="400"/>

### Development
* Fix graph export / .dot to .png conversion
* Add web ui support
* Add linux and mac based malware support
* Improve labeling options 

## Timestamp Heat Map
_Coming soon..._
