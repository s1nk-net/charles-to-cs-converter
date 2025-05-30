# charles-to-cs-converter
This program will convert HTTP comms into valid http blocks for Cobalt Strike. Input can be raw HTTP requests or .har files

# Usage
usage: charles_to_cs_converter.py [-h] [-o OUTPUT] [-n NAME] [-f {har,raw}]
                                  [--block {http-get,http-post,http-stager,http-config,full}]
                                  input

Convert Charles Proxy captures to Cobalt Strike profiles

positional arguments:
  input                 Input file (HAR or raw HTTP)

options:
  -h, --help            show this help message and exit
  -o, --output OUTPUT   Output file (default: stdout)
  -n, --name NAME       Profile name
  -f, --format {har,raw}
                        Input format (auto-detect if not specified)
  --block {http-get,http-post,http-stager,http-config,full}
                        Generate specific block only
