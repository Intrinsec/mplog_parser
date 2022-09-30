# Mplog-Parser

Mplog-Parser parses Microsoft Protection log files to provide CSV files containing useful information to forensic investigators.

## Build

Run the following command line with admin privileges :

```text
pip install -U .
```

## Usage

```text
usage: mplog_parser [-h] [-d DIRECTORY] [-o OUTPUT]

optional arguments:
  -h, --help            show this help message and exit
  -d DIRECTORY, --directory DIRECTORY
                        Location of directory containing log files. NB: Admin rights are needed to access Windows Defender folder (default: C:\ProgramData\Microsoft\Windows Defender\Support\).  When specifying a custom directory, file names must be written following *MPLog-* pattern.
  -o OUTPUT, --output OUTPUT
                        Location of output folder. (default: None)
```
