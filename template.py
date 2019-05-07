# Colin Cowie - @th3_protoCOL
# Template module for malware analysis
import os
import re
import string
import pefile
import exiftool

from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.config import __config__
from viper.core.database import Database
from viper.core.storage import get_sample_path
from viper.common.objects import File

class Template(Module):
    cmd = 'template'
    description = 'Template module for tracking malware'
    authors = ['th3_protoCOL']

    def __init__(self):
        super(Template, self).__init__()
        self.parser.add_argument('-a', '--all', action='store_true', help='Run the module on all samples')
        self.parser.add_argument('-s', '--search', dest='search_string', help='Search for a specifc string')

    def get_strings(self, f):
        # String implementation see http://stackoverflow.com/a/17197027/6880819 - Extended with Unicode support. todo: explore other string detections
        results = []
        result = ""
        counter = 1
        wide_word = False
        min = 3
        for c in f.data.decode('utf-8', 'ignore'):
            # Already have something, check if the second byte is a null
            if counter == 2 and c == "\x00":
                wide_word = True
                counter += 1
                continue
            # Every 2 chars we allow a 00
            if wide_word and c == "\x00" and not counter % 2:
                counter += 1
                continue
            # Valid char, go to next - newlines are to be considered as the end of the string
            if c in string.printable and c not in ['\n', '\r']:
                result += c
                counter += 1
                continue
            if len(result) >= min:
                results.append(result)
            # Reset the variables
            result = ''
            counter = 1
            wide_word = False
        if len(result) >= min:  # Catch result at EOF
            results.append(result)
        return results

    def parse_search(self, strings, search):
        results = []
        for entry in strings:
            to_add = False
            if re.search(search, entry):
                results.append(entry)

        return results

    def parse_pdb(self, strings):
        PDB_REGEX = re.compile(r'\.pdb$', re.IGNORECASE)
        result = None
        for entry in strings:
            if PDB_REGEX.search(entry):
                result = entry;
        return result;

    # Main analysis function
    def scan(self, file):
        sample = File(file)
        strings = self.get_strings(sample)

        # Get exif data
        metadata = []
        with exiftool.ExifTool() as et:
            metadata = et.get_metadata(file)
        if 'EXE:TimeStamp' in metadata:
            timestamp = metadata['EXE:TimeStamp'][:10]

        header = ['Key', 'Value']
        # Modify these!
        rows = [
            ['Name', sample.name],
            ['MD5', sample.md5],
            ['Timestamp',timestamp],
            ['CodeSize', metadata['EXE:CodeSize']],
            ['PDB Path', self.parse_pdb(strings)]
        ]

        # Search for specfic string
        if self.args.search_string:
            search_result = self.parse_search(strings, self.args.search_string)
            if search_result:
                rows.append(['Search Results: ', search_result])
                self.log('table', dict(header=header, rows=rows))
                print('')
        else:
            self.log('table', dict(header=header, rows=rows))

    def run(self):
        super(Template, self).run()

        # Check arguments and scan accordingly
        if not __sessions__.is_set() and not self.args.all:
            self.log('error', 'No open session. Run with \'-a\' to scan all files.')
        elif self.args.all:
            db = Database()
            samples = db.find(key='all')
            for sample in samples:
                self.scan(get_sample_path(sample.sha256))
        else:
            self.scan(__sessions__.current.file.path)
