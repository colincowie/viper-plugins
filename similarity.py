# Colin Cowie - @th3_protoCOL
# Similarity analysis plugin for viper
import os
import re
import string
import pefile
import exiftool
import networkx
import itertools

from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.config import __config__
from viper.core.database import Database
from viper.core.storage import get_sample_path
from viper.common.objects import File
from networkx.drawing.nx_pydot import write_dot

class Similarity(Module):
    cmd = 'similarity'
    description = 'Analyze all samples for code similarity'
    authors = ['th3_protoCOL']

    def __init__(self):
        super(Similarity, self).__init__()
        self.parser.add_argument('-t', '--threshold', dest='threshold', type=float, default=0.75, help='Jaccard index threshold (default is 0.7)')
        self.parser.add_argument('-o', '--output', dest='outfile', default='similarity.dot', help='Output file name for the graph image.') #todo: fix /implement this
        self.parser.add_argument('-p', '--pdb', action='store_true', help='Add path debug information label on nodes')
        self.parser.add_argument('-s', '--strings', action='store_true', help='Compare samples using strings')
        self.parser.add_argument('-i', '--imports', action='store_true', help='Compare samples using imports')
        self.parser.add_argument('-m', '--min', dest='min', type=int, default=4, help='Set minimum string length for search')
        self.parser.add_argument('-e', '--exif', action='store_true', help='Compare samples using ExifData')
        self.parser.add_argument('-c', '--cli', action='store_true', help='Command line only, no graphs')

    def jaccard(self, set1, set2):
        set1_set = set(set1)
        set2_set = set(set2)
        intersection = set1_set.intersection(set2_set)
        intersection_length = float(len(intersection))
        union = set1_set.union(set2_set)
        union_length = float(len(union))
        return intersection_length / union_length

    def get_strings(self, f):
        # String implementation see http://stackoverflow.com/a/17197027/6880819 - Extended with Unicode support. todo: explore other string detections
        results = []
        result = ""
        counter = 1
        wide_word = False
        min = self.args.min
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

    def get_apis(self, path):
        try:
            pe = pefile.PE(path)
        except pefile.PEFormatError:
            return None

        results = []

        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return results

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                results.append(imp.name.decode('utf-8'))
        return results

    def get_exif(self, f):
        with exiftool.ExifTool() as et:
            metadata = et.get_metadata(f)
            return metadata

    def parse_pdb(self, strings):
        PDB_REGEX = re.compile(r'\.pdb$', re.IGNORECASE)
        result = None
        for entry in strings:
            if PDB_REGEX.search(entry):
                result = entry;
        return result;

    # todo: improve and implement this
    def parse_dll(self, strings):
        DLL_REGEX = re.compile(r'^[a-zA-Z0-9]{8,}.dll$', re.IGNORECASE)
        result = None
        for entry in strings:
            if DLL_REGEX.search(entry):
                if "32" not in entry:
                    result = entry;
        return result;

    def run(self):
        super(Similarity, self).run()

        if self.args is None:
            return
        elif self.args.imports and self.args.threshold == 0.75: #todo: find a better way to check if thresholds haven't been set
            self.log('warning', 'Adjusting default threashold to 0.97 to scale for imports')
            threshold = 0.97
        elif self.args.threshold:
            threshold = self.args.threshold
            self.log('info', 'Setting Jaccard index threshold to '+ str(threshold))

        # Get all samples from viper database
        db = Database()
        samples = db.find(key='all')
        malware_features = dict()
        malware_paths = []
        graph = networkx.Graph()

        for sample in samples:
            malware_path = get_sample_path(sample.sha256)
            features = []
            node_label = (os.path.split(sample.sha256)[-1][:10])

            # Check arguments to determine what should be compared
            if self.args.exif:
                if not self.args.strings and not self.args.imports: # Can I find a better way to do this?
                    features += self.get_exif(malware_path)
                metadata = []
                with exiftool.ExifTool() as et:
                    metadata = et.get_metadata(malware_path)
                if 'EXE:TimeStamp' in metadata:
                    node_label = node_label + "\n" + (metadata['EXE:TimeStamp'][:10])
            if self.args.strings:
                features += self.get_strings(File(malware_path))
            if self.args.imports:
                imports = self.get_apis(malware_path)
                if imports is not None:
                    features += imports
                else:
                    self.log('warning', 'No imports found for {0}...'.format(sample.md5))

            # Adds path debug information to nodes
            if self.args.pdb:
                pdb = self.parse_pdb(self.get_strings(File(malware_path)))
                if pdb is not None:
                    self.log('success', 'Found pdb path {0}'.format(pdb))
                    try:
                        project_start = pdb.index('\\Projects')
                        project_end = pdb.index('\\x64\\')
                    except:
                        self.log('error','Unexpected pdb path')
                    pdb_label = pdb[int(project_start)+9:int(project_end)] # todo: find a cleaner way to do this
                    node_label = node_label + "\n" + pdb_label

            # Set default comparison
            if (not self.args.strings and not self.args.imports and not self.args.exif):
                features += self.get_strings(File(malware_path))

            if len(features) == 0:
                self.log('error', 'Extracted {0} features from {1}...'.format(len(features), sample.md5))
                continue

            self.log('success', 'Extracted {0} features from {1}...'.format(len(features), sample.md5))

            malware_paths.append(malware_path)
            malware_features[malware_path] = features

            graph.add_node(malware_path, color='black', label=node_label)

        # Determine the jaccard index beteween malware
        for malware1, malware2 in itertools.combinations(malware_paths, 2):
            # Compute the jaccard index for the current malware pair
            jaccard_index = self.jaccard(malware_features[malware1], malware_features[malware2])
            # If the jaccard distance is above the threshold draw a connection between nodes
            if jaccard_index > threshold:
                if jaccard_index > 0.965:
                    graph_color = '#06121B'
                elif jaccard_index > 0.93:
                    graph_color = '#0D2435'
                elif jaccard_index > 0.895:
                    graph_color = '#133650'
                elif jaccard_index > 0.825:
                    graph_color = '#19496A'
                elif jaccard_index > 0.79:
                    graph_color = '#1F5B85'
                elif jaccard_index > 0.755:
                    graph_color = '#266D9F'
                elif jaccard_index > 0.72:
                    graph_color = '#2C7FBA'
                else:
                    graph_color = '#3291D4'

                graph.add_edge(malware1, malware2, color=graph_color, alpha=0.2, shape='circle', penwidth=(jaccard_index)*4)

        # Save information to graph. todo: find a good way to do this cleanly
        output = "similarity.dot"
        if self.args.outfile:
            output = self.args.outfile
            if ".dot" not in output:
                output = output + ".dot"

        if not self.args.cli:
            write_dot(graph, output)
            self.log('info', 'Attempting to convert graph to image')
            os.system('fdp -Tpng '+output+' -o '+output[:-4]+'.png')
            self.log('success', 'Saved graph data to '+output[:-4]+'.png')
