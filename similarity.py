# Colin Cowie - @th3_protoCOL
# Similarity analysis plugin for viper
import os
import re
import string
import pefile
import exiftool
import itertools

from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.config import __config__
from viper.core.database import Database
from viper.core.storage import get_sample_path
from viper.common.objects import File

from py2neo import Graph, Node, Relationship
from neomodel import StructuredNode, StringProperty, DateProperty

cfg = __config__

# Define Neo4j Node
class SampleNode(StructuredNode):
    name = StringProperty(unique_index=True)
    timestamp = DateProperty()
    pdb = StringProperty()

class Similarity(Module):
    cmd = 'similarity'
    description = 'Analyze all samples for code similarity'
    authors = ['th3_protoCOL']

    def __init__(self):
        super(Similarity, self).__init__()
        self.parser.add_argument('-t', '--threshold', dest='threshold', type=float, default=0.75, help='Jaccard index threshold (default is 0.7)')
        self.parser.add_argument('-p', '--pdb', action='store_true', help='Add path debug information label on nodes')
        self.parser.add_argument('-s', '--strings', action='store_true', help='Compare samples using strings')
        self.parser.add_argument('-i', '--imports', action='store_true', help='Compare samples using imports')
        self.parser.add_argument('-m', '--min', dest='min', type=int, default=4, help='Set minimum string length for search')
        self.parser.add_argument('-e', '--exif', action='store_true', help='Compare samples using ExifData')

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

        # Neo4j Setup
        ## Get Url from Config
        neo4j_url = cfg.similarity.url
        ## Get Username from Config
        neo4j_user = cfg.similarity.user
        ## Get Password from Config
        neo4j_pwd = cfg.similarity.pwd
        ## Connect to neo4j data and define a graph
        graph = Graph(neo4j_url, user=neo4j_user, password=neo4j_pwd)
        try:
            graph.delete_all()
        except:
            print("Are the credintials correct in the config file?")
            return

        sample_nodes = []

        for sample in samples:
            malware_path = get_sample_path(sample.sha256)
            features = []

            timestamp = ""
            # Check arguments to determine what should be compared
            if self.args.exif:
                if not self.args.strings and not self.args.imports: # Can I find a better way to do this?
                    features += self.get_exif(malware_path)
                metadata = []
                with exiftool.ExifTool() as et:
                    metadata = et.get_metadata(malware_path)
                if 'EXE:TimeStamp' in metadata:
                    timestamp = metadata['EXE:TimeStamp'][:10]
            if self.args.strings:
                features += self.get_strings(File(malware_path))
            if self.args.imports:
                imports = self.get_apis(malware_path)
                if imports is not None:
                    features += imports
                else:
                    self.log('warning', 'No imports found for {0}...'.format(sample.md5))

            # Adds path debug information to nodes
            pdb_label = ""
            if self.args.pdb:
                pdb = self.parse_pdb(self.get_strings(File(malware_path)))
                if pdb is not None:
                    self.log('success', 'Found pdb path {0}'.format(pdb))
                    try:
                        project_start = pdb.index('\\Projects')
                        project_end = pdb.index('\\x64\\')
                        # if project_start or project_end is not set then this will fail, so moved here.
                        pdb_label = pdb[int(project_start)+9:int(project_end)]
                    except:
                        self.log('error','Unexpected pdb path')

            # Set default comparison
            if (not self.args.strings and not self.args.imports and not self.args.exif):
                features += self.get_strings(File(malware_path))

            if len(features) == 0:
                self.log('error', 'Extracted {0} features from {1}...'.format(len(features), sample.md5))
                continue

            self.log('success', 'Extracted {0} features from {1}...'.format(len(features), sample.md5))

            malware_features[malware_path] = features

            tx = graph.begin()

            #Create new nodes
            sample_node = Node("SampleNode", name=str(sample.sha256), timestamp=timestamp, pdb=pdb_label)
            labels = [sample.sha256, timestamp]
            sample_node.cast(labels)
            tx.create(sample_node)
            tx.commit()
            sample_nodes.append(sample_node)

        # Determine the jaccard index beteween malware and graph realtionships
        self.log('info', 'Starting graphing process')
        for malware1, malware2 in itertools.combinations(sample_nodes, 2):
            # Compute the jaccard index for the current malware pair
            jaccard_index = self.jaccard(malware_features[get_sample_path(malware1["name"])], malware_features[get_sample_path(malware2["name"])])
            # If the jaccard distance is above the threshold draw a connection between nodes
            if jaccard_index > threshold:
                if jaccard_index > 0.95:
                    r = Relationship(malware1,"very_high", malware2)
                elif jaccard_index > 0.88:
                    r = Relationship(malware1,"high", malware2)
                elif jaccard_index > 0.83:
                    r = Relationship(malware1,"moderate", malware2)
                elif jaccard_index > 0.78:
                    r = Relationship(malware1,"low", malware2)
                elif jaccard_index > 0.60:
                    r = Relationship(malware1,"very_low", malware2)

                tx = graph.begin()
                tx.create(r)
                tx.commit()

        self.log('success', 'Finished graphing nodes and realtionships')
