"""
Compile SMIv1/v2 MIBs
+++++++++++++++++++++
"""

from pysmi.reader import FileReader
from pysmi.searcher import PyFileSearcher, PyPackageSearcher, StubSearcher
from pysmi.writer import PyFileWriter
from pysmi.parser import SmiStarParser
from pysmi.codegen import PySnmpCodeGen
from pysmi.compiler import MibCompiler

inputMibs = ['MIKROTIK-MIB']
srcDirectories = ['.mikrotik-mibs']
dstDirectory = '.pysnmp-mibs'

# Initialize compiler infrastructure

mibCompiler = MibCompiler(SmiStarParser(),
                          PySnmpCodeGen(),
                          PyFileWriter(dstDirectory))

# search for source MIBs here
mibCompiler.addSources(*[FileReader(x) for x in srcDirectories])

# check compiled MIBs in our own productions
mibCompiler.addSearchers(PyFileSearcher(dstDirectory))
# ...and at default PySNMP MIBs packages
mibCompiler.addSearchers(*[PyPackageSearcher(x) for x in PySnmpCodeGen.defaultMibPackages])

# never recompile MIBs with MACROs
mibCompiler.addSearchers(StubSearcher(*PySnmpCodeGen.baseMibs))

# run [possibly recursive] MIB compilation
results = mibCompiler.compile(*inputMibs)  # , rebuild=True, genTexts=True)

print('Results: %s' % ', '.join(['%s:%s' % (x, results[x]) for x in results]))
