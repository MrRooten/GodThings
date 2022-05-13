import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import process
import file
f = file.FileInfo("D:\\SourceCodes\\qwer.py")
print(f.get_basic_info())