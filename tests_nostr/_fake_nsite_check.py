#!/usr/bin/env python3
import sys
content = open(sys.argv[sys.argv.index('-config') + 1]).read()
sys.exit(1 if 'bogus' in content else 0)
