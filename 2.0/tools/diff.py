#!/usr/bin/python
#
# (c) Copyright 2015 Hewlett Packard Enterprise Development LP
# (c) Copyright 2017 SUSE LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#

import filecmp
import fnmatch
import os
from pprint import pprint
import sys
from tabulate import tabulate


def find_dirs(dir):
    for name in os.listdir(dir):
        if os.path.isdir(os.path.join(dir, name)):
            yield (name)


def find_files(dir):
    for name in os.listdir(dir):
        if not os.path.isdir(os.path.join(dir, name)):
            yield (name)


#######
# Main
#######

models = []
directories = {}

# Cloud
if len (sys.argv) > 1:
    for model in sys.argv[1:]:
        models.append(model)
        for subdir in find_dirs(model):
            if subdir not in directories:
                directories[subdir] = {'files': {}}

            for file in find_files(os.path.join(model, subdir)):
                cmp_path = os.path.join(model, subdir, file)

                found_match = False
                for ref_filename, matches in directories[subdir]['files'].iteritems():
                    if file == ref_filename:
                        for match in matches:
                           ref_path = os.path.join(match[0], subdir,file)
                           if filecmp.cmp(ref_path, cmp_path, False):
                               found_match = True
                               match.append(model)
                               break

                if not found_match:
                    if not file in directories[subdir]['files']:
                        directories[subdir]['files'][file] = []
                    directories[subdir]['files'][file].append([model])

# Work out the spacers
dirmax=0
filemax=0
modmax=0
for name in directories:
    if len(name) > dirmax:
        dirmax = len(name)
    
    for file in directories[name]['files']:
        if len(file) > filemax:
            filemax = len(file)

modspace=[]
modsep=[]
for mod in models:
    modspace.append("-" * len(mod))

dirspace = "-" * dirmax
filespace = "-" * filemax

rows=[]
dirfirst=True

for dirname in sorted(directories):
    dir = directories[dirname]
    x_dirname = dirname
    
    filefirst=True
    for file in sorted(dir['files']):
        if x_dirname and not dirfirst:
            row = [dirspace, filespace]
            row.extend (modspace)
            rows.append(row)
        dirfirst = False

        x_file = file

        set_index = 1
        for match_set in dir['files'][file]:

            row = [x_dirname, x_file]
            x_dirname = ""
            x_file = ""
 
            for model in models: 
                if model in match_set:
                    if len(dir['files'][file]) > 1:
                        row.append(str(set_index)*len(model))
                    else:
                        row.append("X"*len(model))
                else:
                    row.append("   ")
                
            rows.append(row)
            set_index += 1



header =  ["Directory", "File"] + models
print tabulate(rows, header, tablefmt="psql")


