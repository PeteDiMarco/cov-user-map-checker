#!/usr/bin/python
#***************************************************************************
#* Copyright 2017 Pete DiMarco
#* 
#* Licensed under the Apache License, Version 2.0 (the "License");
#* you may not use this file except in compliance with the License.
#* You may obtain a copy of the License at
#* 
#*     http://www.apache.org/licenses/LICENSE-2.0
#* 
#* Unless required by applicable law or agreed to in writing, software
#* distributed under the License is distributed on an "AS IS" BASIS,
#* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#* See the License for the specific language governing permissions and
#* limitations under the License.
#***************************************************************************
#
# Name: cov-user-map-check.py
# Version: 0.2
# Date: 2017-05-26
# Written by: Pete DiMarco <pete.dimarco.software@gmail.com>
#
# Description:
# This program will test a rules file used for SCM-to-Coverity-Connect User
# Mapping.  The rules are encoded in JSON and contain Java regular
# expressions.  The program can query Git for a list of user email addresses,
# or read the list from a file.
#
# Limitations:
#  - Assumes Python 2.7 or possibly lower.
#  - Does not support "cimEmail" OR "ldapServer" fields.
#  - Assumes Python 2.7 regexes are the same as Java's.
#  - Only supports Git SCM.
#  - User file assumes 1 user email address per line.
#  - Assumes Posix-compatible shell that supports the "sort" and "uniq"
#    commands.
#
# See also your Coverity installation's online help:
# /doc/en/cov_platform_use_and_admin_guide.html#scm_to_cov_users_mapping

import os
import os.path
import sys
import re
import subprocess
import json
import argparse

Epilog = ""     # Used by argparse.


# \fn run_cmd
# \public
# \brief Runs the command in a shell. Returns an empty string if an exception
#        is raised.
# \param [in] cmd_str          string
# \param [in] ignore_exit_1    boolean
# \return string
def run_cmd(cmd_str, ignore_exit_1 = False):
    result = ""
    try:
        # If we have a reasonable version of Python:
        if sys.version_info >= (2,7):
            result = subprocess.check_output(cmd_str, shell=True)
        else:	# Else this machine needs an upgrade:
            fp = os.popen(cmd_str, "r")
            result = fp.read()
            fp.close()
    except Exception as e:
        # grep will return errno == 1 if it doesn't match any lines
        # in its input stream.  We want to ignore this case since it's
        # not really an error.
        if (type(e) != subprocess.CalledProcessError or e.returncode != 1 or
            not ignore_exit_1):
            print("\tThis command:")
            print(cmd_str)
            print("\tGenerated this exception:")
            print(e, str(e))
    return result


# \fn read_file
# \public
# \brief Reads the contents of a file into 1 large string.
# \param [in] file_name          string
# \return string
def read_file(file_name):
    result = ""
    if os.path.exists(file_name) and os.path.isfile(file_name):
        try:
            fp = open(file_name, "r")
            result = fp.read()
            fp.close()
        except:
            print("ERROR: Problem reading %s." % file_name)
            exit(0)
    else:
        print("ERROR: %s does not exist." % file_name)
        exit(0)
    return result



# \class UserMapper
# \public
# \brief Processes the rules read in from a JSON file.
# WARNING: DOES NOT SUPPORT "cimEmail" OR "ldapServer".
class UserMapper():
    def __init__(self, raw_text):
        self.input_pattern = []
        self.output_pattern = []
        try:
            json_data = json.loads(raw_text)
            for rule in json_data["map"]:
                self.input_pattern.append(re.compile(rule["scmUsername"]))
                self.output_pattern.append(rule["cimUsername"])
        except Exception as e:
            print("UserMapper: Exception raised:", e, str(e))


    # \fn map_user
    # \public
    # \brief Evaluates each rule for scm_name.  Returns a list of the results. 
    # \param [in] scm_name       string
    # \return list of strings
    def map_user(self, scm_name):
        result = []
        try:
            for index in range(len(self.input_pattern)):	# For each rule:
                match = self.input_pattern[index].search(scm_name)
                if match:
                    output = self.output_pattern[index]		# Build output of rule.
                    submatches = match.groups()
                    assert len(submatches) < 10			# Check $1 ... $9.
                    for i in range(len(submatches)):
                        # This could recursively explode if a submatch
                        # contains \$<NUMBER>.
                        output = re.sub("\\$%d" % (i+1), submatches[i], output) 
                    result.append(output)		# Add to list of rule matches.
        except Exception as e:
            print("map_user: Exception raised:", e, str(e))
        return result


# Parse command line arguments:
parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description="Verify SCM-to-Coverity user mapping rules.",
                                 epilog=Epilog)
parser.add_argument('file', type=str, help='JSON rules file to verify')
parser.add_argument('-g', '--git-dir', dest='git_dir',
                    help='Directory containing Git repo.')
parser.add_argument('-u', '--users', dest='user_file',
                    help='File containing a list of SCM users.')
parser.add_argument('-D', '--DEBUG', action='store_true', default=False,
                    help='Enable debugging mode.')
args = parser.parse_args()

# We need either a Git repo directory or a file containing user names,
# but not both:
if (bool(args.git_dir == None or args.git_dir == "") ==
    bool(args.user_file == None or args.user_file == "")):
    print("ERROR: -g and -u are mutually exclusive.")
    parser.print_help()
    exit(0)

users = []      # Our list of users for testing.

# Read in our JSON rules:
rules = UserMapper(read_file(args.file))

# If we're searching for users from Git:
if args.git_dir != None and len(args.git_dir) != 0:
    # Sort the output of the "git log" command to create a list of users.
    git_users_cmd = "git log --format='%aE' | sort | uniq"
    try:
        saved_path = os.getcwd()
        os.chdir(args.git_dir)
    except:
        print("ERROR: Can't access directory %s." % args.git_dir)
        exit(0)

    users = run_cmd(git_users_cmd).split('\n')

    try:
        os.chdir(saved_path)
    except:
        print("WARNING: Can't access directory %s." % saved_path)

# Else if we've been given a list of users:
elif args.user_file != None and len(args.user_file) != 0:
    users = read_file(args.user_file).split('\n')

else:
    print("ERROR: Bad value for -g (%s) or -u (%s)." %
          (args.git_dir, args.user_file))
    parser.print_help()
    exit(0)

# Clean up the user names.  An email address should have at least 3 chars:
users = [ usr.strip() for usr in users if len(usr.strip()) > 2 ]

for user in users:				# For every user in the list:
    matches = rules.map_user(user)		# Find which rules match the user.
    if len(matches) == 0:
        print("No matches for user %s." % user)
    else:					# Show every possible match for user:
        print("User %s mapped to:" % user)
        for m in matches:
            print("\t" + m)


