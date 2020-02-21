#!/usr/bin/env python3
"""
Exscript runner tool.

Usage:
  exsrun encode <text>
  exsrun [options] (-s --script=FILE)... <host>...
  exsrun [options] (-f --fromfile=FILE) (-s --script=FILE)...
  exsrun -h | --help
  exsrun --version

Options:
  -h --help                 Show this screen.
  --version                 Show version.
  -c NUM --connections=NUM  Set maximum connections [default: 1].
  -v NUM --verbose=NUM      Set out debug information [default: 1].
  -a FILE --accounts=FILE   Get username/password from file [default: acc.cfg].
  -l FILE --logging=FILE    Save logging information to file.
  -p PASS --password=PASS   Set authorization password.
  -f FILE --fromfile=FILE   Get hosts from file.
  -s FILE --script=FILE     Add the script file to the queue.
  --status                  Print status information in end.
  --summarize               Print summarize information in end.
"""
import re
import os
import logging
import base64
from docopt import docopt
from Exscript import Queue, Logger
from Exscript.util.log import log_to
from Exscript.util.report import status, summarize
from Exscript.util.file import get_accounts_from_file, get_hosts_from_file
import Exscript.util.template as template

args = docopt(__doc__, version="1.4.8")

if args["encode"]:
    print(base64.b64encode(bytes(args["<text>"], "utf-8")).decode("utf-8"))
    exit(0)

check_exists = []

check_exists.append(args["--accounts"])
check_exists.append(args["--fromfile"])
check_exists.extend(args["--script"])

for filename in list(filter(None, check_exists)):
    if not os.path.exists(filename):
        exit("Specified file '%s' does not exist." % filename)

hosts = args["<host>"] or get_hosts_from_file(args["--fromfile"])

accounts = get_accounts_from_file(args["--accounts"])

for account in accounts:
    account.set_authorization_password(args["--password"])

script = ""

for filename in args["--script"]:
    script += ''.join(filter(str.strip, open(filename).readlines()))

template.test(script)

username_prompt = re.compile(r"(user ?name|user ?id|login)[\w\s()<>]*: *$",
                             re.IGNORECASE)
password_prompt = re.compile(r"(password)[\w\s()<>]*: *$",
                             re.IGNORECASE)

login_error_prompt = re.compile(r"""[\r\n]?[^\r\n]*(?:bad secrets|bad password|
                                denied|invalid|too short|incorrect|
                                connection timed out|rejected|
                                fail|failed|failure)""",
                                re.IGNORECASE | re.X)

error_prompt = re.compile(r"^%?\s*(?:error|invalid|incomplete|\
                          unrecognized|unknown command|failure|failed|fail|\
                          connection timed out|[^\r\n]+ not found)",
                          re.IGNORECASE)

logger = Logger()

@log_to(logger)

def do_job(job, host, conn):
    conn.set_login_error_prompt(login_error_prompt)
    conn.set_username_prompt(username_prompt)
    conn.set_password_prompt(password_prompt)
    conn.set_error_prompt(error_prompt)
    conn.app_authenticate()
    if conn.is_app_authenticated():
        template.eval(conn, script)

def job_cb(jobname, exc_info):
    logging.basicConfig(stream=open(args["--logging"] or os.devnull, 'a'),
                        format='%(asctime)s %(message)s')
    logging.warning("%s %s: %s", jobname,
                    exc_info[1].__class__.__name__,
                    ('%r' % str(exc_info[1]))[1:-1])

queue = Queue(verbose=int(args["--verbose"]),
              max_threads=int(args["--connections"]),
              exc_cb=job_cb,
              stderr=open(os.devnull, 'w'))

queue.add_account(accounts)
queue.run(hosts, do_job)
queue.shutdown()

if args["--status"]:
    print(status(logger))
if args["--summarize"]:
    print(summarize(logger))
