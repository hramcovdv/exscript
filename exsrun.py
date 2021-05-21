"""Exscript runner tool.

Usage:
  exsrun cipher WORD
  exsrun [options] [-v | -vv | -vvv] (--script=FILE)... (--hosts=FILE | HOST)...
  exsrun -h | --help
  exsrun --version

Options:
  -h --help                 Show this screen.
  --version                 Show version.
  -f FILE --hosts=FILE      Get hosts from file.
  -s FILE --script=FILE     Add the script file to the queue.
  -u USER --username=USER   Set authentication username.
  -p PSWD --password=PSWD   Set authentication password.
  -a FILE --accounts=FILE   Get username/password from file.
  -l FILE --logging=FILE    Save logging information to file.
  -c NUM --connections=NUM  Set maximum connections [default: 1].
  --status                  Print status information in end.
  --summarize               Print summarize information in end."""
import re
import os
import sys
import base64
import logging
from getpass import getpass
from docopt import docopt
from Exscript import Queue, Logger, Account, Host
from Exscript.util.log import log_to
from Exscript.util.decorator import bind
from Exscript.util.report import status, summarize
from Exscript.util.file import get_accounts_from_file, get_hosts_from_file
from Exscript.parselib.exception import ExecuteError
import Exscript.util.template as template

logger = Logger()

LOGIN_ERROR_PROMPT = re.compile(
    r"[\r\n]?[^\r\n]*(?:bad secrets|bad password|denied|invalid|too short|incorrect|connection timed out|rejected|fail|failed|failure)",
    re.IGNORECASE)

ERROR_PROMPT = re.compile(
    r"^%?\s*(?:error|invalid|incomplete|unrecognized|unknown command|failure|failed|fail|connection timed out|[^\r\n]+ not found)",
    re.IGNORECASE)

USERNAME_PROMPT = re.compile(
    r"(user ?name|user ?id|login)[\w\s()<>]*: *$",
    re.IGNORECASE)

PASSWORD_PROMPT = re.compile(
    r"(password)[\w\s()<>]*: *$",
    re.IGNORECASE)


def read_file(filename):
    """ Read text file
    """
    with open(filename) as file:
        return file.read()


def cipher(word, encoding='utf-8'):
    """ Base64 encrypted word
    """
    hashed = base64.b64encode(word.encode(encoding=encoding))
    return hashed.decode(encoding=encoding)


def init_connection(func):
    """ Initializing the connection
    """
    def wrapper(job, host, conn, script):
        conn.set_login_error_prompt(LOGIN_ERROR_PROMPT)
        conn.set_error_prompt(ERROR_PROMPT)
        conn.set_username_prompt(USERNAME_PROMPT)
        conn.set_password_prompt(PASSWORD_PROMPT)
        conn.app_authenticate()
        func(job, host, conn, script)

    return wrapper


@log_to(logger)
@init_connection
def do_job(job, host, conn, script):
    """ Run script on host if authenticated
    """
    if conn.is_app_authenticated():
        template.eval(conn, script)


def job_cb(jobname, exc_info):
    """ Callback as log report
    """
    class_name = exc_info[1].__class__.__name__
    message = ('%r' % str(exc_info[1]))[1:-1]

    logging.warning("%s %s: %s", jobname, class_name, message)


if __name__ == "__main__":
    args = docopt(__doc__, version="1.6")

    logging.basicConfig(filename=args['--logging'],
                        datefmt="%Y-%m-%d %H:%M:%S",
                        level=logging.WARNING,
                        format="%(asctime)s %(levelname)s %(message)s")

    if args['cipher']:
        print(cipher(args['WORD']))
        sys.exit(0)

    check_files = args['--hosts'] + args['--script'] + [args['--accounts']]
    for filename in filter(None, check_files):
        if not os.path.isfile(filename):
            sys.exit('No such file: %s' % filename)

    hosts = []
    if args['--hosts']:
        for filename in args['--hosts']:
            hosts += get_hosts_from_file(filename)

    if args['HOST']:
        hosts += [Host(host) for host in args['HOST']]

    all_in_one_script = ""
    for filename in args['--script']:
        all_in_one_script += read_file(filename)

    try:
        template.test(all_in_one_script)
    except ExecuteError as error:
        sys.exit(error)

    queue = Queue(
        verbose=int(args['-v']),
        max_threads=int(args['--connections']),
        # stdout=open(os.devnull, "w"),
        stderr=open(os.devnull, "w"),
        exc_cb=job_cb)

    if args['--accounts']:
        queue.add_account(get_accounts_from_file(args['--accounts']))
    else:
        queue.add_account(
            Account(args['--username'] or input('Enter username: '),
                    args['--password'] or getpass('Enter password: ')))

    queue.run(hosts, bind(do_job, all_in_one_script))
    queue.shutdown()

    if args['--status']:
        print(status(logger))

    if args['--summarize']:
        print(summarize(logger))
