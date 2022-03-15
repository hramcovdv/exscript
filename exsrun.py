"""Exscript runner tool.

Usage:
  exsrun [options] [-v | -vv | -vvv] (--script=FILE)... (--hosts=FILE | HOST...)
  exsrun -h | --help
  exsrun --version

Options:
  -h --help                 Show this screen.
  --version                 Show version.
  -f FILE --hosts=FILE      Get hosts from file.
  -s FILE --script=FILE     Add the script file to the queue.
  -a FILE --accounts=FILE   Get username/password from file.
  -l FILE --logging=FILE    Save logging information to file.
  -c NUM --connections=NUM  Set maximum connections [default: 1].
  --status                  Print status information in end.
  --summarize               Print summarize information in end."""
import re
import os
import logging
from docopt import docopt
from Exscript import Queue, Logger, Host
from Exscript.util import decorator, template
from Exscript.util.log import log_to
from Exscript.util.report import status, summarize
from Exscript.util.interact import read_login
from Exscript.util.file import get_hosts_from_file, get_accounts_from_file

USERNAME_PROMPT = re.compile(
    r'(user ?name|user ?id|login).*: *$',
    re.IGNORECASE)

PASSWORD_PROMPT = re.compile(
    r'(password).*: *$',
    re.IGNORECASE)

LOGIN_ERROR_PROMPT = re.compile(
    r'[\r\n]?[^\r\n]*(?:bad secrets|bad password|denied|invalid|too short|incorrect|connection timed out|rejected|fail|failed|failure)',
    re.IGNORECASE)

ERROR_PROMPT = re.compile(
    r'^%?\s*(?:error|invalid|incomplete|unrecognized|unknown command|failure|failed|fail|connection timed out|[^\r\n]+ not found)',
    re.IGNORECASE)

logger = Logger()


def get_script_from_files(filenames):
    """ Combine all scripts into one.
    """
    script = ''

    for filename in filenames:
        if not os.path.exists(filename):
            raise IOError('No such file: %s' % filename)

        with open(filename, 'r', encoding='utf-8') as file:
            script += file.read()

    template.test(script)

    return script


def init_connection(func):
    """ Initializing the connection.
    """
    def wrapper(job, host, conn, script):
        conn.set_username_prompt(USERNAME_PROMPT)
        conn.set_password_prompt(PASSWORD_PROMPT)
        conn.set_login_error_prompt(LOGIN_ERROR_PROMPT)
        conn.set_error_prompt(ERROR_PROMPT)
        conn.app_authenticate()
        func(job, host, conn, script)

    return wrapper


@log_to(logger)
@init_connection
def do_job(job, host, conn, script):
    """ Run script on host if authenticated.
    """
    if conn.is_app_authenticated():
        template.eval(conn, script)


def job_cb(jobname, exc_info):
    """ Callback as log report.
    """
    class_name = exc_info[1].__class__.__name__
    message = ('%r' % str(exc_info[1]))[1:-1]

    logging.warning('%s %s: %s', jobname, class_name, message)


if __name__ == '__main__':
    args = docopt(__doc__, version='1.7')

    logging.basicConfig(
        filename=args['--logging'],
        datefmt='%Y-%m-%d %H:%M:%S',
        level=logging.WARNING,
        format='%(asctime)s %(levelname)s %(message)s'
    )

    queue = Queue(
        verbose=int(args['-v'])-1,
        max_threads=int(args['--connections']),
        stderr=open(os.devnull, 'w'),
        exc_cb=job_cb
    )

    proto = 'ssh' if args['--ssh'] else 'telnet'

    script = get_script_from_files(args['--script'])
    
    if args['--hosts']:
        hosts = get_hosts_from_file(args['--hosts'])
    else:
        hosts = [Host(h) for h in args['HOST']]

    if args['--accounts']:
        queue.add_account(get_accounts_from_file(args['--accounts']))
    else:
        queue.add_account(read_login())

    queue.run(hosts, decorator.bind(do_job, script))
    queue.shutdown()

    if args['--status']:
        print(status(logger))
        
    if args['--summarize']:
        print(summarize(logger))
