"""Reference fix: command injection.

Why the hole existed
    The host name was pasted into a command line, and the command line was handed
    to a shell. The shell does not know which part was the developer's and which
    part was the user's: `;`, `&&`, `|`, a newline, `$(...)` and backticks in the
    "host name" all start commands of their own, run as the web server's user.

Why this fix works
    Two independent layers. The command is a list of arguments run without a
    shell, so no character in `host` has any special meaning: `127.0.0.1; id` is
    one strange host name that ping cannot resolve, not two commands. And the
    host must look like an IP address or a DNS name before anything runs; the
    `--` before it tells ping that no options follow, so a "host" such as `-f`
    cannot switch on ping's flood mode (argument injection).

The secure pattern
    Do not start a shell to run one program: pass a list of arguments
    (subprocess.run([...]), never shell=True or os.system). Better still, use a
    library call instead of a program when one exists. Validate user input against
    what it must be (an allowlist pattern), not against a list of bad characters:
    blocklists forget the newline, `$(...)` or the next shell's syntax. Put `--`
    before user-supplied arguments. If a shell is truly unavoidable, quote every
    user value with shlex.quote. Run the process with the least privilege it needs.
"""

import ipaddress
import re

# One or more labels of letters, digits and inner hyphens, joined by dots: mail.example.test
DNS_NAME = re.compile(
    r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
)


def ping_command(host: str):
    """Return the command that pings `host` once, or None to refuse the host.

    Quillbook runs the result like subprocess.run(command, shell=isinstance(command, str)):
    a string is handed to /bin/sh, a list of arguments runs ping directly, with no shell.
    """
    host = host.strip()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not DNS_NAME.fullmatch(host):
            return None
    return ["ping", "-c", "1", "--", host]
