"""Challenge: command injection in the mail server check.

Stage 2: patch ping_command, then run `pytest fix_tests -k command_injection`.
"""


# BREACHLAB: patch this function
def ping_command(host: str):
    """Return the command that pings `host` once, or None to refuse the host.

    Quillbook runs the result like subprocess.run(command, shell=isinstance(command, str)):
    a string is handed to /bin/sh, a list of arguments runs ping directly, with no shell.
    """
    return f"ping -c 1 {host}"
