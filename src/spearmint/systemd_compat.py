"""Literal ExecStart arguments supported by systemd 249 and later."""


def literal_arguments(arguments: list[str]) -> list[str]:
    # systemd unescapes $$ without expanding it as an environment reference.
    # --expand-environment=no is only available starting with systemd 254.
    escaped = [argument.replace('$', '$$') for argument in arguments]
    # systemd-run resolves the executable before the manager unescapes argv.
    # A constant executable keeps dollar signs in the real program path literal.
    return ['/usr/bin/env', '--', *escaped] if '$' in arguments[0] else escaped
