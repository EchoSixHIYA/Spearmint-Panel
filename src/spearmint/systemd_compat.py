"""Literal ExecStart arguments supported by systemd 249 and later."""


def literal_arguments(arguments: list[str]) -> list[str]:
    # systemd unescapes $$ without expanding it as an environment reference.
    # --expand-environment=no is only available starting with systemd 254.
    return [argument.replace('$', '$$') for argument in arguments]
