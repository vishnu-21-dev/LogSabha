"""The LogSabha verifier: an offline command-line tool.

It reads evidence bundles (files exported by witnesses) and chain data (through a chain reader).
It never talks to a live witness. Verdicts are only MATCH, MISMATCH or CANNOT VERIFY.
"""
