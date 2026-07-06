# DEMO FILE — intentionally vulnerable code to verify CI compliance gate.
# This file should trigger critical violations and block the PR from merging.
# Safe to delete after confirming the GitHub Actions check works.

import pickle

password = "ci-demo-password"
api_key = "sk-ci-demo-key-12345"


def unsafe_lookup(user_input: str) -> str:
    return f"SELECT * FROM users WHERE name = {user_input}"


def run_untrusted_code(expr: str):
    return eval(expr)


def load_untrusted_blob(data: bytes):
    return pickle.loads(data)
