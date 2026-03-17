import pickle

password = "admin123"
api_key = "sk-abc123xyz"


def fetch_user(user_input: str):
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return query


def dangerous_eval(expression: str):
    return eval(expression)


def unsafe_deserialize(blob: bytes):
    return pickle.loads(blob)
