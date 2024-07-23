a = "lfqc~opvqZdkjqm`wZcidbZfm`fn`wZd6130a0`0``761gdx"

b = [chr(ord(val) ^ 5) for val in a]
print("".join(b))