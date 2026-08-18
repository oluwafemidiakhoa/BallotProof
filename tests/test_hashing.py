from ballotproof.hashing import sha256_bytes


def test_sha256_is_stable() -> None:
    assert sha256_bytes(b"ballotproof") == (
        "648695ca49f751a0a47df7df2ff04be2f1d6ed9b9a46d10cc774da3a55eca60f"
    )
