"""One-shot patch for raced-directory durability."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

store_path = ROOT / "src/csd_foundry/synthesis/v0_4/publication_store.py"
store = store_path.read_text(encoding="utf-8")
old = '''        if not path.is_dir():
            raise PublicationStoreError("publication path exists but is not a directory")
'''
new = '''        if not path.is_dir():
            raise PublicationStoreError("publication path exists but is not a directory")
        cls._fsync_directory(path)
        cls._fsync_directory(path.parent)
'''
if old not in store:
    raise RuntimeError("publication directory validation block changed")
store_path.write_text(store.replace(old, new, 1), encoding="utf-8")

test_path = ROOT / "tests/test_v0_4_publication_protocol.py"
tests = test_path.read_text(encoding="utf-8")
marker = '''def test_concurrent_directory_creation_is_idempotent(
'''
regression = '''def test_preexisting_raced_directory_syncs_its_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedPublicationStore(tmp_path)
    envelope = AttemptCompletionEnvelope.from_completion(publication_fixture_accepted())
    target = store.object_path(envelope.digest).parent
    target.mkdir(parents=True)

    synced: list[Path] = []
    monkeypatch.setattr(
        ContentAddressedPublicationStore,
        "_fsync_directory",
        staticmethod(synced.append),
    )
    result = store.publish_bytes(envelope.canonical_bytes, expected_digest=envelope.digest)

    assert result.disposition is PublicationDisposition.PUBLISHED
    assert target in synced
    assert target.parent in synced


'''
if marker not in tests:
    raise RuntimeError("publication concurrency test insertion point changed")
test_path.write_text(tests.replace(marker, regression + marker, 1), encoding="utf-8")
