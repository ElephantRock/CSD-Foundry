# Contributing

Changes must be issue-driven, tested, and reviewed through a pull request.

```bash
pip install -e '.[dev]'
ruff format --check .
ruff check .
mypy src
pytest
```

Dataset releases are immutable. Corrections require a new record identity or version,
an updated manifest, and an explicit supersession record.
