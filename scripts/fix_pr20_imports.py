from pathlib import Path


path = Path("src/csd_foundry/synthesis/v0_4/execution_validation.py")
text = path.read_text(encoding="utf-8")
text = text.replace(
    "from csd_foundry.synthesis.v0_4.generation_namespace import build_generation_namespace\n"
    "from csd_foundry.synthesis.v0_4.execution_vectors import (\n",
    "from csd_foundry.synthesis.v0_4.execution_vectors import (\n",
)
text = text.replace(
    "    validate_execution_vector_catalog,\n)\n"
    "from csd_foundry.synthesis.v0_4.serialization import canonical_sha256\n",
    "    validate_execution_vector_catalog,\n)\n"
    "from csd_foundry.synthesis.v0_4.generation_namespace import build_generation_namespace\n"
    "from csd_foundry.synthesis.v0_4.serialization import canonical_sha256\n",
)
path.write_text(text, encoding="utf-8")

path = Path("tests/test_v0_4_execution_review_regressions.py")
text = path.read_text(encoding="utf-8")
text = text.replace(
    "    ExecutionInventory,\n"
    "    InventorySupersessionRecord,\n"
    "    ExecutionProtocolError,\n",
    "    ExecutionInventory,\n"
    "    ExecutionProtocolError,\n"
    "    InventorySupersessionRecord,\n",
)
path.write_text(text, encoding="utf-8")
