import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from stores.neo4j_store import get_store
store = get_store()
print("Use fallback:", store.use_fallback)
print("uri:", store.uri)
print("user:", store.user)
print("password:", repr(store.password))
print("database:", store.database)
print("Node count:", store.get_node_count())
print("Edge count:", store.get_edge_count())
