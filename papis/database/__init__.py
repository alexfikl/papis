from contextlib import contextmanager
from typing import Iterator, Optional

from .base import Database
import papis.library
import papis.logging
import papis.document

logger = papis.logging.get_logger(__name__)

DATABASES = {}  # type: Dict[papis.library.Library, Database]


def get(library_name: Optional[str] = None) -> Database:
    global DATABASES

    import papis.config
    if library_name is None:
        library = papis.config.get_lib()
    else:
        library = papis.config.get_lib_from_name(library_name)

    try:
        database = DATABASES[library]
    except KeyError:
        backend = papis.config.get("database-backend") or "papis"
        database = _instantiate_database(backend, library)
        DATABASES[library] = database

    return database


def _instantiate_database(
        backend_name: str,
        library: papis.library.Library) -> Database:
    if backend_name == "papis":
        import papis.database.cache
        return papis.database.cache.Database(library)
    elif backend_name == "whoosh":
        import papis.database.whoosh
        return papis.database.whoosh.Database(library)
    else:
        raise ValueError("Invalid database backend: '{}'".format(backend_name))


def get_all_query_string() -> str:
    return get().get_all_query_string()


def clear_cached() -> None:
    global DATABASES
    DATABASES = {}


@contextmanager
def context(doc: papis.document.Document,
            library_name: Optional[str] = None) -> Iterator[Database]:
    db = get(library_name=library_name)
    try:
        yield db
    finally:
        doc.save()
        db.update(doc)
