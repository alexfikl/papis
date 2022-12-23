"""
The doctor command checks for the overall health of your
library.

There are many checks implemented and some others that you
can add yourself through the python configuration file.
"""

import os
import re
import collections
from typing import Any, Optional, List, NamedTuple, Callable, Dict, Set

import click

import papis
import papis.cli
import papis.config
import papis.strings
import papis.database
import papis.document
import papis.logging

logger = papis.logging.get_logger(__name__)

# FIXME: when going to python >=3.6, these should be classes (dataclasses?) and
# have some basic documentation for the various fields
FixFn = Callable[[], None]
Error = NamedTuple("Error", [("name", str),
                             ("path", str),
                             ("payload", str),
                             ("msg", str),
                             ("suggestion_cmd", str),
                             ("fix_action", FixFn),
                             ("doc", Optional[papis.document.Document]),
                             ])
CheckFn = Callable[[papis.document.Document], List[Error]]
Check = NamedTuple("Check", [("name", str),
                             ("operate", CheckFn),
                             ])
REGISTERED_CHECKS = {}  # type: Dict[str, Check]


def error_to_dict(e: Error) -> Dict[str, Any]:
    return {
        "msg": e.payload,
        "path": e.path,
        "name": e.name,
        "suggestion": e.suggestion_cmd}


def register_check(name: str, check_function: CheckFn) -> None:
    """
    Register a check.

    Registered checks are recognized by ``papis`` and can be used by users
    in their configuration files, for example.
    """
    REGISTERED_CHECKS[name] = Check(name=name, operate=check_function)


def registered_checks_names() -> List[str]:
    return list(REGISTERED_CHECKS.keys())


FILES_CHECK_NAME = "files"


def files_check(doc: papis.document.Document) -> List[Error]:
    """
    Check whether the files of a document actually exist in the filesystem.

    :returns: a :class:`list` of errors, one for each file that does not exist.
    """
    files = doc.get_files()
    folder = doc.get_main_folder() or ""

    def make_fixer(filename: str) -> FixFn:
        def fixer() -> None:
            """
            Files fixer function that removes non-existent files from the document.

            For now it only works if the file name is not of the form
            ``subdirectory/filename``, but only ``filename``.
            """

            with papis.database.context(doc):
                basename = os.path.basename(filename)
                if basename in doc["files"]:
                    logger.info("[FIX] Removing file from document: '%s'", basename)
                    doc["files"].remove(basename)

        return fixer

    return [Error(name=FILES_CHECK_NAME,
                  path=folder,
                  msg="File '{}' declared but does not exist".format(f),
                  suggestion_cmd="papis edit --doc-folder {}".format(folder),
                  fix_action=make_fixer(f),
                  payload=f,
                  doc=doc)
            for f in files if os.path.exists(f)]


KEYS_EXIST_CHECK_NAME = "keys-exist"


def keys_check(doc: papis.document.Document) -> List[Error]:
    """
    Checks whether the keys provided in the configuration
    option ``doctor-keys-check`` exit in the document and are non-empty.

    :returns: a :class:`list` of errors, one for each key that does not exist.
    """
    keys = papis.config.getlist("doctor-keys-exist-keys")
    folder = doc.get_main_folder() or ""

    return [Error(name=KEYS_EXIST_CHECK_NAME,
                  path=folder,
                  msg="Key '{}' does not exist.".format(k),
                  suggestion_cmd="papis edit --doc-folder {}".format(folder),
                  fix_action=lambda: None,
                  payload=k,
                  doc=doc)
            for k in keys if k not in doc]


REFS_CHECK_NAME = "refs"


def refs_check(doc: papis.document.Document) -> List[Error]:
    """
    Checks that a ref exists and if not it tries to create one according to
    the ``ref-format`` configuration option, if the user chooses to fix it.

    :returns: an error if the reference does not exist or contains invalid
        characters (as required by BibTeX).
    """
    folder = doc.get_main_folder() or ""
    bad_symbols = re.compile(r"[ ,{}\[\]@#`']")

    def fixer() -> None:
        ref = papis.bibtex.create_reference(doc, force=True)
        logger.info("[FIX] Setting ref '%s' in '%s'",
                    ref,
                    papis.document.describe(doc))

        with papis.database.context(doc):
            doc["ref"] = ref

    ref = doc.get("ref")
    ref = str(ref).strip() if ref is not None else ref

    if not ref:
        return [Error(name=REFS_CHECK_NAME,
                      path=folder,
                      msg="Reference missing.",
                      suggestion_cmd=("papis edit --doc-folder {}"
                                      .format(folder)),
                      fix_action=fixer,
                      payload="",
                      doc=doc)]

    m = bad_symbols.findall(ref)
    if m:
        return [Error(name=REFS_CHECK_NAME,
                      path=folder,
                      msg="Bad characters ({}) found in reference.".format(set(m)),
                      suggestion_cmd="papis edit --doc-folder {}".format(folder),
                      fix_action=fixer,
                      payload="",
                      doc=doc)]

    return []


DUPLICATED_KEYS_SEEN = collections.defaultdict(set)  # type: Dict[str, Set[str]]
DUPLICATED_KEYS_NAME = "duplicated-keys"


def duplicated_keys_check(doc: papis.document.Document) -> List[Error]:
    """
    Check for duplicated keys in the list given by the
    ``doctor-duplicated-keys-check`` configuration option.

    :returns: a :class:`list` of errors, one for each key with a value that already
        exist in the documents from the current query.
    """
    keys = papis.config.getlist("doctor-duplicated-keys-keys")
    folder = doc.get_main_folder() or ""

    results = []  # type: List[Error]
    for key in keys:
        value = doc.get(key)
        if value is None:
            continue

        value = str(value)
        seen = DUPLICATED_KEYS_SEEN[key]
        if value not in seen:
            seen.update(value)
            continue

        results.append(Error(name=DUPLICATED_KEYS_NAME,
                             path=folder,
                             msg="Key '{}' is duplicated ({}).".format(key, value),
                             suggestion_cmd="papis edit {}:'{}'".format(key, value),
                             fix_action=lambda: None,
                             payload=key,
                             doc=doc))

    return results


BIBTEX_TYPE_CHECK_NAME = "bibtex-type"


def bibtex_type_check(doc: papis.document.Document) -> List[Error]:
    """
    Check that the document type is compatible with BibTeX or BibLaTeX type
    descriptors.

    :returns: an error if the types are not compatible.
    """
    import papis.bibtex
    folder = doc.get_main_folder() or ""
    bib_type = doc.get("type")

    if bib_type is None:
        return [Error(name=BIBTEX_TYPE_CHECK_NAME,
                      path=folder,
                      msg="Document does not define a type.",
                      suggestion_cmd="papis edit --doc-folder {}".format(folder),
                      fix_action=lambda: None,
                      payload="type",
                      doc=doc)]

    if bib_type not in papis.bibtex.bibtex_types:
        return [Error(name=BIBTEX_TYPE_CHECK_NAME,
                      path=folder,
                      msg=("Document type '{}' is not a valid BibTeX type."
                           .format(bib_type)),
                      suggestion_cmd="papis edit --doc-folder {}".format(folder),
                      fix_action=lambda: None,
                      payload=bib_type,
                      doc=doc)]

    return []


BIBLATEX_TYPE_ALIAS_CHECK_NAME = "biblatex-type-alias"


def biblatex_type_alias_check(doc: papis.document.Document) -> List[Error]:
    import papis.bibtex
    folder = doc.get_main_folder() or ""

    def make_fixer(value: str) -> FixFn:
        def fixer() -> None:
            with papis.database.context(doc):
                logger.info("[FIX] Setting 'type' to '%s'", value)
                doc["type"] = value

        return fixer

    bib_type = doc.get("type")
    bib_type_base = papis.bibtex.bibtex_type_aliases.get(bib_type)
    if bib_type is not None and bib_type_base is not None:
        return [Error(name=BIBLATEX_TYPE_ALIAS_CHECK_NAME,
                      path=folder,
                      msg=("Document type '{}' is an alias for '{}' in BibLaTeX."
                           .format(bib_type, bib_type_base)),
                      suggestion_cmd="papis edit --doc-folder {}".format(folder),
                      fix_action=make_fixer(bib_type_base),
                      payload=bib_type,
                      doc=doc)]

    return []


BIBLATEX_KEY_ALIAS_CHECK_NAME = "biblatex-key-alias"


def biblatex_key_alias_check(doc: papis.document.Document) -> List[Error]:
    import papis.bibtex
    folder = doc.get_main_folder() or ""

    def make_fixer(key: str) -> FixFn:
        def fixer() -> None:
            with papis.database.context(doc):
                new_key = papis.bibtex.bibtex_key_aliases[key]
                logger.info("[FIX] Renaming key '%s' to '%s'", key, new_key)
                doc[new_key] = doc[key]
                del doc[key]

        return fixer

    # NOTE: `journal` is a key that papis relies on and we do not want to rename it
    aliases = papis.bibtex.bibtex_key_aliases.copy()
    del aliases["journal"]

    return [Error(name=BIBLATEX_KEY_ALIAS_CHECK_NAME,
                  path=folder,
                  msg=("Document key '{}' is an alias for '{}' in BibLaTeX."
                       .format(key, aliases[key])),
                  suggestion_cmd="papis edit --doc-folder {}".format(folder),
                  fix_action=make_fixer(key),
                  payload=key,
                  doc=doc)
            for key in doc if key in aliases]


BIBLATEX_REQUIRED_KEYS_CHECK_NAME = "biblatex-required-keys"


def biblatex_required_keys_check(doc: papis.document.Document) -> List[Error]:
    import papis.bibtex
    folder = doc.get_main_folder() or ""

    errors = bibtex_type_check(doc)
    if errors:
        return errors

    # translate bibtex type
    bib_type = doc["type"]
    bib_type = papis.bibtex.bibtex_type_aliases.get(bib_type, bib_type)

    if bib_type not in papis.bibtex.bibtex_type_required_keys:
        bib_type = papis.bibtex.bibtex_type_required_keys_aliases.get(bib_type, "empty")

    required_keys = papis.bibtex.bibtex_type_required_keys[bib_type]
    aliases = {v: k for k, v in papis.bibtex.bibtex_key_aliases.items()}

    return [Error(name=BIBLATEX_REQUIRED_KEYS_CHECK_NAME,
                  path=folder,
                  msg=("Document of type '{}' requires one of the keys '{}' "
                       "to be compatible with BibLaTeX."
                       .format(bib_type, "', '".join(keys))),
                  suggestion_cmd="papis edit --doc-folder {}".format(folder),
                  fix_action=lambda: None,
                  payload=",".join(keys),
                  doc=doc)
            for keys in required_keys
            if not any(key in doc or aliases.get(key) in doc for key in keys)]


KEY_TYPE_CHECK_NAME = "key-type"


def key_type_check(doc: papis.document.Document) -> List[Error]:
    """
    Check document keys have expected types.

    The ``doctor-key-type-check-keys`` configuration entry defines a mapping
    of keys and their expected types.

    :returns: a :class:`list` of errors, one for each key does not have the
        expected type (if it exists).
    """
    folder = doc.get_main_folder() or ""

    results = []
    for value in papis.config.getlist("doctor-key-type-check-keys"):
        try:
            key, cls_name = eval(value)
        except SyntaxError:
            logger.error("Invalid (key, type) pair: '%s'", value)
            continue

        try:
            cls = eval(cls_name)
        except NameError:
            logger.error("Invalid type for key '%s': '%s'", key, cls_name)
            continue

        doc_value = doc.get(key)
        if doc_value is not None and not isinstance(doc_value, cls):
            results.append(Error(name=KEY_TYPE_CHECK_NAME,
                                 path=folder,
                                 msg=("Key '{}' ({}) should be of type '{}'"
                                      " but found '{}'"
                                      .format(key, doc_value,
                                              cls, type(doc_value).__name__)),
                                 suggestion_cmd=("papis edit --doc-folder {}"
                                                 .format(folder)),
                                 fix_action=lambda: None,
                                 payload=key,
                                 doc=doc))
    return results


HTML_CODE_REGEX = re.compile(r"&[a-z_A-Z0-9]+;")
HTML_CODES_CHECK_NAME = "html-codes"


def html_codes_check(doc: papis.document.Document) -> List[Error]:
    """
    Checks that the keys in ``doctor-html-code-keys`` configuratio options do
    not contain any HTML codes like ``&amp;`` etc.

    :returns: a :class:`list` of errors, one for each key that contains HTML codes.
    """
    results = []
    folder = doc.get_main_folder() or ""

    def make_fixer(key: str) -> FixFn:
        def fixer() -> None:
            import html

            with papis.database.context(doc):
                val = html.unescape(doc[key])
                doc[key] = val
                logger.info("[FIX] Setting '%s' to '%s'", key, val)

        return fixer

    for key in papis.config.getlist("doctor-html-codes-keys"):
        value = doc.get(key)
        if value is None:
            continue

        m = HTML_CODE_REGEX.findall(str(value))
        if m:
            results.append(Error(name=HTML_CODES_CHECK_NAME,
                                 path=folder,
                                 msg=("Field '{}' contains HTML codes {}"
                                      .format(key, m)),
                                 suggestion_cmd=(
                                     "papis edit --doc-folder {}".format(folder)),
                                 fix_action=make_fixer(key),
                                 payload=key,
                                 doc=doc))

    return results


register_check(FILES_CHECK_NAME, files_check)
register_check(KEYS_EXIST_CHECK_NAME, keys_check)
register_check(DUPLICATED_KEYS_NAME, duplicated_keys_check)
register_check(BIBTEX_TYPE_CHECK_NAME, bibtex_type_check)
register_check(BIBLATEX_TYPE_ALIAS_CHECK_NAME, biblatex_type_alias_check)
register_check(BIBLATEX_KEY_ALIAS_CHECK_NAME, biblatex_key_alias_check)
register_check(BIBLATEX_REQUIRED_KEYS_CHECK_NAME, biblatex_required_keys_check)
register_check(REFS_CHECK_NAME, refs_check)
register_check(HTML_CODES_CHECK_NAME, html_codes_check)
register_check(KEY_TYPE_CHECK_NAME, key_type_check)


def run(doc: papis.document.Document, checks: List[str]) -> List[Error]:
    """
    Runner for ``papis doctor``.

    It runs all the checks given by the *checks* argument that have been
    registered through :func:`register_check`.
    """
    assert all(check in REGISTERED_CHECKS for check in checks)

    results = []  # type: List[Error]
    for check in checks:
        results.extend(REGISTERED_CHECKS[check].operate(doc))

    return results


@click.command("doctor")
@click.help_option("--help", "-h")
@papis.cli.query_argument()
@papis.cli.sort_option()
@click.option("-t", "--checks", "_checks",
              default=lambda: papis.config.getlist("doctor-default-checks"),
              multiple=True,
              type=click.Choice(registered_checks_names()),
              help="Checks to run on every document.")
@click.option("--json", "_json",
              default=False, is_flag=True,
              help="Output the results in json format")
@click.option("--fix",
              default=False, is_flag=True,
              help="Auto fix the errors with the auto fixer mechanism")
@click.option("-s", "--suggest",
              default=False, is_flag=True,
              help="Suggest commands to be run for resolution")
@click.option("-e", "--explain",
              default=False, is_flag=True,
              help="Give a short message for the reason of the error")
@click.option("--edit",
              default=False, is_flag=True,
              help="Edit every file with the edit command.")
@papis.cli.all_option()
@papis.cli.doc_folder_option()
def cli(query: str,
        doc_folder: str,
        sort_field: Optional[str],
        sort_reverse: bool,
        _all: bool,
        fix: bool,
        edit: bool,
        explain: bool,
        _checks: List[str],
        _json: bool,
        suggest: bool) -> None:
    """Check for common problems in documents"""

    documents = papis.cli.handle_doc_folder_query_all_sort(
        query, doc_folder, sort_field, sort_reverse, _all)

    if not documents:
        logger.warning(papis.strings.no_documents_retrieved_message)
        return

    logger.debug("Running checks: %s", _checks)

    errors = []  # type: List[Error]
    for doc in documents:
        errors.extend(run(doc, _checks))

    if errors:
        logger.warning("%s errors found", len(errors))
    else:
        logger.info("No errors found!")

    if _json:
        import json

        print(json.dumps(list(map(error_to_dict, errors))))
        return

    from papis.commands.edit import run as edit_run

    for error in errors:
        print("{e.name}\t{e.payload}\t{e.path}".format(e=error))

        if explain:
            print("\tReason: {}".format(error.msg))

        if suggest:
            print("\tSuggestion: {}".format(error.suggestion_cmd))

        if fix:
            error.fix_action()

        if edit and error.doc:
            input("Press any key to edit...")
            edit_run(error.doc)
