"""
This command is used to list items in a library.

Examples
^^^^^^^^

- List all files associated will all documents in the library:

    .. code:: sh

        papis list --all --file

- List the year and title of all documents with some custom formatting:

    .. code:: sh

        papis list --all --format '{doc[year]} {doc[title]}'

- List all documents according to the ``bibitem`` formatting (stored in a template
  file ``bibitem.template``):

    .. code:: sh

        papis list --all --template bibitem.template

- For scripting, printing the id of a series of documents is valuable in order
  to further use the id in other scripts.

    .. code:: sh

        papis_id=$(papis list --id einstein)
        papis open papis_id:${papis_id}
        papis edit papis_id:${papis_id}
        # etc.

Command-line Interface
^^^^^^^^^^^^^^^^^^^^^^

.. click:: papis.commands.list:cli
    :prog: papis list
"""

import os
from typing import List, Optional, Sequence, Tuple

import click

import papis.id
import papis.cli
import papis.config
import papis.strings
import papis.document
import papis.format
import papis.logging

logger = papis.logging.get_logger(__name__)


def run(documents: Sequence[papis.document.Document],
        show_files: bool = False,
        show_dir: bool = False,
        show_id: bool = False,
        show_info: bool = False,
        show_notes: bool = False,
        show_format: str = "",
        template: Optional[str] = None
        ) -> List[str]:
    """List document properties.

    :arg template: a path to a file containing a format string that can be
        used instead of *show_format*.
    :return: a list of properties depending on the given flags.
    """

    if show_files:
        return [f for doc in documents for f in doc.get_files()]

    if show_id:
        return [papis.id.get(d) for d in documents]

    if show_notes:
        return [f for doc in documents for f in doc.get_notes()]

    if show_info:
        return [d.get_info_file() for d in documents]

    if show_format or template is not None:
        if not show_format and template is not None:
            if not os.path.exists(template):
                logger.error("Template file '%s' not found.", template)
                return []

            with open(template) as fd:
                show_format = fd.read()

        return [
            papis.format.format(show_format, document,
                                default=papis.document.describe(document))
            for document in documents
        ]

    if show_dir:
        return [f for d in documents if (f := d.get_main_folder()) is not None]

    raise ValueError("At least one of the flags should be True")


@click.command("list")
@click.help_option("--help", "-h")
@papis.cli.query_argument()
@papis.cli.bool_flag(
    "-i", "--info", "show_info",
    help="Show the info file for each document")
@papis.cli.bool_flag(
    "--id", "show_id",
    help="Show the papis id for each document")
@papis.cli.bool_flag(
    "-f", "--file", "show_files",
    help="Show the files for each document")
@papis.cli.bool_flag(
    "-d", "--dir", "show_dir",
    help="Show the folder name containing each document")
@papis.cli.bool_flag(
    "-n", "--notes", "show_notes",
    help="Show notes files for each document")
@click.option(
    "--format", "show_format",
    help="Show documents using a custom format, e.g. '{doc[year]} {doc[title]}",
    default="")
@papis.cli.bool_flag(
    "--libraries", "show_libraries",
    help="List defined libraries")
@papis.cli.bool_flag(
    "--exporters", "show_exporters",
    help="List available exporters")
@papis.cli.bool_flag(
    "--explorers", "show_explorers",
    help="List available explorers")
@papis.cli.bool_flag(
    "--importers", "show_importers",
    help="List available importers")
@papis.cli.bool_flag(
    "--downloaders", "show_downloaders",
    help="List available downloaders")
@papis.cli.bool_flag(
    "--pickers", "show_pickers",
    help="List available pickers")
@click.option(
    "--template",
    help="Template file containing a papis format to list documents",
    default=None)
@papis.cli.all_option()
@papis.cli.sort_option()
@papis.cli.doc_folder_option()
def cli(query: str,
        show_info: bool,
        show_id: bool,
        show_files: bool,
        show_notes: bool,
        show_dir: bool,
        show_format: str,
        show_libraries: bool,
        show_exporters: bool,
        show_explorers: bool,
        show_importers: bool,
        show_downloaders: bool,
        show_pickers: bool,
        template: Optional[str],
        _all: bool,
        doc_folder: Tuple[str, ...],
        sort_field: Optional[str],
        sort_reverse: bool) -> None:
    """List document metadata"""
    from papis.plugin import get_extension_manager

    if show_libraries:
        for lib in papis.config.get_libs():
            click.echo(f"{lib} {papis.config.get('dir', section=lib)}")
        return

    if show_exporters:
        from papis.commands.export import EXPORTER_EXTENSION_NAME
        for p in get_extension_manager(EXPORTER_EXTENSION_NAME):
            c = p.plugin
            click.echo(f"{p.name} {c.__module__}.{c.__name__}")
        return

    if show_explorers:
        from papis.commands.explore import EXPLORER_EXTENSION_NAME
        for p in get_extension_manager(EXPLORER_EXTENSION_NAME):
            c = p.plugin.callback
            click.echo(f"{p.name} {c.__module__}.{c.__name__}")
        return

    if show_importers:
        from papis.importer import IMPORTER_EXTENSION_NAME
        for p in get_extension_manager(IMPORTER_EXTENSION_NAME):
            c = p.plugin
            click.echo(f"{p.name} {c.__module__}.{c.__name__}")
        return

    if show_downloaders:
        from papis.downloaders import DOWNLOADERS_EXTENSION_NAME
        for p in get_extension_manager(DOWNLOADERS_EXTENSION_NAME):
            c = p.plugin
            click.echo(f"{p.name} {c.__module__}.{c.__name__}")
        return

    if show_pickers:
        from papis.pick import PICKER_EXTENSION_NAME
        for p in get_extension_manager(PICKER_EXTENSION_NAME):
            c = p.plugin
            click.echo(f"{p.name} {c.__module__}.{c.__name__}")
        return

    documents = papis.cli.handle_doc_folder_query_all_sort(
        query, doc_folder, sort_field, sort_reverse, _all)

    if not documents:
        logger.warning(papis.strings.no_documents_retrieved_message)
        return

    objects = run(
        documents,
        show_notes=show_notes,
        show_files=show_files,
        show_dir=show_dir,
        show_id=show_id,
        show_info=show_info,
        show_format=show_format,
        template=template)

    for o in objects:
        click.echo(o)
