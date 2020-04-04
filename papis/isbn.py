import papis.document
import papis.importer
import logging
import isbnlib
import click
# See https://github.com/xlcnd/isbnlib for details
from typing import Optional, Dict, Any, List

logger = logging.getLogger('papis:isbnlib')


def get_data(
        query: str = "",
        service: str = "default") -> List[Dict[str, Any]]:
    global logger
    results = []  # type: List[Dict[str, Any]]
    logger.debug('Trying to retrieve isbn')
    isbn = isbnlib.isbn_from_words(query)
    data = isbnlib.meta(isbn, service=service)
    if data is None:
        return results
    else:
        logger.debug('Trying to retrieve isbn')
        assert(isinstance(data, dict))
        results.append(data_to_papis(data))
        return results


def data_to_papis(data: Dict[str, Any]) -> Dict[str, Any]:
    """Convert data from isbnlib into papis formated data

    :param data: Dictionary with data
    :type  data: dict
    :returns: Dictionary with papis keynames

    """
    _k = papis.document.KeyConversionPair
    key_conversion = [
            _k("authors", [{
                "key": "author_list",
                "action": lambda authors: [
                    papis.document.split_author_name(author)
                    for author in authors]}]),
            _k("isbn-13", [
                {"key": "isbn-13", "action": None},
                {"key": "isbn", "action": None},
                {"key": "ref", "action": None}]),
    ]

    data = {k.lower(): data[k] for k in data}
    data['type'] = 'book'

    return papis.document.keyconversion_to_data(
            key_conversion, data, keep_unknown_keys=True)


class Importer(papis.importer.Importer):
    """Importer that retries ISBN data."""

    def __init__(self, **kwargs: Any):
        papis.importer.Importer.__init__(self, name="isbn", **kwargs)

    @classmethod
    def match(cls, uri: str) -> Optional[papis.importer.Importer]:
        if isbnlib.notisbn(uri):
            return None
        return Importer(uri=uri)

    @papis.importer.cache
    def fetch(self: papis.importer.Importer) -> Any:
        try:
            data = get_data(self.uri)[0]
        except isbnlib.dev._exceptions.NoDataForSelectorError:
            pass
        else:
            self.ctx.data = data


@click.command('isbn')
@click.pass_context
@click.help_option('--help', '-h')
@click.option('--query', '-q', default=None)
@click.option(
    '--service',
    '-s',
    default='default',
    type=click.Choice(['default', 'goob', 'openl'])
)
def explorer(ctx: click.core.Context, query: str, service: str) -> None:
    """
    Look for documents using isbnlib

    Examples of its usage are

    papis explore isbn -q 'Albert einstein' pick cmd 'firefox {doc[url]}'

    """
    logger = logging.getLogger('explore:isbn')
    logger.info('Looking up...')
    data = get_data(
        query=query,
        service=service,
    )
    docs = [papis.document.from_data(data=d) for d in data]
    logger.info('{} documents found'.format(len(docs)))
    ctx.obj['documents'] += docs
