import os
import configparser
import papis.utils
import logging

logger = logging.getLogger("config")

CONFIGURATION = None #: Global configuration object variable.
DEFAULT_SETTINGS = None #: Default settings for the whole papis.
DEFAULT_MODE = "document" #: Default mode in the modal architecture.
OVERRIDE_VARS = {
    "folder": None,
    "cache": None,
    "file": None,
    "scripts": None
}


general_settings = {
    "mode"         : "document",
    "opentool"     : "xdg-open",
    "editor"       : "xdg-open",
    "file-browser" : "xdg-open",
    "default"      : "papers",
    "match_format" : \
        "{doc[tags]}{doc.subfolder}{doc[title]}{doc[author]}{doc[year]}",
    "header_format": \
        "{doc[title]:<70.70}|{doc[author]:<20.20} ({doc[year]:-<4})",
}


def get_general_settings_name():
    """Get the section name of the general settings
    :returns: Section's name
    :rtype:  str
    """
    return "settings"


def get_default_settings(section="", key=""):
    """Get the default settings for all non-user variables
    in papis.

    If section and key are given, then the setting
    for the given section and the given key are returned.

    If only ``key`` is given, then the setting
    for the ``general`` section is returned.

    :param section: Particular section of the default settings
    :type  section: str
    :param key: Setting's name to be queried for.
    :type  key: str
    """
    global DEFAULT_SETTINGS
    import papis.gui
    if DEFAULT_SETTINGS is None:
        DEFAULT_SETTINGS = {
            get_general_settings_name(): general_settings,
        }
        DEFAULT_SETTINGS.update(
            papis.gui.get_default_settings()
        )
    if not section and not key:
        return DEFAULT_SETTINGS
    elif not section:
        return DEFAULT_SETTINGS[get_general_settings_name()][key]
    else:
        return DEFAULT_SETTINGS[section][key]


def get_config_folder():
    """Get folder where the configuration files are stored,
    e.g. /home/user/.papis
    """
    return os.path.join(
        os.path.expanduser("~"), ".papis"
    )


def get_cache_folder():
    """Get folder where the cache files are stored,
    e.g. /home/user/.papis/cache
    """
    return os.path.join(
        get_config_folder(), "cache"
    )


def get_config_file():
    """Get the path of the main configuration file,
    e.g. /home/user/.papis/config
    """
    global OVERRIDE_VARS
    if OVERRIDE_VARS["file"] is not None:
        config_file = OVERRIDE_VARS["file"]
    else:
        config_file = os.path.join(
            get_config_folder(), "config"
        )
    logger.debug("Getting config file %s" % config_file)
    return config_file


def set_config_file(filepath):
    """Override the main configuration file path
    """
    global OVERRIDE_VARS
    if filepath is not None:
        logger.debug("Setting config file to %s" % filepath)
        OVERRIDE_VARS["file"] = filepath


def get_scripts_folder():
    """Get folder where the scripts are stored,
    e.g. /home/user/.papis/scripts
    """
    return os.path.join(
        get_config_folder(), "scripts"
    )


def general_get(key, section=None, data_type=None):
    """General getter method that will be specialised for different modules.

    :param data_type: The data type that should be expected for the value of
        the variable.
    :type  data_type: DataType, e.g. int, src ...
    :param default: Default value for the configuration variable if it is not set.
    :type  default: It should be the same that ``data_type``
    :param extras: List of tuples containing section and prefixes
    """
    # Init main variables
    method = None
    value = None
    config = get_configuration()
    lib = papis.utils.get_lib()
    global_section = get_general_settings_name()
    specialized_key = section + "-" + key if section is not None else key
    extras = [(section, key)] if section is not None else []
    sections = [(global_section, specialized_key)] +\
        extras + [(lib, specialized_key)]
    default_settings = get_default_settings()

    # Check data type for setting getter method
    if data_type == int:
        method = config.getint
    elif data_type == float:
        method = config.getfloat
    elif data_type == bool:
        method = config.getboolean
    else:
        method = config.get

    # Try to get key's value from configuration
    for extra in sections:
        sec = extra[0]
        whole_key = extra[1]
        if sec not in config.keys():
            continue
        if whole_key in config[sec].keys():
            value = method(sec, whole_key)

    if value is None:
        try:
            default = default_settings.get(
                section or global_section
            ).get(
                specialized_key if section is None else key
            )
        except KeyError:
            raise papis.exceptions.DefaultSettingValueMissing(
                "Value for '%s' is not at all registered and known" % (
                    key
                )
            )
        else:
            return default
    return value


def get(*args, **kwargs):
    """String getter
    """
    return general_get(*args, **kwargs)


def getint(*args, **kwargs):
    """Integer getter
    """
    return general_get(*args, data_type=int, **kwargs)


def getfloat(*args, **kwargs):
    """Float getter
    """
    return general_get(*args, data_type=float, **kwargs)


def getboolean(*args, **kwargs):
    """Bool getter
    """
    return general_get(*args, data_type=bool, **kwargs)


def inMode(mode):
    current_mode = get("mode", default=DEFAULT_MODE)
    logger.debug("current_mode = %s" % current_mode)
    return mode == current_mode


def get_configuration():
    """Get the configuratoin object, if no papis configuration has ever been
    initialized, it initializes one. Only one configuration per process should
    ever be configurated.

    :returns: Configuration object
    :rtype:  papis.config.Configuration
    """
    global CONFIGURATION
    if CONFIGURATION is None:
        logger.debug("Creating configuration")
        CONFIGURATION = Configuration()
    return CONFIGURATION


def reset_configuration():
    """Destroys existing configuration and returns a new one.

    :returns: Configuration object
    :rtype:  papis.config.Configuration
    """
    global CONFIGURATION
    if CONFIGURATION is not None:
        logger.warning("Overwriting previous configuration")
    CONFIGURATION = None
    logger.debug("Reseting configuration")
    return get_configuration()


# DELETE
def get_default_match_format():
    return "{doc.subfolder}{doc[title]}{doc[author]}{doc[year]}"


# DELETE
def get_default_header_format():
    return "{doc[title]:<70.70}|{doc[author]:<20.20} ({doc[year]:-<4})"


# DELETE
def get_header_format(key="header_format"):
    try:
        header_format = get(key)
    except:
        header_format = get_default_header_format()
    return header_format


# DELETE
def get_match_format():
    try:
        match_format = get("match_format")
    except:
        match_format = get_default_match_format()
    return match_format


class Configuration(configparser.ConfigParser):

    default_info = {
      "papers": {
        'dir': '~/Documents/papers'
      },
      "settings": {
        'default': 'papers'
      }
    }

    logger = logging.getLogger("Configuration")

    def __init__(self):
        configparser.ConfigParser.__init__(self)
        self.dir_location = get_config_folder()
        self.scripts_location = get_scripts_folder()
        self.file_location = get_config_file()
        self.initialize()

    def handle_includes(self):
        if "include" in self.keys():
            for name in self["include"]:
                self.logger.debug("including %s" % name)
                self.read(os.path.expanduser(self.get("include", name)))

    def initialize(self):
        if not os.path.exists(self.dir_location):
            os.makedirs(self.dir_location)
        if not os.path.exists(self.scripts_location):
            os.makedirs(self.scripts_location)
        if os.path.exists(self.file_location):
            self.read(self.file_location)
            self.handle_includes()
        else:
            for section in self.default_info:
                self[section] = {}
                for field in self.default_info[section]:
                    self[section][field] = self.default_info[section][field]
            with open(self.file_location, "w") as configfile:
                self.write(configfile)

    def save(self):
        fd = open(self.file_location, "w")
        self.write(fd)
        fd.close()
