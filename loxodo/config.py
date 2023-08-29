#
# Loxodo -- Password Safe V3 compatible Password Vault
# Copyright (C) 2008 Christoph Sommer <mail@christoph-sommer.de>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

# pylint: disable=too-many-instance-attributes

import os
import platform
from configparser import ConfigParser as SafeConfigParser
from pathlib import Path
from collections import deque


class History(deque):
    'Hostory of opened vaults'
    def __init__(self):
        super().__init__(self, 10)

    def append(self, value: str):
        if not value:
            return
        value = value.strip()
        if value:
            if value in self:
                # don't append existing path
                return
            super().append(value)

    def appendleft(self, value: str):
        if not value:
            return
        value = value.strip()
        if value:
            if value in self:
                # remove and insert
                self.remove(value)
            super().appendleft(value)


class Config:
    """
    Manages the configuration file
    """
    def __init__(self):
        """
        DEFAULT VALUES
        """
        self._basescript = None
        self.recentvaults = History()
        self.pwlength = 10
        self.reduction = False
        self.search_notes = False
        self.search_passwd = False
        self.alphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_"

        self._fname: Path = self.get_config_filename()
        self._parser = SafeConfigParser()

        if self._fname.exists():
            self._parser.read(self._fname)

        if not self._parser.has_section("base"):
            self._parser.add_section("base")

        for num in range(self.recentvaults.maxlen):
            k = f'recentvaults{num}'
            if self._parser.has_option("base", k):
                self.recentvaults.append(self._parser.get("base", k))

        if self._parser.has_option("base", "alphabet"):
            self.alphabet = self._parser.get("base", "alphabet")

        if self._parser.has_option("base", "pwlength"):
            self.pwlength = int(self._parser.get("base", "pwlength"))

        if self._parser.has_option("base", "alphabetreduction"):
            if self._parser.get("base", "alphabetreduction") == "True":
                self.reduction = True

        if self._parser.has_option("base", "search_notes"):
            if self._parser.get("base", "search_notes") == "True":
                self.search_notes = True

        if self._parser.has_option("base", "search_passwd"):
            if self._parser.get("base", "search_passwd") == "True":
                self.search_passwd = True

        if not self._fname.exists():
            self.save()

    def set_basescript(self, basescript):
        self._basescript = basescript

    def get_basescript(self):
        return self._basescript

    def save(self):
        if not self._fname.parent.exists():
            self._fname.parent.mkdir(0o700, parents=True, exist_ok=True)

        for i, item in enumerate(self.recentvaults):
            self._parser.set("base", f"recentvaults{i}", item)

        self._parser.set("base", "pwlength", str(self.pwlength))
        s = self.alphabet.replace('%', '%%')
        self._parser.set("base", "alphabet", s)
        self._parser.set("base", "alphabetreduction", str(self.reduction))
        self._parser.set("base", "search_notes", str(self.search_notes))
        self._parser.set("base", "search_passwd", str(self.search_passwd))
        with open(self._fname, 'w') as filehandle:  # pylint: disable=unspecified-encoding
            self._parser.write(filehandle)

    @staticmethod
    def get_config_filename() -> Path:
        """
        Returns the full filename of the config file
        """
        base_fname = Path("loxodo")

        # On Mac OS X, config files go to ~/Library/Application Support/foo/
        if platform.system() == "Darwin":
            base_path = Path.home() / "Library" / "Application Support"
            if base_path.is_dir():
                return base_path / base_fname / f'{base_fname}.ini'
        # On Microsoft Windows, config files go to $APPDATA/foo/
        elif platform.system() in ("Windows", "Microsoft"):
            if "APPDATA" in os.environ:
                base_path = Path(os.environ["APPDATA"])
                if base_path.is_dir():
                    return base_path / base_fname / f'{base_fname}.ini'

        # Allow config directory override as per freedesktop.org XDG Base Directory Specification
        if "XDG_CONFIG_HOME" in os.environ:
            base_path = Path(os.environ["XDG_CONFIG_HOME"])
            if base_path.is_dir():
                return base_path / base_fname / f'{base_fname}.ini'

        # Default configuration path is ~/.config/foo/
        base_path = Path.home() / ".config"
        if base_path.is_dir():
            return base_path / base_fname / f'{base_fname}.ini'

        return Path.home() / f'.{base_fname}.ini'

config = Config()
