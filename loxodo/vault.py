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

import hashlib
import struct
from hmac import HMAC, compare_digest
import os
import tempfile
import time
from enum import IntEnum
from uuid import UUID, uuid4
import secrets
import dataclasses
from datetime import datetime

from .twofish.twofish_ecb import TwofishECB
from .twofish.twofish_cbc import TwofishCBC
from . import __version__


class BadPasswordError(RuntimeError):
    pass


class VaultFormatError(RuntimeError):
    pass


class VaultVersionError(VaultFormatError):
    pass


@dataclasses.dataclass
class Field:
    """
    Contains the raw, on-disk representation of a record's field.
    """
    raw_type: int
    raw_value: bytes

    @property
    def raw_len(self):
        return len(self.raw_value)


@dataclasses.dataclass
class Header:
    """
    Contains the fields of a Vault header.
    """
    raw_fields: dict[int, Field] = dataclasses.field(default_factory=dict)

    def add_raw_field(self, raw_field: Field):
        self.raw_fields[raw_field.raw_type] = raw_field

    @property
    def what_saved(self):
        if Headers.WHAT_SAVED in self.raw_fields:
            field = self.raw_fields[Headers.WHAT_SAVED]
            return field.raw_value.decode('utf_8', 'replace')
        return ""

    @property
    def last_save(self):
        if Headers.LAST_SAVE in self.raw_fields:
            field = self.raw_fields[Headers.LAST_SAVE]
            i = struct.unpack("<L", field.raw_value)[0]
            return datetime.fromtimestamp(i).strftime('%Y-%m-%d %H:%M:%S')
        return ""

    @property
    def version(self):
        if Headers.VERSION in self.raw_fields:
            field = self.raw_fields[Headers.VERSION]
            i = struct.unpack("<H", field.raw_value)[0]
            return f'{i:04x}'
        return ""


class Headers(IntEnum):
    'currently implemented headers, the rest are saved as is'
    VERSION = 0x00  # Version
    LAST_SAVE = 0x04    # Timestamp of last save
    WHAT_SAVED = 0x06   # What performed last save


class Fields(IntEnum):
    'currently implemented fields, the rest are saved as is'
    UUID = 0x01
    GROUP = 0x02
    TITLE = 0x03
    USER = 0x04
    NOTES = 0x05
    PASSWD = 0x06
    CREATED = 0x07
    LAST_MOD = 0x0c
    URL = 0x0d


END_OF_ENTRY: int = 0xff     # end of header or fields

FILE_MAGIC: bytes = b'PWS3'
END_OF_FILE: bytes = b"PWS3-EOFPWS3-EOF"


def _read_field_tlv(filehandle, cipher) -> Field:
    """
    Return one field of a vault record by reading from the given file handle.
    """
    data = filehandle.read(16)
    if not data or len(data) < 16:
        raise VaultFormatError("EOF encountered when parsing record field")
    if data == END_OF_FILE:
        return None
    data = cipher.decrypt(data)
    raw_len = struct.unpack("<L", data[0:4])[0]
    raw_type = struct.unpack("<B", bytes([data[4]]))[0]
    #   data = [int]
    raw_value = data[5:]
    if raw_len > 11:
        for _ in range((raw_len+4)//16):
            data = filehandle.read(16)
            if not data or len(data) < 16:
                raise VaultFormatError("EOF encountered when parsing record field")
            raw_value += cipher.decrypt(data)
    raw_value = raw_value[:raw_len]
    return Field(raw_type, raw_value)


@dataclasses.dataclass
class Record:
    """
    Contains the fields of an individual password record.
    """
    raw_fields: dict[int, Field] = dataclasses.field(default_factory=dict)
    _uuid: UUID = None
    _group: str = ""
    _title: str = ""
    _user: str = ""
    _notes: str = ""
    _passwd: str = ""
    _created: int = 0
    _last_mod: int = 0
    _url: str = ""

    @staticmethod
    def create():
        record = Record()
        record.uuid = uuid4()
        time_ = int(time.time())
        record.last_mod = time_
        record.created = time_
        return record

    def add_raw_field(self, raw_field: Field):
        self.raw_fields[raw_field.raw_type] = raw_field
        if raw_field.raw_type == Fields.UUID:
            self._uuid = UUID(bytes_le=raw_field.raw_value)
        elif raw_field.raw_type == Fields.GROUP:
            self._group = raw_field.raw_value.decode('utf_8', 'replace')
        elif raw_field.raw_type == Fields.TITLE:
            self._title = raw_field.raw_value.decode('utf_8', 'replace')
        elif raw_field.raw_type == Fields.USER:
            self._user = raw_field.raw_value.decode('utf_8', 'replace')
        elif raw_field.raw_type == Fields.NOTES:
            self._notes = raw_field.raw_value.decode('utf_8', 'replace')
        elif raw_field.raw_type == Fields.PASSWD:
            self._passwd = raw_field.raw_value.decode('utf_8', 'replace')
        elif raw_field.raw_type == Fields.LAST_MOD and raw_field.raw_len == 4:
            self._last_mod = struct.unpack("<L", raw_field.raw_value)[0]
        elif raw_field.raw_type == Fields.CREATED and raw_field.raw_len == 4:
            self._created = struct.unpack("<L", raw_field.raw_value)[0]
        elif raw_field.raw_type == Fields.URL:
            self._url = raw_field.raw_value.decode('utf_8', 'replace')

    def mark_modified(self):
        self.last_mod = int(time.time())

    @property
    def uuid(self) -> UUID:
        return self._uuid

    @uuid.setter
    def uuid(self, value: UUID):
        self._uuid = value
        raw_id = Fields.UUID
        self.raw_fields[raw_id] = Field(raw_id, value.bytes_le)
        self.mark_modified()

    @property
    def group(self) -> str:
        return self._group

    @group.setter
    def group(self, value: str):
        self._group = value
        raw_id = Fields.GROUP
        self.raw_fields[raw_id] = Field(raw_id, value.encode('utf_8', 'replace'))
        self.mark_modified()

    @property
    def title(self) -> str:
        return self._title

    @title.setter
    def title(self, value: str):
        self._title = value
        raw_id = Fields.TITLE
        self.raw_fields[raw_id] = Field(raw_id, value.encode('utf_8', 'replace'))
        self.mark_modified()

    @property
    def user(self) -> str:
        return self._user

    @user.setter
    def user(self, value: str):
        self._user = value
        raw_id = Fields.USER
        self.raw_fields[raw_id] = Field(raw_id, value.encode('utf_8', 'replace'))
        self.mark_modified()

    @property
    def notes(self) -> str:
        return self._notes

    @notes.setter
    def notes(self, value: str):
        self._notes = value
        raw_id = Fields.NOTES
        self.raw_fields[raw_id] = Field(raw_id, value.encode('utf_8', 'replace'))
        self.mark_modified()

    @property
    def passwd(self) -> str:
        return self._passwd

    @passwd.setter
    def passwd(self, value: str):
        self._passwd = value
        raw_id = Fields.PASSWD
        self.raw_fields[raw_id] = Field(raw_id, value.encode('utf_8', 'replace'))
        self.mark_modified()

    @property
    def last_mod(self) -> int:
        return self._last_mod

    @last_mod.setter
    def last_mod(self, value: int):
        self._last_mod = value
        raw_id = Fields.LAST_MOD
        self.raw_fields[raw_id] = Field(raw_id, struct.pack("<L", value))

    @property
    def created(self) -> int:
        return self._created

    @created.setter
    def created(self, value: int):
        self._created = value
        raw_id = Fields.CREATED
        self.raw_fields[raw_id] = Field(raw_id, struct.pack("<L", value))

    @property
    def url(self) -> str:
        return self._url

    @url.setter
    def url(self, value: str):
        self._url = value
        raw_id = Fields.URL
        self.raw_fields[raw_id] = Field(raw_id, value.encode('utf_8', 'replace'))
        self.mark_modified()

    def is_corresponding(self, record) -> bool:
        """
        Return True if Records are the same, based on either UUIDs (if available) or title
        """
        if not self.uuid or not record.uuid:
            return self.title == record.title
        return self.uuid == record.uuid

    def is_newer_than(self, record):
        """
        Return True if this Record's last modifed date is later than the given one's.
        """
        return self.last_mod > record.last_mod

    def merge(self, record):
        """
        Merge in fields from another Record, replacing existing ones
        """
        self.raw_fields = {}
        for field in record.raw_fields.values():
            self.add_raw_field(field)


def duplicate_record(record2: Record) -> Record:
    record = Record()
    record.merge(record2)
    record.uuid = uuid4()
    time_ = int(time.time())
    record.last_mod = time_
    record.created = time_
    record.title = record2.title + ' (copy)'
    return record


def _urandom(count):
    return secrets.token_bytes(count)


def _write_field_tlv(filehandle, cipher, field):
    """
    Write one field of a vault record using the given file handle.
    """
    if field is None:
        filehandle.write(END_OF_FILE)
        return

    assert len(field.raw_value) == field.raw_len

    raw_len = struct.pack("<L", field.raw_len)
    raw_type = struct.pack("<B", field.raw_type)
    raw_value = field.raw_value

    # Assemble TLV block and pad to 16-byte boundary
    data = raw_len + raw_type + raw_value
    if len(data) % 16 != 0:
        pad_count = 16 - (len(data) % 16)
        data += _urandom(pad_count)

    data = cipher.encrypt(data)

    filehandle.write(data)


def _stretch_password(password, salt, iterations):
    """
    Generate the SHA-256 value of a password after several rounds of stretching.

    The algorithm is described in the following paper:
    [KEYSTRETCH Section 4.1] http://www.schneier.com/paper-low-entropy.pdf
    """
    sha = hashlib.sha256()
    sha.update(password)
    sha.update(salt)
    stretched_password = sha.digest()
    for dummy in range(iterations):
        stretched_password = hashlib.sha256(stretched_password).digest()
    return stretched_password


class Vault:
    """
    Represents a collection of password Records in PasswordSafe V3 format.

    The on-disk represenation of the Vault is described in the following file:
    http://passwordsafe.svn.sourceforge.net/viewvc/passwordsafe/trunk/pwsafe/pwsafe/docs/formatV3.txt?revision=2139
    """

    #write_iter = 2048  # version < 0x030F
    write_iter = 262_144  # version 0x030F
        # The original minimum was 2,048.  As of file format 0x030F, the minimum is
        # 262,144. Older databases are silently upgraded to this vaule when saved.

    def __init__(self, password, filename=None):
        self.f_tag: bytes = None
        self.f_salt = None
        self.f_iter = None
        self.f_sha_ps = None
        self.f_b1 = None
        self.f_b2 = None
        self.f_b3 = None
        self.f_b4 = None
        self.f_iv = None
        self.f_hmac: bytes = None
        self.header = Header()
        self.records = []
        if not filename:
            self._create_empty(password)
        else:
            self._read_from_file(filename, password)

    @staticmethod
    def create(password, filename):
        vault = Vault(password)
        vault.write_to_file(filename, password)

    def _create_empty(self, password: bytes):
        self.f_tag = FILE_MAGIC
        self.f_salt = _urandom(32)
        self.f_iter = self.write_iter
        stretched_password = _stretch_password(password, self.f_salt, self.f_iter)
        self.f_sha_ps = hashlib.sha256(stretched_password).digest()

        cipher = TwofishECB(stretched_password)
        self.f_b1 = cipher.encrypt(_urandom(16))
        self.f_b2 = cipher.encrypt(_urandom(16))
        self.f_b3 = cipher.encrypt(_urandom(16))
        self.f_b4 = cipher.encrypt(_urandom(16))
        key_k = cipher.decrypt(self.f_b1) + cipher.decrypt(self.f_b2)
        key_l = cipher.decrypt(self.f_b3) + cipher.decrypt(self.f_b4)

        self.f_iv = _urandom(16)

        hmac_checker = HMAC(key_l, b"", hashlib.sha256)
        cipher = TwofishCBC(key_k, self.f_iv)

        # No records yet

        self.f_hmac = hmac_checker.digest()

    def _read_from_stream(self, filehandle, password: bytes):
        # read boilerplate

        self.f_tag = filehandle.read(4)  # TAG: magic tag
        if self.f_tag != FILE_MAGIC:
            raise VaultVersionError("Not a PasswordSafe V3 file")

        self.f_salt = filehandle.read(32)  # SALT: SHA-256 salt
        self.f_iter = struct.unpack("<L", filehandle.read(4))[0]
        #   ITER: SHA-256 keystretch iterations
        stretched_password = _stretch_password(password, self.f_salt, self.f_iter)
        #   P': the stretched key
        my_sha_ps = hashlib.sha256(stretched_password).digest()

        self.f_sha_ps = filehandle.read(32) # H(P'): SHA-256 hash of stretched passphrase
        if self.f_sha_ps != my_sha_ps:
            raise BadPasswordError("Wrong password")

        self.f_b1 = filehandle.read(16)  # B1
        self.f_b2 = filehandle.read(16)  # B2
        self.f_b3 = filehandle.read(16)  # B3
        self.f_b4 = filehandle.read(16)  # B4

        cipher = TwofishECB(stretched_password)
        key_k = cipher.decrypt(self.f_b1) + cipher.decrypt(self.f_b2)
        key_l = cipher.decrypt(self.f_b3) + cipher.decrypt(self.f_b4)

        self.f_iv = filehandle.read(16)  # IV: initialization vector of Twofish CBC

        hmac_checker = HMAC(key_l, b"", hashlib.sha256)
        cipher = TwofishCBC(key_k, self.f_iv)

        # read header

        while True:
            field = _read_field_tlv(filehandle, cipher)
            if not field:
                break
            if field.raw_type == END_OF_ENTRY:
                break
            self.header.add_raw_field(field)
            hmac_checker.update(field.raw_value)

        # read fields

        current_record = Record()
        while True:
            field = _read_field_tlv(filehandle, cipher)
            if not field:
                break
            if field.raw_type == END_OF_ENTRY:
                self.records.append(current_record)
                current_record = Record()
            else:
                hmac_checker.update(field.raw_value)
                current_record.add_raw_field(field)

        # read HMAC

        self.f_hmac = filehandle.read(32)  # HMAC: used to verify Vault's integrity

        my_hmac = hmac_checker.digest()
        #if self.f_hmac != my_hmac:
        if not compare_digest(self.f_hmac, my_hmac):
            # https://docs.python.org/3.10/library/hmac.html#hmac.HMAC.digest
            # When comparing the output of digest() to an externally supplied
            # digest during a verification routine, it is recommended to use
            # the compare_digest() function instead of the == operator
            # to reduce the vulnerability to timing attacks
            raise VaultFormatError("File integrity check failed")

    def _read_from_file(self, filename, password: bytes):
        """
        Initialize all class members by loading the contents of a Vault stored in the given file.
        """
        with open(filename, 'rb') as filehandle:
            self._read_from_stream(filehandle, password)

    def write_to_stream(self, filehandle, password: bytes):
        _last_save = struct.pack("<L", int(time.time()))
        self.header.raw_fields[Headers.LAST_SAVE] = Field(Headers.LAST_SAVE, _last_save)
        _what_saved = f'Loxodo v{__version__}'.encode("utf_8", "replace")
        self.header.raw_fields[Headers.WHAT_SAVED] = Field(Headers.WHAT_SAVED, _what_saved)

        # FIXME: choose new SALT, B1-B4, IV values on each file write? Conflicting Specs!

        # write boilerplate

        filehandle.write(self.f_tag)
        filehandle.write(self.f_salt)

        f_iter = max(self.f_iter, self.write_iter)
        filehandle.write(struct.pack("<L", f_iter))

        stretched_password = _stretch_password(password, self.f_salt, f_iter)
        self.f_sha_ps = hashlib.sha256(stretched_password).digest()
        filehandle.write(self.f_sha_ps)

        filehandle.write(self.f_b1)
        filehandle.write(self.f_b2)
        filehandle.write(self.f_b3)
        filehandle.write(self.f_b4)

        cipher = TwofishECB(stretched_password)
        key_k = cipher.decrypt(self.f_b1) + cipher.decrypt(self.f_b2)
        key_l = cipher.decrypt(self.f_b3) + cipher.decrypt(self.f_b4)

        filehandle.write(self.f_iv)

        hmac_checker = HMAC(key_l, b"", hashlib.sha256)
        cipher = TwofishCBC(key_k, self.f_iv)

        end_of_record = Field(END_OF_ENTRY, b"")

        for field in self.header.raw_fields.values():
            _write_field_tlv(filehandle, cipher, field)
            hmac_checker.update(field.raw_value)
        _write_field_tlv(filehandle, cipher, end_of_record)
        hmac_checker.update(end_of_record.raw_value)

        for record in self.records:
            for field in record.raw_fields.values():
                _write_field_tlv(filehandle, cipher, field)
                hmac_checker.update(field.raw_value)
            _write_field_tlv(filehandle, cipher, end_of_record)
            hmac_checker.update(end_of_record.raw_value)

        _write_field_tlv(filehandle, cipher, None)

        self.f_hmac = hmac_checker.digest()
        filehandle.write(self.f_hmac)

    def write_to_file(self, filename, password: bytes):
        """
        Store contents of this Vault into a file.
        """

        # write to temporary file first
        (osfilehandle, tmpfilename) = tempfile.mkstemp(
            '.part', os.path.basename(filename) + ".", os.path.dirname(filename), text=False)
        #filehandle = os.fdopen(osfilehandle, "wb")
        with open(osfilehandle, 'wb') as filehandle:
            self.write_to_stream(filehandle, password)
        #filehandle.close()

        try:
            _ = Vault(password, filename=tmpfilename)
        except RuntimeError as e:
            os.remove(tmpfilename)
            raise VaultFormatError("File integrity check failed") from e

        # after writing the temporary file, replace the original file with it
        try:
            os.remove(filename)
        except OSError:
            pass
        os.rename(tmpfilename, filename)
