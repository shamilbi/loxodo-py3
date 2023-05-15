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
from hmac import HMAC
import os
import tempfile
import time
from uuid import UUID, uuid4
import secrets
import dataclasses

from loxodo.twofish.twofish_ecb import TwofishECB
from loxodo.twofish.twofish_cbc import TwofishCBC


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


def _read_field_tlv(filehandle, cipher) -> Field:
    """
    Return one field of a vault record by reading from the given file handle.
    """
    data = filehandle.read(16)
    if not data or len(data) < 16:
        raise VaultFormatError("EOF encountered when parsing record field")
    if data == b"PWS3-EOFPWS3-EOF":
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
    _last_mod: int = 0
    _url: str = ""

    @staticmethod
    def create():
        record = Record()
        record.uuid = uuid4()
        record.last_mod = int(time.time())
        return record

    def add_raw_field(self, raw_field: Field):
        self.raw_fields[raw_field.raw_type] = raw_field
        if raw_field.raw_type == 0x01:
            self._uuid = UUID(bytes_le=raw_field.raw_value)
        elif raw_field.raw_type == 0x02:
            self._group = raw_field.raw_value.decode('utf_8', 'replace')
        elif raw_field.raw_type == 0x03:
            self._title = raw_field.raw_value.decode('utf_8', 'replace')
        elif raw_field.raw_type == 0x04:
            self._user = raw_field.raw_value.decode('utf_8', 'replace')
        elif raw_field.raw_type == 0x05:
            self._notes = raw_field.raw_value.decode('utf_8', 'replace')
        elif raw_field.raw_type == 0x06:
            self._passwd = raw_field.raw_value.decode('utf_8', 'replace')
        elif raw_field.raw_type == 0x0c and raw_field.raw_len == 4:
            self._last_mod = struct.unpack("<L", raw_field.raw_value)[0]
        elif raw_field.raw_type == 0x0d:
            self._url = raw_field.raw_value.decode('utf_8', 'replace')

    def mark_modified(self):
        self.last_mod = int(time.time())

    @property
    def uuid(self) -> UUID:
        return self._uuid

    @uuid.setter
    def uuid(self, value: UUID):
        self._uuid = value
        raw_id = 0x01
        self.raw_fields[raw_id] = Field(raw_id, value.bytes_le)
        self.mark_modified()

    @property
    def group(self) -> str:
        return self._group

    @group.setter
    def group(self, value: str):
        self._group = value
        raw_id = 0x02
        self.raw_fields[raw_id] = Field(raw_id, value.encode('utf_8', 'replace'))
        self.mark_modified()

    @property
    def title(self) -> str:
        return self._title

    @title.setter
    def title(self, value: str):
        self._title = value
        raw_id = 0x03
        self.raw_fields[raw_id] = Field(raw_id, value.encode('utf_8', 'replace'))
        self.mark_modified()

    @property
    def user(self) -> str:
        return self._user

    @user.setter
    def user(self, value: str):
        self._user = value
        raw_id = 0x04
        self.raw_fields[raw_id] = Field(raw_id, value.encode('utf_8', 'replace'))
        self.mark_modified()

    @property
    def notes(self) -> str:
        return self._notes

    @notes.setter
    def notes(self, value: str):
        self._notes = value
        raw_id = 0x05
        self.raw_fields[raw_id] = Field(raw_id, value.encode('utf_8', 'replace'))
        self.mark_modified()

    @property
    def passwd(self) -> str:
        return self._passwd

    @passwd.setter
    def passwd(self, value: str):
        self._passwd = value
        raw_id = 0x06
        self.raw_fields[raw_id] = Field(raw_id, value.encode('utf_8', 'replace'))
        self.mark_modified()

    @property
    def last_mod(self) -> int:
        return self._last_mod

    @last_mod.setter
    def last_mod(self, value: int):
        self._last_mod = value
        raw_id = 0x0c
        self.raw_fields[raw_id] = Field(raw_id, struct.pack("<L", value))

    @property
    def url(self) -> str:
        return self._url

    @url.setter
    def url(self, value: str):
        self._url = value
        raw_id = 0x0d
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

    def for_cmp(self):
        return self._group + self._title


def duplicate_record(record2: Record) -> Record:
    record = Record()
    record.merge(record2)
    record.uuid = uuid4()
    record.last_mod = int(time.time())
    record.title = record2.title + ' (copy)'
    return record


def _urandom(count):
    return secrets.token_bytes(count)


def _write_field_tlv(filehandle, cipher, field):
    """
    Write one field of a vault record using the given file handle.
    """
    if field is None:
        filehandle.write(b"PWS3-EOFPWS3-EOF")
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
    def __init__(self, password, filename=None):
        self.f_tag = None
        self.f_salt = None
        self.f_iter = None
        self.f_sha_ps = None
        self.f_b1 = None
        self.f_b2 = None
        self.f_b3 = None
        self.f_b4 = None
        self.f_iv = None
        self.f_hmac = None
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
        self.f_tag = 'PWS3'
        self.f_salt = _urandom(32)
        self.f_iter = 2048
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
        if self.f_tag != b'PWS3':
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
            if field.raw_type == 0xff:
                break
            self.header.add_raw_field(field)
            hmac_checker.update(field.raw_value)

        # read fields

        current_record = Record()
        while True:
            field = _read_field_tlv(filehandle, cipher)
            if not field:
                break
            if field.raw_type == 0xff:
                self.records.append(current_record)
                current_record = Record()
            else:
                hmac_checker.update(field.raw_value)
                current_record.add_raw_field(field)

        # read HMAC

        self.f_hmac = filehandle.read(32)  # HMAC: used to verify Vault's integrity

        my_hmac = hmac_checker.digest()
        if self.f_hmac != my_hmac:
            raise VaultFormatError("File integrity check failed")

        #self.records.sort(key=lambda r: r._group + r._title)
        self.records.sort(key=lambda r: r.for_cmp())

    def _read_from_file(self, filename, password: bytes):
        """
        Initialize all class members by loading the contents of a Vault stored in the given file.
        """
        #filehandle = open(filename, 'rb')
        with open(filename, 'rb') as filehandle:
            self._read_from_stream(filehandle, password)
        #filehandle.close()

    def write_to_stream(self, filehandle, password: bytes):
        _last_save = struct.pack("<L", int(time.time()))
        self.header.raw_fields[0x04] = Field(0x04, _last_save)
        _what_saved = "Loxodo 0.0-git".encode("utf_8", "replace")
        self.header.raw_fields[0x06] = Field(0x06, _what_saved)

        # FIXME: choose new SALT, B1-B4, IV values on each file write? Conflicting Specs!

        # write boilerplate

        filehandle.write(self.f_tag)
        filehandle.write(self.f_salt)
        filehandle.write(struct.pack("<L", self.f_iter))

        stretched_password = _stretch_password(password, self.f_salt, self.f_iter)
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

        end_of_record = Field(0xff, b"")

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
