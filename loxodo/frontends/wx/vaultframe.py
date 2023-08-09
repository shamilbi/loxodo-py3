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

# pylint: disable=bad-indentation,too-many-ancestors,unused-argument
# pylint: disable=too-many-statements,too-many-locals,too-many-branches
# pylint: disable=line-too-long,no-member

import os
import csv
import binascii
import webbrowser
from datetime import datetime
import re

import wx
import wx.adv

from loxodo import __version__

from loxodo.vault import (
    Vault, BadPasswordError, VaultFormatError, VaultVersionError, Record, duplicate_record)
from loxodo.config import config
from loxodo.frontends.wx.recordframe import RecordFrame
from loxodo.frontends.wx.mergeframe import MergeFrame
from loxodo.frontends.wx.settings import Settings
from loxodo.frontends.wx.wxlocale import _
from loxodo.frontends.wx import get_icon

try:
    import mintotp
except ImportError:
    mintotp = None

class VaultFrame(wx.Frame):
    """
    Displays (and lets the user edit) the Vault.
    """
    class VaultListCtrl(wx.ListCtrl):
        """
        wx.ListCtrl that contains the contents of a Vault.
        """
        def __init__(self, *args, **kwds):
            wx.ListCtrl.__init__(self, *args, **kwds)
            self.vault = None
            self._filterstring = ""
            self.displayed_entries = []
            self.InsertColumn(0, _("Title"))
            self.InsertColumn(1, _("Username"))
            self.InsertColumn(2, _("Group"))
            self.InsertColumn(3, _("ModTime"))
            self.SetColumnWidth(0, 256)
            self.SetColumnWidth(1, 180)
            self.SetColumnWidth(2, 180)
            self.SetColumnWidth(3, 128)
            #self.sort_function = lambda e1: e1.group.lower()
            self.sort_function = lambda e1: (e1.title.lower(), e1.user.lower(), e1.last_mod)
            self.update_fields()

        def OnGetItemText(self, item, col):
            """
            Return display text for entries of a virtual list

            Overrides the base classes' method.
            """
            # Workaround for obscure wxPython behaviour that leads to an empty wx.ListCtrl sometimes calling OnGetItemText
            if (item < 0) or (item >= len(self.displayed_entries)):
              return "--"

            s = '--'
            if col == 0:
                s = self.displayed_entries[item].title
            if col == 1:
                s = self.displayed_entries[item].user
            if col == 2:
                s = self.displayed_entries[item].group
            if col == 3:
                s = ''
                i: int = self.displayed_entries[item].last_mod
                if i:
                    s = datetime.fromtimestamp(i).strftime('%Y-%m-%d %H:%M:%S')
            return s

        def update_fields(self):
            """
            Update the visual representation of list.

            Extends the base classes' method.
            """
            if not self.vault:
                self.displayed_entries = []
                return
            self.displayed_entries = [record for record in self.vault.records if self.filter_record(record)]

            self.displayed_entries.sort(key=self.sort_function)
            self.SetItemCount(len(self.displayed_entries))
            wx.ListCtrl.Refresh(self)

        def filter_record(self,record):
            if not self._filterstring:
                return True

            if record.title.lower().find(self._filterstring.lower()) >= 0:
               return True

            if record.group.lower().find(self._filterstring.lower()) >= 0:
               return True

            if record.user.lower().find(self._filterstring.lower()) >= 0:
               return True

            if config.search_notes:
             if record.notes.lower().find(self._filterstring.lower()) >= 0:
                return True

            if config.search_passwd:
             if record.passwd.find(self._filterstring) >= 0:
                return True

            return False

        def set_vault(self, vault):
            """
            Set the Vault this control should display.
            """
            self.vault = vault
            self.update_fields()
            self.select_first()

        def set_filter(self, filterstring):
            """
            Sets a filter string to limit the displayed entries
            """
            self._filterstring = filterstring
            self.update_fields()
            self.select_first()

        def deselect_all(self):
            """
            De-selects all items
            """
            while self.GetFirstSelected() != -1:
                self.Select(self.GetFirstSelected(), False)

        def select_first(self):
            """
            Selects and focuses the first item (if there is one)
            """
            #self.deselect_all()
            #if self.GetItemCount() > 0:
            #    self.Select(0, True)
            #    self.Focus(0)
            self.select_index(0)

        def select_index(self, i: int):
            self.deselect_all()
            if (count := self.GetItemCount()) > 0 and i >= 0:
                if i < count:
                    j = i
                else:
                    j = count - 1
                self.Select(j, True)
                self.Focus(j)

        def delete_index(self, i: int):
            if (count := self.GetItemCount()) > 0 and 0 <= i < count:
                del self.displayed_entries[i]
                self.SetItemCount(len(self.displayed_entries))
                wx.ListCtrl.Refresh(self)
                if self.GetFirstSelected() == -1:
                    # last entry
                    self.select_index(i)

        def insert_index(self, i: int, r: Record):
            if i >= 0:
                self.displayed_entries.insert(i, r)
                self.SetItemCount(len(self.displayed_entries))
                wx.ListCtrl.Refresh(self)
                self.select_index(i)


    def __init__(self, *args, **kwds):
        kwds["style"] = wx.DEFAULT_FRAME_STYLE
        wx.Frame.__init__(self, *args, **kwds)

        self.Bind(wx.EVT_CLOSE, self._on_frame_close)

        self.panel = wx.Panel(self, -1)

        self._searchbox = wx.SearchCtrl(self.panel, size=(200, 30))
        # size(200, -1) --> too small height on Linux-x86_64
        self._searchbox.ShowCancelButton(True)
        self.list = self.VaultListCtrl(
                self.panel, -1, size=(700, 240),
                style=wx.LC_REPORT|wx.BORDER_SUNKEN|wx.LC_VIRTUAL|wx.LC_SINGLE_SEL)
        self.list.Bind(wx.EVT_COMMAND_RIGHT_CLICK, self._on_list_contextmenu)
        self.list.Bind(wx.EVT_RIGHT_UP, self._on_list_contextmenu)
        self.list.Bind(wx.EVT_CHAR, self._on_list_box_char)
        # EVT_LIST_COL_END_DRAG: A column has been resized by the user

        self.statusbar = self.CreateStatusBar(1, wx.STB_SIZEGRIP)

        # Set up menus
        filemenu = wx.Menu()
        temp_id = wx.NewId()
        filemenu.Append(temp_id, _("Change &Password") + "...")
        self.Bind(wx.EVT_MENU, self._on_change_password, id=temp_id)

        temp_id = wx.NewId()
        filemenu.Append(temp_id, _("&Merge Records from") + "...")
        self.Bind(wx.EVT_MENU, self._on_merge_vault, id=temp_id)

        # export to csv
        temp_id = wx.NewId()
        filemenu.Append(temp_id, _("&Export to CSV") + "...")
        self.Bind(wx.EVT_MENU, self._on_export_csv, id=temp_id)

        filemenu.Append(wx.ID_ABOUT, _("&About"))
        self.Bind(wx.EVT_MENU, self._on_about, id=wx.ID_ABOUT)
        filemenu.Append(wx.ID_PREFERENCES, _("&Settings"))
        self.Bind(wx.EVT_MENU, self._on_settings, id=wx.ID_PREFERENCES)
        filemenu.AppendSeparator()
        filemenu.Append(wx.ID_EXIT, _("E&xit"))
        self.Bind(wx.EVT_MENU, self._on_exit, id=wx.ID_EXIT)

        self._recordmenu = wx.Menu()
        self._recordmenu.Append(wx.ID_ADD, _("&Add\tCtrl+Shift+A"))
        self.Bind(wx.EVT_MENU, self._on_add, id=wx.ID_ADD)
        self._recordmenu.Append(wx.ID_DUPLICATE, _("&Duplicate\tCtrl+D"))
        self.Bind(wx.EVT_MENU, self._on_add_duplicate, id=wx.ID_DUPLICATE)
        self._recordmenu.Append(wx.ID_DELETE, _("&Delete\tCtrl+Del"))
        self.Bind(wx.EVT_MENU, self._on_delete, id=wx.ID_DELETE)
        self._recordmenu.AppendSeparator()
        self._recordmenu.Append(wx.ID_PROPERTIES, _("&Edit\tCtrl+E"))
        self.Bind(wx.EVT_MENU, self._on_edit, id=wx.ID_PROPERTIES)
        self._recordmenu.AppendSeparator()

        temp_id = wx.NewId()
        self._recordmenu.Append(temp_id, _("Copy &Username\tCtrl+U"))
        self.Bind(wx.EVT_MENU, self._on_copy_username, id=temp_id)

        temp_id = wx.NewId()
        self._recordmenu.Append(temp_id, _("Copy &Password\tCtrl+P"))
        self.Bind(wx.EVT_MENU, self._on_copy_password, id=temp_id)

        if mintotp:
            temp_id = wx.NewId()
            self._recordmenu.Append(temp_id, _("Create &TOTP from Password\tCtrl+T"))
            self.Bind(wx.EVT_MENU, self._on_totp, id=temp_id)

        temp_id = wx.NewId()
        self._recordmenu.Append(temp_id, _("Open UR&L\tCtrl+L"))
        self.Bind(wx.EVT_MENU, self._on_open_url, id=temp_id)

        temp_id = wx.NewId()
        self._recordmenu.Append(temp_id, _("Search &For Entry\tCtrl+F"))
        self.Bind(wx.EVT_MENU, self._on_search_for_entry, id=temp_id)

        menu_bar = wx.MenuBar()
        menu_bar.Append(filemenu, _("&Vault"))
        menu_bar.Append(self._recordmenu, _("&Record"))
        self.SetMenuBar(menu_bar)

        self.SetTitle("Loxodo - " + _("Vault Contents"))
        self.statusbar.SetStatusWidths([-1])
        statusbar_fields = [""]
        #for i in range(len(statusbar_fields)):
        for i, field in enumerate(statusbar_fields):
            #self.statusbar.SetStatusText(statusbar_fields[i], i)
            self.statusbar.SetStatusText(field, i)

        sizer = wx.BoxSizer(wx.VERTICAL)
        _rowsizer = wx.BoxSizer(wx.HORIZONTAL)
        self.Bind(wx.EVT_SEARCHCTRL_CANCEL_BTN, self._on_search_cancel, self._searchbox)
        self.Bind(wx.EVT_TEXT, self._on_search_do, self._searchbox)
        self._searchbox.Bind(wx.EVT_CHAR, self._on_searchbox_char)

        _rowsizer.Add(self._searchbox, proportion=0,
                      flag=wx.ALL | wx.ALIGN_CENTER_VERTICAL | wx.ALIGN_LEFT, border=5)
        sizer.Add(_rowsizer, proportion=0, flag=wx.ALIGN_LEFT | wx.ALL, border=5)
        sizer.Add(self.list, 1, wx.EXPAND, 0)
        self.panel.SetSizer(sizer)
        _sz_frame = wx.BoxSizer()
        _sz_frame.Add(self.panel, 1, wx.EXPAND)
        self.SetSizer(_sz_frame)

        sizer.Fit(self)
        self.Layout()

        self.Bind(wx.EVT_LIST_ITEM_ACTIVATED, self._on_list_item_activated, self.list)
        self.Bind(wx.EVT_LIST_COL_CLICK, self._on_list_column_click, self.list)

        self._searchbox.SetFocus()

        # icon
        self.icon = get_icon('loxodo-icon.png', 128, 128)
        self.SetIcon(self.icon)

        self.vault_file_name = None
        self.vault_password = None
        self.vault = None
        self._is_modified = False

    def _on_list_box_char(self, key_event):
        """
        Typing in the list box doesn't do anything, redirect it to the search box
        """
        keycode = key_event.GetKeyCode()
        if not 0 < keycode < 256:
            # Arrow keys, page up, etc -- let event propagate to default handler
            key_event.Skip()
            return
        if key_event.HasModifiers() or keycode == wx.WXK_TAB:
            # ctrl (eg Ctrl-U to copy username, Ctrl-P to copy password)
            # TAB - switch to SearchBox
            key_event.Skip()
            return
        self._searchbox.SetFocus()
        self._searchbox.EmulateKeyPress(key_event)

    def save_vault2(self):
        self._is_modified = True
        if ((self.vault_file_name is not None) and (self.vault_password is not None)):
            self.save_vault(self.vault_file_name, self.vault_password)

    def mark_modified(self):
        #self._is_modified = True
        #if ((self.vault_file_name is not None) and (self.vault_password is not None)):
        #    self.save_vault(self.vault_file_name, self.vault_password)
        self.save_vault2()
        self.list.update_fields()

    def set_title(self):
        if self.vault:
            header = self.vault.header
            self.SetTitle(f'Loxodo - {self.vault_file_name}, {header.what_saved}, {header.last_save}')

    def open_vault(self, filename, password):
        """
        Set the Vault that this frame should display.
        """
        self.vault_file_name = None
        self.vault_password = None
        self._is_modified = False
        self.vault = Vault(password, filename=filename)
        self.list.set_vault(self.vault)
        self.vault_file_name = filename
        self.vault_password = password
        self.statusbar.SetStatusText(_("Read Vault contents from disk"), 0)
        self.set_title()

    def save_vault(self, filename, password):
        """
        Write Vault contents to disk.
        """
        try:
            self._is_modified = False
            self.vault_file_name = filename
            self.vault_password = password
            self.vault.write_to_file(filename, password)
            self.statusbar.SetStatusText(_("Wrote Vault contents to disk"), 0)
            self.set_title()
        except RuntimeError:
            dial = wx.MessageDialog(self,
                                    _("Could not write Vault contents to disk"),
                                    _("Error writing to disk"),
                                    wx.OK | wx.ICON_ERROR
                                    )
            dial.ShowModal()
            dial.Destroy()

    def _clear_clipboard(self, match_text = None):
        if match_text:
            if not wx.TheClipboard.Open():
                raise RuntimeError(_("Could not open clipboard"))
            try:
                clip_object = wx.TextDataObject()
                if wx.TheClipboard.GetData(clip_object):
                    if clip_object.GetText() != match_text:
                        return
            finally:
                wx.TheClipboard.Close()
        wx.TheClipboard.Clear()
        self.statusbar.SetStatusText(_('Cleared clipboard'), 0)

    def _copy_to_clipboard(self, text, duration = None):
        if not wx.TheClipboard.Open():
            raise RuntimeError(_("Could not open clipboard"))
        try:
            clip_object = wx.TextDataObject(text)
            wx.TheClipboard.SetData(clip_object)
            if duration:
                wx.CallLater(duration * 1000, self._clear_clipboard, text)
        finally:
            wx.TheClipboard.Close()

    def _on_list_item_activated(self, event):
        """
        Event handler: Fires when user double-clicks a list entry.
        """
        index = event.GetIndex()
        self.list.deselect_all()
        self.list.Select(index, True)
        self.list.Focus(index)
        self._on_copy_password(None)

    def _on_list_column_click(self, event):
        """
        Event handler: Fires when user clicks on the list header.
        """
        col = event.GetColumn()
        if col == 0:
            #self.list.sort_function = lambda e1: e1.title.lower()
            self.list.sort_function = lambda e1: (e1.title.lower(), e1.user.lower(), e1.last_mod)
        elif col == 1:
            #self.list.sort_function = lambda e1: e1.user.lower()
            self.list.sort_function = lambda e1: (e1.user.lower(), e1.last_mod)
        elif col == 2:
            #self.list.sort_function = lambda e1: e1.group.lower()
            self.list.sort_function = lambda e1: (e1.group.lower(), e1.last_mod)
        elif col == 3:
            self.list.sort_function = lambda e1: (e1.last_mod, e1.title.lower(), e1.user.lower())
        else:
            return
        self.list.update_fields()

    def _on_list_contextmenu(self, dummy):
        self.PopupMenu(self._recordmenu)

    def _on_about(self, dummy):
        """
        Event handler: Fires when user chooses this menu item.
        """
        gpl_v2 = """This program is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software Foundation;
either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program;
if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA."""

        developers = (
                      "Christoph Sommer",
                      "Bjorn Edstrom (Python Twofish)",
                      "Brian Gladman (C Twofish)",
                      "Tim Kuhlman",
                      "David Eckhoff",
                      "Nick Verbeck"
                      )

        about = wx.adv.AboutDialogInfo()
        about.SetIcon(get_icon("loxodo-icon.png", 128, 128))
        about.SetName("Loxodo")
        about.SetVersion(__version__)
        about.SetCopyright("Copyright (C) 2008 Christoph Sommer <mail@christoph-sommer.de>")
        about.SetWebSite("http://www.christoph-sommer.de/loxodo")
        about.SetLicense(gpl_v2)
        about.SetDevelopers(developers)
        wx.adv.AboutBox(about)

    def _on_settings(self, dummy):
        """
        Event handler: Fires when user chooses this menu item.
        """
        settings = Settings(self)
        settings.ShowModal()
        settings.Destroy()
        self.list.update_fields()

    def _on_change_password(self, dummy):

        # FIXME: choose new SALT, B1-B4, IV values on password change? Conflicting Specs!

        dial = wx.PasswordEntryDialog(self,
                                _("New password"),
                                _("Change Vault Password")
                                )
        retval = dial.ShowModal()
        password_new = dial.GetValue().encode('latin1', 'replace')
        dial.Destroy()
        if retval != wx.ID_OK:
            return

        dial = wx.PasswordEntryDialog(self,
                                _("Re-enter new password"),
                                _("Change Vault Password")
                                )
        retval = dial.ShowModal()
        password_new_confirm = dial.GetValue().encode('latin1', 'replace')
        dial.Destroy()
        if retval != wx.ID_OK:
            return
        if password_new_confirm != password_new:
            dial = wx.MessageDialog(self,
                                    _('The given passwords do not match'),
                                    _('Bad Password'),
                                    wx.OK | wx.ICON_ERROR
                                    )
            dial.ShowModal()
            dial.Destroy()
            return

        self.vault_password = password_new
        self.statusbar.SetStatusText(_('Changed Vault password'), 0)
        self.mark_modified()

    def _on_export_csv(self, dummy):
        wildcard = "|".join((_("CSV files") + " (*.csv)", "*.csv", _("All files") + " (*.*)", "*.*"))
        dialog = wx.FileDialog(self, message=_("Save to CSV..."),
                               defaultDir=os.path.dirname(self.vault_file_name),
                               defaultFile='', wildcard=wildcard,
                               style=wx.FD_SAVE)
        with dialog:
            if dialog.ShowModal() != wx.ID_OK:
                return
            filename = dialog.GetPath()
        with open(filename, 'w', newline='', encoding='utf-8') as fp:
            writer = csv.writer(fp, dialect='unix')
            writer.writerow(('Group', 'Title', 'Username', 'Password', 'URL', 'Notes'))
            for r in self.vault.records:
                writer.writerow((r.group, r.title, r.user, r.passwd, r.url, r.notes.replace('\r\n', '\n')))

    def _on_merge_vault(self, dummy):
        wildcard = "|".join((_("Vault") + " (*.psafe3)", "*.psafe3", _("All files") + " (*.*)", "*.*"))
        dialog = wx.FileDialog(self, message = _("Open Vault..."), defaultFile = self.vault_file_name, wildcard = wildcard, style = wx.FD_OPEN)
        if dialog.ShowModal() != wx.ID_OK:
            return
        filename = dialog.GetPath()
        dialog.Destroy()

        dial = wx.PasswordEntryDialog(self,
                                _("Password"),
                                _("Open Vault...")
                                )
        retval = dial.ShowModal()
        password = dial.GetValue().encode('latin1', 'replace')
        dial.Destroy()
        if retval != wx.ID_OK:
            return

        merge_vault = None
        try:
            merge_vault = Vault(password, filename=filename)
        except BadPasswordError:
            dial = wx.MessageDialog(self,
                                    _('The given password does not match the Vault'),
                                    _('Bad Password'),
                                    wx.OK | wx.ICON_ERROR
                                    )
            dial.ShowModal()
            dial.Destroy()
            return
        except VaultVersionError:
            dial = wx.MessageDialog(self,
                                    _('This is not a PasswordSafe V3 Vault'),
                                    _('Bad Vault'),
                                    wx.OK | wx.ICON_ERROR
                                    )
            dial.ShowModal()
            dial.Destroy()
            return
        except VaultFormatError:
            dial = wx.MessageDialog(self,
                                    _('Vault integrity check failed'),
                                    _('Bad Vault'),
                                    wx.OK | wx.ICON_ERROR
                                    )
            dial.ShowModal()
            dial.Destroy()
            return

        oldrecord_newrecord_reason_pairs = []  # list of (oldrecord, newrecord, reason) tuples to merge
        for record in merge_vault.records:
            # check if corresponding record exists in current Vault
            my_record = None
            for record2 in self.vault.records:
                if record2.is_corresponding(record):
                    my_record = record2
                    break

            # record is new
            if not my_record:
                oldrecord_newrecord_reason_pairs.append((None, record, _("new")))
                continue

            # record is more recent
            if record.is_newer_than(my_record):
                oldrecord_newrecord_reason_pairs.append((my_record, record, _('updates "%s"') % my_record.title))
                continue

        dial = MergeFrame(self, oldrecord_newrecord_reason_pairs)
        retval = dial.ShowModal()
        oldrecord_newrecord_reason_pairs = dial.get_checked_items()
        dial.Destroy()
        if retval != wx.ID_OK:
            return

        for oldrecord, newrecord, reason in oldrecord_newrecord_reason_pairs:
            if oldrecord:
                oldrecord.merge(newrecord)
            else:
                self.vault.records.append(newrecord)
        self.mark_modified()

    def _on_exit(self, dummy):
        """
        Event handler: Fires when user chooses this menu item.
        """
        self.Close(True)  # Close the frame.

    def _on_edit(self, dummy):
        """
        Event handler: Fires when user chooses this menu item.
        """
        index = self.list.GetFirstSelected()
        if index == -1:
            return
        entry = self.list.displayed_entries[index]

        with RecordFrame(self) as recordframe:
            recordframe.vault_record = entry
            if recordframe.ShowModal() == wx.ID_OK:
                #self.mark_modified()
                self.save_vault2()
                # stay on the entry
                wx.ListCtrl.Refresh(self.list)

    def _on_add(self, dummy):
        """
        Event handler: Fires when user chooses this menu item.
        """
        entry = Record.create()

        recordframe = RecordFrame(self)
        recordframe.vault_record = entry
        if recordframe.ShowModal() != wx.ID_CANCEL:
            self.vault.records.append(entry)
            self.mark_modified()
        recordframe.Destroy()

    def _on_add_duplicate(self, dummy):
        index = self.list.GetFirstSelected()
        if index == -1:
            return
        entry2 = self.list.displayed_entries[index]
        entry = duplicate_record(entry2)

        with RecordFrame(self) as recordframe:
            recordframe.vault_record = entry
            if recordframe.ShowModal() == wx.ID_OK:
                self.vault.records.append(entry)
                #self.mark_modified()
                self.save_vault2()
                self.list.insert_index(index + 1, entry)

    def _on_delete(self, dummy):
        """
        Event handler: Fires when user chooses this menu item.
        """
        index = self.list.GetFirstSelected()
        if index == -1:
            return
        entry = self.list.displayed_entries[index]

        dial = wx.MessageDialog(
                self,
                _("Are you sure you want to delete this record? There is no way to undo this action."),
                _("Really delete record?"),
                wx.YES_NO | wx.YES_DEFAULT | wx.ICON_QUESTION
                )
        retval = dial.ShowModal()
        dial.Destroy()
        if retval != wx.ID_YES:
            return

        self.vault.records.remove(entry)
        #self.mark_modified()
        self.save_vault2()
        self.list.delete_index(index)

    def _on_copy_username(self, dummy):
        """
        Event handler: Fires when user chooses this menu item.
        """
        index = self.list.GetFirstSelected()
        if index == -1:
            return
        entry = self.list.displayed_entries[index]
        try:
            self._copy_to_clipboard(entry.user)
            self.statusbar.SetStatusText(_('Copied username of "%s" to clipboard') % entry.title, 0)
        except RuntimeError:
            self.statusbar.SetStatusText(_('Error copying username of "%s" to clipboard') % entry.title, 0)

    def _on_copy_password(self, dummy):
        """
        Event handler: Fires when user chooses this menu item.
        """
        index = self.list.GetFirstSelected()
        if index == -1:
            return
        entry = self.list.displayed_entries[index]
        try:
            self._copy_to_clipboard(entry.passwd, duration=10)
            self.statusbar.SetStatusText(_('Copied password of "%s" to clipboard') % entry.title, 0)
        except RuntimeError:
            self.statusbar.SetStatusText(_('Error copying password of "%s" to clipboard') % entry.title, 0)

    def _on_totp(self, dummy):
        if mintotp:
            index = self.list.GetFirstSelected()
            if index == -1:
                return
            entry = self.list.displayed_entries[index]
            passwd2 = entry.passwd.replace(' ', '')     # A B -> AB
            m = re.match(r'([a-z0-9]+):', passwd2, flags=re.A + re.I)   # sha1:....
            if m:
                digest = m.group(1)
                passwd2 = passwd2[len(digest) + 1:]
            else:
                digest = 'sha1'
            try:
                totp = mintotp.totp(passwd2, digest=digest)
                self._copy_to_clipboard(totp, duration=10)
                totp2 = ' '.join([totp[i:i + 3] for i in range(0, len(totp), 3)])   # 123 456 ...
                self.statusbar.SetStatusText(f'TOTP({digest}): {totp2}', 0)
            except (RuntimeError, binascii.Error, ValueError):
                # ValueError: totp: bad digest
                self.statusbar.SetStatusText(_('Error copying TOTP of "%s" to clipboard') % entry.title, 0)

    def _on_open_url(self, dummy):
        """
        Event handler: Fires when user chooses this menu item.
        """
        index = self.list.GetFirstSelected()
        if index == -1:
            return
        entry = self.list.displayed_entries[index]
        try:
            webbrowser.open(entry.url)
        except ImportError:
            self.statusbar.SetStatusText(_('Could not load python module "webbrowser" needed to open "%s"') % entry.url, 0)

    def _on_search_for_entry(self, dummy):
        """
        Event handler: Fires when user chooses this menu item.
        """
        self._searchbox.SetFocus()
        self._searchbox.SelectAll()

    def _on_search_do(self, dummy):
        """
        Event handler: Fires when user interacts with search field
        """
        self.list.set_filter(self._searchbox.GetValue())

    def _on_search_cancel(self, dummy):
        """
        Event handler: Fires when user interacts with search field
        """
        self._searchbox.SetValue("")

    def _on_frame_close(self, dummy):
        """
        Event handler: Fires when user closes the frame
        """
        self.Destroy()

    def _on_searchbox_char(self, evt):
        """
        Event handler: Fires when user presses a key in self._searchbox
        """
        keycode = evt.GetKeyCode()
        # If "Enter" was pressed, ignore key and copy password of first match
        if keycode == wx.WXK_RETURN:
            self._on_copy_password(None)
            return

        # If "Escape" was pressed, ignore key and clear the Search box
        if keycode == wx.WXK_ESCAPE:
            self._on_search_cancel(None)
            return

        # If "Up" or "Down" was pressed, ignore key and focus self.list
        if keycode in (wx.WXK_UP, wx.WXK_DOWN):
            self.list.SetFocus()
            return
        if evt.GetModifiers() == wx.MOD_CONTROL and keycode == wx.WXK_CONTROL_U:
            self._on_copy_username(None)
            return

        # Ignore all other keys
        evt.Skip()
