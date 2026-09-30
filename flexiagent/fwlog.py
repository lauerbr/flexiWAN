#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2019  flexiWAN Ltd.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
################################################################################

import os
import syslog
import traceback

from datetime import datetime

from fw_redact import redact_str

FWLOG_LEVEL_INFO  = 0x01
FWLOG_LEVEL_DEBUG = 0x0F
FWLOG_LEVEL_TRACE = 0xFF

class Fwlog:
    """This is logging class representation.

    :param level: Start logging from this severity level.
    """
    def __init__(self, name, level=0x00):
        """Constructor method
        """
        self.level = level
        self.to_syslog_enabled   = True
        self.to_terminal_enabled = True
        self.name                = name
    
    def __str__(self):
        return self.name

    def _build_log_line_prefix(self, add_date=False):
        # We prefix every log line with name of class that invoked the log print.
        #
        date = ''
        if add_date:
            # "Jul  6 04:14:30" - like in syslog except zero padding of day
            date = datetime.today().strftime('%b %d %H:%M:%S') + ': '
        return date

    def _log_message(self, log_message, to_terminal, to_syslog, print_bt, min_level=None, prefix='', suffix='', **kwargs):
        """Redacts the message and logs it, if the logger level is not lower than 'min_level'.

        :param log_message:       Message contents.
        :param to_terminal:       Print to terminal.
        :param to_syslog:         Print to syslog.
        :param print_bt:          Print backtrace after the log_message. For debugging.
        :param min_level:         The message is logged only if logger level is equal or above it.
                                  If None, the message is always logged.
        :param prefix:            The prefix to be added to the message, e.g. "error: ".
        :param suffix:            The suffix to be added to the message.
        :param kwargs:            Additional arguments for _log(), e.g. truncate_long_line.

        :returns: None.
        """
        if min_level is not None and self.level < min_level:
            return
        self._log(prefix + redact_str(log_message) + suffix, to_terminal, to_syslog, print_bt=print_bt, **kwargs)

    # The excep(), error(), warning(), info(), debug() and trace() methods have
    # same parameters:
    #   :param log_message:       Message contents.
    #   :param to_terminal:       Print to terminal.
    #   :param to_syslog:         Print to syslog.
    #   :param print_bt:          Print backtrace after the log_message. For debugging.
    #
    def excep(self, log_message, to_terminal=True, to_syslog=True, print_bt=False):
        """Print exception message."""
        self._log_message(log_message, to_terminal, to_syslog, print_bt, prefix="excep: ", truncate_long_line=False)

    def error(self, log_message, to_terminal=True, to_syslog=True, print_bt=False):
        """Print error message."""
        self._log_message(log_message, to_terminal, to_syslog, print_bt, prefix="error: ", truncate_long_line=False)

    def warning(self, log_message, to_terminal=True, to_syslog=True, print_bt=False):
        """Print warning message."""
        self._log_message(log_message, to_terminal, to_syslog, print_bt, prefix="*** warning: ", suffix=" ***", truncate_long_line=False)

    def info(self, log_message, to_terminal=True, to_syslog=True, print_bt=False):
        """Print info message."""
        self._log_message(log_message, to_terminal, to_syslog, print_bt, min_level=FWLOG_LEVEL_INFO)

    def debug(self, log_message, to_terminal=True, to_syslog=True, print_bt=False):
        """Print debug message."""
        self._log_message(log_message, to_terminal, to_syslog, print_bt, min_level=FWLOG_LEVEL_DEBUG)

    def trace(self, log_message, to_terminal=True, to_syslog=True, print_bt=False):
        """Print trace message."""
        self._log_message(log_message, to_terminal, to_syslog, print_bt, min_level=FWLOG_LEVEL_TRACE)

    def is_debug_enabled(self):
        """Returns True if debug messages are logged. Use it to avoid building
        expensive debug messages that are not going to be logged anyway.
        """
        return self.level >= FWLOG_LEVEL_DEBUG

    def set_level(self, level):
        """Set severity level to show messages that are above this level.

        :param level:             Severity level.

        :returns: None.
        """
        self.level = level

    def set_target(self, to_syslog=True, to_terminal=True):
        """Set default log output targets.

        :param to_syslog:         Output to syslog.
        :param to_terminal:       Output to terminal.

        :returns: None.
        """
        self.to_syslog_enabled   = to_syslog
        self.to_terminal_enabled = to_terminal


class FwLogSyslog(Fwlog):
    def __init__(self, level=FWLOG_LEVEL_INFO, identification="fwagent", huge_line_file=None):
        """Constructor method
        """
        Fwlog.__init__(self, level=level, name="syslog(ident=fwagent)")
        syslog.openlog(ident=identification)

        self.huge_line_log = None
        if huge_line_file:
            self.set_huge_line_file(huge_line_file)

    def __str__(self):
        return "syslog" if not self.huge_line_log else f"syslog & {str(self.huge_line_log)}"

    def set_huge_line_file(self, huge_line_log_filename):
        # Prevent "Permission denied" when is invoked by non-root (e.g. 'fwagent show', 'fwdump', etc)
        if not os.path.exists(huge_line_log_filename) or os.access(huge_line_log_filename, os.W_OK):
            self.huge_line_log = FwLogFile(huge_line_log_filename)

    def _log(self, log_message, to_terminal=True, to_syslog=True, truncate_long_line=True, print_bt=False):
        """Print log message.

        :param log_message:       Message contents.
        :param to_terminal:       Print to terminal.
        :param to_syslog:         Print to syslog.
        :param print_bt:          Print backtrace after the log_message. For debugging.

        :returns: None.
        """
        stack = ''.join(traceback.format_stack()) if print_bt else ""

        if to_terminal and self.to_terminal_enabled:
            print(log_message)
            if stack:
                print(stack)

        if to_syslog and self.to_syslog_enabled:

            try:
                chunk_len = 4096  # Should be big enough to include `add-tunnel` with certificate for IKEv2 tunnels

                # Prepend prefix (name of class that produced log line) and truncate the log line to 4K.
                # Note syslog discards lines beyond 8K by default, so take a caution if you modify this code!
                #
                log_message = self._build_log_line_prefix() + log_message
                if len(log_message) < chunk_len:
                    syslog.syslog(log_message)
                    return

                if truncate_long_line:
                    truncated_message = log_message[0:chunk_len] + ' <truncated>'
                    syslog.syslog(truncated_message)
                    if self.huge_line_log:
                        self.huge_line_log._log(log_message)
                    return

                msgs = [log_message[i:i+chunk_len] for i in range(0, len(log_message), chunk_len)]
                for idx, msg in enumerate(msgs):
                    if idx == 0:
                        syslog.syslog(msg)
                    else:
                        syslog.syslog(">> " + msg)
            finally:
                if stack:
                    syslog.syslog(stack)

class FwLogDevNull(Fwlog):
    def __init__(self, identification="fwagent"):
        """Constructor method
        """
        Fwlog.__init__(self, name=f"dev_null(ident={identification})")

    def __str__(self):
        return "dev_null"

    def _log(self, log_message, to_terminal=True, to_syslog=True, truncate_long_line=True, print_bt=False):
        """Print log message.

        :param log_message:       Message contents.
        :param to_terminal:       Print to terminal.
        :param to_syslog:         Print to syslog.
        :param print_bt:          Print backtrace after the log_message. For debugging.

        :returns: None.
        """
        return


class FwLogFile(Fwlog):
    def __init__(self, filename, max_size=100000000, level=FWLOG_LEVEL_INFO):
        """Constructor method
        """
        Fwlog.__init__(self, level=level, name=filename)
        self.filepath, self.filename = os.path.split(filename)
        self.max_size = max_size  # 10 MB by default
        self.cur_size = 0
        self.to_terminal_enabled = False

        if os.path.exists(filename):
            self.cur_size = os.path.getsize(filename)
        self.f = self._open(filename, 'a')

    def __str__(self):
        return os.path.join(self.filepath, self.filename)

    def _open(self, filename, mode):
        """Open log file. New files are created with 0640 permissions,
        as logs might include sensitive information."""
        flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if mode == 'a' else os.O_TRUNC)
        return os.fdopen(os.open(filename, flags, 0o640), mode)

    def _rotate(self):
        self.f.close()
        main_filename = os.path.join(self.filepath, self.filename)
        backup_filename = os.path.join(self.filepath, self.filename + '.1')
        os.rename(main_filename, backup_filename)
        self.f = self._open(main_filename, 'w')
        self.cur_size = 0

    def _log(self, log_message, to_terminal=True, to_syslog=True, truncate_long_line=False, print_bt=False):
        """Print log message.

        :param log_message:       Message contents.
        :param to_terminal:       Print to terminal - NOT IN USE for FwLogFile
        :param to_syslog:         Print to syslog
        :param print_bt:          Print backtrace after the log_message. For debugging.

        :returns: None.
        """
        stack = ''.join(traceback.format_stack()) if print_bt else ""

        if to_terminal and self.to_terminal_enabled:
            print(log_message)
            if stack:
                print(stack)

        log_prefix  = self._build_log_line_prefix(add_date=True)
        log_message = log_message.replace('\r\n', '#012').replace('\n', '#012')  # Mimic syslog format
        log_message = log_prefix + log_message

        if to_syslog and self.to_syslog_enabled:
            try:
                # Split long line into chunks of 8K to make it compatible with various editors.
                #
                chunk_len = 8000
                total_len = len(log_message)

                if total_len <= chunk_len:
                    self.f.write(log_message + '\n')
                elif truncate_long_line:
                    truncated_msg = log_message[0:chunk_len] + f" <{total_len} bytes were truncated to {chunk_len}>\n"
                    self.f.write(log_prefix + truncated_msg)
                else:
                    msgs = [log_message[i:i+chunk_len] for i in range(0, total_len, chunk_len)]
                    self.f.write(log_prefix + "--multiline-start--\n")
                    for msg in msgs:
                        self.f.write(msg + '\n')
                    self.f.write(log_prefix + "--multiline-end--\n")
                self.f.flush()
                self.cur_size += total_len

            finally:
                if stack:
                    self.f.write(stack + '\n')
                    self.f.flush()
                if self.cur_size > self.max_size:
                    self._rotate()


class FwObjectLogger:
    """Wraps the FwLog (by aggregation), while keeping object specific information,
    e.g. name of object class. This name is prepended to the log lines.
    For example if class FwCfgRequestHandler inherits from the FwObjectLogger,
    the FwCfgRequestHandler::log() will print "FwCfgRequestHandler: ..." lines
    into log.
    """
    def __init__(self, object_name, log=None):
        import fwglobals
        self.log = log if log else fwglobals.log if fwglobals.g_initialized else FwLogSyslog()
        self.prefix = f"{object_name}: "

    def __str__(self):
        return str(self.log)

    def __ne__(self, other):
        return str(self.log) != str(other.log)

    def is_debug_enabled(self):
        is_debug_enabled = getattr(self.log, 'is_debug_enabled', None)
        return is_debug_enabled() if is_debug_enabled else True

    def excep(self, log_message, to_terminal=True, to_syslog=True, print_bt=False):
        self.log.excep(self.prefix + log_message, to_terminal=to_terminal, to_syslog=to_syslog, print_bt=print_bt)

    def error(self, log_message, to_terminal=True, to_syslog=True, print_bt=False):
        self.log.error(self.prefix + log_message, to_terminal=to_terminal, to_syslog=to_syslog, print_bt=print_bt)

    def warning(self, log_message, to_terminal=True, to_syslog=True, print_bt=False):
        self.log.warning(self.prefix + log_message, to_terminal=to_terminal, to_syslog=to_syslog, print_bt=print_bt)

    def info(self, log_message, to_terminal=True, to_syslog=True, print_bt=False):
        self.log.info(self.prefix + log_message, to_terminal=to_terminal, to_syslog=to_syslog, print_bt=print_bt)

    def debug(self, log_message, to_terminal=True, to_syslog=True, print_bt=False):
        self.log.debug(self.prefix + log_message, to_terminal=to_terminal, to_syslog=to_syslog, print_bt=print_bt)

    def trace(self, log_message, to_terminal=True, to_syslog=True, print_bt=False):
        self.log.trace(self.prefix + log_message, to_terminal=to_terminal, to_syslog=to_syslog, print_bt=print_bt)
