################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2022  flexiWAN Ltd.
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

import importlib.util
import json
import os
import shlex
import stat
import subprocess
import threading
import time

class CalledProcessSigTerm(subprocess.CalledProcessError):
    """ Raised when executed command is terminated by SIGTERM """
    pass

def pid_of(process_name):
    """Get pid of process.

    :param process_name:   Process name.

    :returns:           process identifier.
    """
    try:
        # There is an issue with pidof on Ubuntu 20.04 so replaced it with pgrep.
        pid = subprocess.check_output(['pgrep', '-x', process_name]).decode().strip()
    except subprocess.CalledProcessError as e:
        # if check_output returns negative exit code it means that command was killed by OS signal, like SIGTERM, SIGKILL, etc.
        # and we can't determine if process is running so raise Exception instead
        if e.returncode < 0:
            raise CalledProcessSigTerm(e.returncode, e.cmd)
        else:
            pid = None
    return pid

def kill_process(name, timeout=10):
    os.system(f'sudo killall {name}')
    while timeout >= 0:
        if pid_of(name):
            timeout -= 1
            time.sleep(1)
        else:
            return True
    return False

_VPP_PROCESS_NAMES = ('vpp_main', 'vpp')
_vpp_pid_cache = None   # PID (string, as returned by pgrep) of the last found VPP process

def _is_vpp_pid_alive(pid):
    """Check that process 'pid' exists and it is still VPP (PIDs might be reused)."""
    try:
        os.kill(int(pid), 0)
    except PermissionError:
        pass        # process exists, but belongs to other user
    except (OSError, ValueError, TypeError):
        return False
    try:
        with open(f'/proc/{pid}/comm') as f:
            return f.read().strip() in _VPP_PROCESS_NAMES
    except OSError:
        return False

def vpp_pid():
    """Get pid of VPP process.
    The PID found by 'pgrep' is cached. The cached value is validated by
    os.kill(pid, 0) and /proc/<pid>/comm, so 'pgrep' is spawned only if VPP
    was restarted or stopped.

    :returns:           process identifier.
    """
    global _vpp_pid_cache
    pid = _vpp_pid_cache
    if pid and _is_vpp_pid_alive(pid):
        return pid

    _vpp_pid_cache = None
    pid = pid_of('vpp_main')
    if not pid:
        pid = pid_of('vpp')

    if pid and pid.isdigit():   # don't cache multiple PIDs, if pgrep found few processes
        _vpp_pid_cache = pid
    return pid

def vpp_does_run():
    """Check if VPP is running.

    :returns:           Return 'True' if VPP is running.
    """
    return True if vpp_pid() else False

class FwYamlFileCache:
    """Cache of parsed yaml files. The parsed content of file is reused
    as long as the file modification time, change time, size and inode
    are not changed. It is thread safe.
    IMPORTANT: the returned objects are shared, the caller must not modify them!
    """
    def __init__(self):
        self.cache = {}   # file name -> (file signature, parsed yaml)
        self.lock  = threading.Lock()

    def load(self, fname):
        import yaml     # import here to keep this module light for users that don't need yaml

        st = os.stat(fname)
        signature = (st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_ino)
        with self.lock:
            cached = self.cache.get(fname)
            if cached and cached[0] == signature:
                return cached[1]
        with open(fname, 'r') as stream:
            content = yaml.safe_load(stream)
        with self.lock:
            self.cache[fname] = (signature, content)
        return content

    def forget_except(self, fnames):
        """Removes from cache all files except the provided."""
        with self.lock:
            for fname in set(self.cache) - set(fnames):
                del self.cache[fname]

SYS_CLASS_NET = '/sys/class/net'

def sys_class_net_lines():
    """Returns list of '<name> -> <link target>' strings for entries of the
    /sys/class/net folder, e.g.:
        'enp0s3 -> ../../devices/pci0000:00/0000:00:03.0/net/enp0s3'
    The strings are the same as the end of lines printed by 'ls -l /sys/class/net',
    so they can be parsed in the same way, but without spawning shell processes.
    Entries that are not symbolic links (e.g. bonding_masters) are represented by name only.
    Raises OSError if /sys/class/net can't be read.
    """
    lines = []
    for name in sorted(os.listdir(SYS_CLASS_NET)):
        try:
            lines.append(f'{name} -> {os.readlink(os.path.join(SYS_CLASS_NET, name))}')
        except OSError:
            lines.append(name)
    return lines

def sys_class_net_grep(pattern, exclude=None):
    """Emulates 'ls -l /sys/class/net | grep -v <exclude> | grep <pattern>'
    for fixed strings (not regular expressions).

    :returns: list of matching lines (see sys_class_net_lines()), [] on no match or error.
    """
    try:
        lines = sys_class_net_lines()
    except OSError:
        return []
    return [l for l in lines if pattern in l and not (exclude and exclude in l)]

def sys_class_net_read(if_name, attribute):
    """Reads /sys/class/net/<if_name>/<attribute> file.

    :returns: stripped content of the file or None if it can't be read,
              e.g. if interface does not exist or it is down (carrier).
    """
    if not if_name or '/' in if_name or if_name in ('.', '..'):
        return None
    try:
        with open(os.path.join(SYS_CLASS_NET, if_name, attribute)) as f:
            return f.read().strip()
    except OSError:
        return None

def sys_class_net_driver(if_name):
    """Returns name of the kernel driver bound to the interface device
    (basename of /sys/class/net/<if_name>/device/driver link), or None if
    the interface has no device driver, e.g. virtual interfaces.
    """
    if not if_name or '/' in if_name or if_name in ('.', '..'):
        return None
    try:
        return os.path.basename(os.readlink(os.path.join(SYS_CLASS_NET, if_name, 'device', 'driver')))
    except OSError:
        return None

def ensure_private_dir(path, mode=0o700):
    """Create directory if needed and ensure it is owned by the effective user
    and is not accessible by others (default 0700).
    Raises PermissionError if the path exists and is not a directory owned by us
    (e.g. was pre-created by another local user or is a symlink).
    """
    os.makedirs(path, mode=mode, exist_ok=True)
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
        raise PermissionError(f"{path}: is not a directory owned by uid {os.geteuid()}")
    if stat.S_IMODE(st.st_mode) != mode:
        os.chmod(path, mode)
    return path

def open_private_file(path, flags=os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode=0o600):
    """Open file with restrictive permissions and return file descriptor.
    The permissions are enforced also for file that exists already.
    Symbolic links are not followed.
    """
    fd = os.open(path, flags | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
    except Exception:
        os.close(fd)
        raise
    return fd

def write_private_file(path, content, mode=0o600):
    """Write the 'content' (str or bytes) into file created with restrictive permissions."""
    fd = open_private_file(path, mode=mode)
    with os.fdopen(fd, 'wb' if isinstance(content, bytes) else 'w') as f:
        f.write(content)

def touch_private_file(path, mode=0o600):
    """Create file if it does not exist and ensure it has restrictive permissions.
    Errors are ignored (e.g. symbolic link, read-only filesystem), as this is
    a best effort hardening that should not break the caller.
    """
    try:
        os.close(open_private_file(path, flags=os.O_WRONLY | os.O_CREAT, mode=mode))
    except OSError:
        pass

def run_linux_commands(commands, exception_on_error=True):
    for command in commands:
        ret = os.system(command)
        if ret and exception_on_error:
            raise Exception(f'failed to run "{command}". error code is {ret}')
    return True

def run_fwagent_command(cmd, appl_id=None):
    '''Wrapper for the "fwagent ..." command that applications might use to access running fwagent
    daemon in order to monitor or to configure its various aspects.
    This wrapper ensures that no deadlock happen between "fwagent ..." shell process and daemon,
    if "fwagent ..." is called in context of the daemon process.
        For example, the deadlock might happen, when the daemon receives 'start-router' request,
    locks system, starts router and notifies available applications of "on_router_is_started" event.
    While handling this event, some application might invoke "fwagent configure router interfaces
    create -addr ..." shell command, and the shell process will be blocked on the system lock,
    while trying to modify router configuration. That creates the deadlock.

    :param cmd:         Options of the 'fwagent' command to be run - either list of
                        arguments or string of space separated arguments.
                        The command is run without shell, so no shell features
                        (pipes, redirections, variables) are supported.
    :param appl_id:     Application identifier. It is stored in the 'identifier' field
                        of the FwApplicationInterface abstract class.
    '''
    exec_cmd = ['fwagent']
    if appl_id:
        exec_cmd.append(f'--appl_id={appl_id}')
    exec_cmd += list(cmd) if isinstance(cmd, (list, tuple)) else shlex.split(cmd)
    out      = subprocess.check_output(exec_cmd, stderr=subprocess.STDOUT).decode()
    out_dict = json.loads(out) if out else {}
    return out_dict

def load_python_module(entry_point, module_name):
    module = None
    for root, dirs, files in os.walk(entry_point):
        for name in files:
            if module_name in name:
                spec = importlib.util.spec_from_file_location(module_name, f'{root}/{name}')
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                break

        # If the inner loop completes without encountering
        # the break statement then the following else
        # block will be executed and outer loop will
        # continue to the next iteration
        else:
            continue

        # If the inner loop terminates due to the
        # break statement, the else block will not
        # be executed and the following break
        # statement will terminate the outer loop also
        break

    return module
