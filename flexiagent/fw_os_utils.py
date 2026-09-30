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

def vpp_pid():
    """Get pid of VPP process.

    :returns:           process identifier.
    """
    pid = pid_of('vpp_main')
    if not pid:
        pid = pid_of('vpp')

    return pid

def vpp_does_run():
    """Check if VPP is running.

    :returns:           Return 'True' if VPP is running.
    """
    return True if vpp_pid() else False

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
