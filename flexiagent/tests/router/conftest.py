import pytest
import os
import glob
import shutil
from datetime import datetime
import psutil
import sys, select

CODE_ROOT = os.path.realpath(__file__).replace('\\', '/').split('/tests/')[0]
sys.path.append(CODE_ROOT)
import fwutils
import fwwifi

from build.config import config
kill_cmd = config.commands.kill.cmd

@pytest.fixture
def netplan_backup():
    orig_yamls = glob.glob("/etc/netplan/*.yaml")+ \
                glob.glob("/lib/netplan/*.yaml") + \
                glob.glob("/run/netplan/*.yaml")
    #taking backup of original netplan yaml files
    for file in orig_yamls:
        orig_yaml = file.replace('yaml', 'yaml.backup_pytest')
        shutil.move(file, orig_yaml)

    yield

    os.system('rm -f /etc/netplan/*.yaml')
    orig_yamls = glob.glob("/etc/netplan/*.backup_pytest")+ \
                glob.glob("/lib/netplan/*.backup_pytest") + \
                glob.glob("/run/netplan/*.backup_pytest")
    for file in orig_yamls:
        orig_yaml = file.replace('yaml.backup_pytest', 'yaml')
        shutil.move(file, orig_yaml)
    os.system(f'sudo {kill_cmd}')

@pytest.fixture(autouse=True)
def fixture_globals(currpath):
    start_time = datetime.now()

    yield

    end_time = datetime.now()
    print("Test: %s. Elapsed: %s" % (currpath, str(end_time - start_time)))

@pytest.fixture
def currpath(request):
    return str(request.node.fspath)

@pytest.fixture(autouse=True)
def run_lte(currpath):
    if 'lte_' in currpath:
        exists = False
        for nicname, addrs in psutil.net_if_addrs().items():
            driver = fwutils.get_ethtool_value(nicname, 'driver')
            if driver and driver in ['cdc_mbim', 'qmi_wwan']:
                exists = True

                # store LTE dev it in a global scope
                pytest.lte_dev_id = fwutils.build_interface_dev_id(nicname)

                break
        if not exists:
            pytest.skip('LTE card does not exist on the current machine')
    yield

@pytest.fixture(autouse=True)
def run_wifi(currpath):
    if 'wifi_' in currpath:
        exists = False
        for nicname, addrs in psutil.net_if_addrs().items():
            if fwwifi.is_wifi_interface(nicname):
                exists = True
                break
        if not exists:
            pytest.skip('WiFi card does not exist on the current machine')
    yield

@pytest.fixture
def fqdn_fast_resolution():
    """Fixture to temporarily modify FQDN resolution interval in the YAML config file for testing"""
    filename = "agent_conf.fast_fqdn.yaml"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    file_path = os.path.join(parent_dir, filename)

    yield 10, file_path  # Return the interval value set for testing
