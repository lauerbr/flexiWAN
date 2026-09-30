#! /bin/bash

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2023  flexiWAN Ltd.
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

# Exports
export DEBIAN_FRONTEND=noninteractive

# Constants
AGENT_SERVICE_FILE='/lib/systemd/system/flexiwan-router.service'
AGENT_SERVICE='flexiwan-router'
SCRIPT_NAME="$(basename $BASH_SOURCE)"
KERNEL_BASE_VERSION="5.15.0-124"
KERNEL_FULL_VERSION="${KERNEL_BASE_VERSION}-generic"
KERNEL_HWE_APT_METAPKG_NAME="linux-generic-hwe-$(lsb_release -rs)"
KERNEL_HWE_APT_PKGS_LIST="linux-headers-$KERNEL_FULL_VERSION linux-image-$KERNEL_FULL_VERSION"
KERNEL_HWE_APT_PKGS_LIST="$KERNEL_HWE_APT_PKGS_LIST linux-modules-$KERNEL_FULL_VERSION"
KERNEL_HWE_APT_PKGS_LIST="$KERNEL_HWE_APT_PKGS_LIST linux-modules-extra-$KERNEL_FULL_VERSION linux-firmware"
KERNEL_HWE_APT_PKGS_LIST="$KERNEL_HWE_APT_PKGS_LIST intel-microcode amd64-microcode"


# Constants passed to the script by fwagent
AGENT_LOG_FILE="$1"
JOB_ID="$2"

log() {
    echo `date +'%b %e %R:%S'`" $HOSTNAME $SCRIPT_NAME:" "$@" >> "$AGENT_LOG_FILE" 2>&1
}

update_jobs_db() {
    log "$1": "$2"
    fwagent configure jobs update --job_id $JOB_ID --request 'upgrade-linux-sw' --command "$1" --job_error "$2"
}

handle_upgrade_failure() {
    log "Kernel upgrade failed"
    update_jobs_db "$1" "$2"
    systemctl restart "$AGENT_SERVICE"
}

update_service_conf_file() {
    if [ ! -f "$AGENT_SERVICE_FILE" ]; then
        update_jobs_db "update service.unit file" "${AGENT_SERVICE_FILE} not found"
        return 1
    fi

    action="$1"

    # When $action is set to modify, don't add the configuration if it already exists.
    # When $action is set to restore, don't remove the configuration if it does not exist.
    kill_mode_conf=`grep KillMode=process "$AGENT_SERVICE_FILE"`
    if [[ "$action" == "modify" && -z "$kill_mode_conf" ]] ; then
        log "INFO: Modifying $AGENT_SERVICE_FILE to add KillMode=process"
        echo -e "\n[Service]\nKillMode=process" >> "$AGENT_SERVICE_FILE"
        systemctl daemon-reload
    elif [[ "$action" == "restore" && ! -z "$kill_mode_conf" ]] ; then
        log "INFO: Restoring $AGENT_SERVICE_FILE"
        sed -i -e '/KillMode=process/d' $AGENT_SERVICE_FILE
        sed -i -e '${/\[Service\]/d}' $AGENT_SERVICE_FILE
        sed -i -e '${/^$/d}' $AGENT_SERVICE_FILE
        systemctl daemon-reload
    fi
}

clean_and_reboot() {
    update_service_conf_file restore
    ret=${PIPESTATUS[0]}
    if [ ${ret} != 0 ]; then
        update_jobs_db "upgrade linux" "update_service_conf_file failed: ${ret}"
    fi
    reboot
}

check_installed_kernel_hwe() {
    dpkg-query -W -f='${Status}\n' $KERNEL_HWE_APT_METAPKG_NAME 2>/dev/null | grep -q "install ok installed"
    kernel_hwe_installed=${PIPESTATUS[0]}
    if [ $kernel_hwe_installed -eq 0 ] ; then
        log "INFO: $KERNEL_HWE_APT_METAPKG_NAME already installed."
        return 1
    fi

    ls /lib/modules | grep -q "${KERNEL_BASE_VERSION%%-*}"
    kernel_hwe_installed=${PIPESTATUS[0]}
    if [ $kernel_hwe_installed -eq 0 ] ; then
        log "INFO: HWE kernel already installed (currently running $(uname -r))."
        return 1
    fi
}

kernel_hwe_upgrade() {
    log "INFO: Running apt-get update ..."
    res=$(apt-get update --error-on=any)
    if [ ${PIPESTATUS[0]} != 0 ]; then
        log "WARN: apt update failed. Trying to solve it by installing/upgrading ca-certificates package. res=${res}"
        res=$(apt-get install ca-certificates)
        if [ ${PIPESTATUS[0]} != 0 ]; then
            log "Error: failed upgrading ca-certificates package. res=${res}"
            handle_upgrade_failure 'update debian repositories' 'Failed to update debian repositores'
            exit 1
        fi
        log "Running apt-get update again"
        res=$(apt-get update --error-on=any)
        if [ ${PIPESTATUS[0]} != 0 ]; then
            log "Error: failed second apt-get update. res=${res}"
            handle_upgrade_failure 'update debian repositories' 'Failed to update debian repositores again'
            exit 1
        fi
    fi

    log "INFO: Preparing WiFi drivers to be rebuild when installing new kernel..."
    kernel_latest_installed_version="$(ls /lib/modules | sort -rV | head -n 1)"
    wifi_drivers_list="ath10k ath9k"
    wifi_drivers_version="5.10.16-1"
    for driver in $wifi_drivers_list ; do
        wifi_drivers_name="$driver"
        wifi_drivers_name_and_version="${wifi_drivers_name}-${wifi_drivers_version}"
        apt_pkg_name="flexiwan-${driver}-dkms"
        wifi_drivers_src_dir="/usr/src/${wifi_drivers_name_and_version}"
        wifi_drivers_dkms_config="${wifi_drivers_src_dir}/dkms.conf"

        # Check if the installed WiFi driver has the patched code (compilation issue + DKMS fix)
        # If not, nothing to do
        grep -q "^MAKE\[0\]=.*; make KLIB=/lib/modules/\${kernelver}" $wifi_drivers_dkms_config
        wifi_drivers_patched=$?
        if [[ -d $wifi_drivers_src_dir && $wifi_drivers_patched -eq 1 ]] ; then
            log "INFO: Patching $apt_pkg_name WiFi drivers to be rebuild when installing new kernel..."
            # Use unpredictable private directory instead of fixed /tmp path,
            # as this script runs as root.
            temp_dir="$(mktemp -d "/tmp/${apt_pkg_name}_${wifi_drivers_version}.XXXXXX")"
            if [ -z "$temp_dir" ] || ! cd "$temp_dir" ; then
                log "Error: failed to create temporary directory for $apt_pkg_name"
                continue
            fi
            chown _apt:root "$temp_dir"
            apt-mark unhold "$apt_pkg_name"
            apt download "${apt_pkg_name}=${wifi_drivers_version}"
            ar xv "${apt_pkg_name}_${wifi_drivers_version}"_*.deb
            tar xJf data.tar.xz -C /
            chown root:root -R "$wifi_drivers_src_dir"
            cd
            rm -rf "$temp_dir"
        else
            log "INFO: No need to patch $apt_pkg_name WiFi drivers."
        fi
    done

    log "INFO: Running apt install -y $KERNEL_HWE_APT_PKGS_LIST ..."
    apt install -y $KERNEL_HWE_APT_PKGS_LIST
}


# Upgrade process
log "Starting linux upgrade process..."

date_now=$(date "+%F %H:%M:%S")
log "Starting Kernel HWE upgrade at ${date_now}"

# Before doing anything, check if HWE kernel is already installed.
# If so, nothing needs to be done.
check_installed_kernel_hwe
ret=${PIPESTATUS[0]}
date_now=$(date "+%F %H:%M:%S")
if [ ${ret} != 0 ]; then
    log "INFO: Kernel HWE upgrade finished at ${date_now}"
    exit 0
fi

# Stop agent connection loop to the MGMT, to make sure the
# agent does not prcoess messages during the upgrade process.
log "Closing connection to MGMT..."
res=$(fwagent stop)
if [ ${PIPESTATUS[0]} != 0 ]; then
    log "Error: Closing connection to MGMT - ${res}"
    handle_upgrade_failure 'stop agent connection' 'Failed to stop agent connection to management'
    exit 1
fi

# Check if there's another process running this script
res=$(pgrep -afc $SCRIPT_NAME)
if [ $res -gt 1 ] ; then
    log "Error: another $SCRIPT_NAME process is running"
    handle_upgrade_failure 'check Host OS upgrade process' 'Failed to run Host OS upgrade due to another process running it'
    exit 1
fi

# Set "KillMode" option in the service file, to make sure systemd
# doesn't kill the 'fwupgrade_kernel.sh' process itself on stopping the fwagent process,
# as today the 'fwupgrade_kernel.sh' is invoked by the fwagent on receiving
# 'upgrade-linux-sw' request from flexiManage. Note, the vpp and rest processes
# in the fwagent control group are not stopped too, but we are OK with this for now.
#
update_service_conf_file modify
ret=${PIPESTATUS[0]}
if [ ${ret} != 0 ]; then
    log "Error: modifying service file - ${ret}"
    handle_upgrade_failure "upgrade linux" "update_service_conf_file failed: ${ret}"
    exit 1
fi

kernel_hwe_upgrade
ret=${PIPESTATUS[0]}
date_now=$(date "+%F %H:%M:%S")
if [ ${ret} != 0 ]; then
    log "ERR: Kernel HWE not upgraded - ${ret}"
    update_service_conf_file restore
    handle_upgrade_failure "upgrade linux" "kernel_hwe_upgrade failed: ${ret}"
    exit 1
fi

log "INFO: Kernel HWE upgrade finished at ${date_now}"

clean_and_reboot
