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

# Constants
AGENT_SERVICE="flexiwan-router"
AGENT_SERVICE_FILE="/lib/systemd/system/${AGENT_SERVICE}.service"
APT_SOURCE_FILES="/etc/apt/sources.list.d/flexiwan*"
APT_SOURCE_REGEXP="^deb[ \t]+\[[ \t]*arch=(.+)[ \t]*\][ \t]+(http.*)/(.+)[ \t]+(.+)[ \t]+(.+)$"
APT_URL_REGEXP="(http|https)://[a-zA-Z0-9./?=_%:-]*"
SW_REPOSITORY="$(grep -Eoh "$APT_SOURCE_REGEXP" $APT_SOURCE_FILES | head -1 | cut -d '/' -f3 )"
SW_REPOSITORY_GPG_KEY="$(grep -Eoh "$APT_SOURCE_REGEXP" $APT_SOURCE_FILES | head -1 | grep -Eoh "$APT_URL_REGEXP")/gpgkey/flexiwan.ng.source.gpg.key"
AGENT_CHECK_TIMEOUT=360
APT_LOCK_TIMEOUT=60
SCRIPT_NAME="$(basename $BASH_SOURCE)"

# Constants passed to the script by fwagent
TARGET_VERSION="$1"
VERSIONS_FILE="$2"
UPGRADE_STATUS_FILE="$3"
AGENT_LOG_FILE="$4"
JOB_ID="$5"

# Globals
prev_ver=''
curr_ver=''

log() {
    echo `date +'%b %e %R:%S'`" $HOSTNAME $SCRIPT_NAME:" "$@" >> "$AGENT_LOG_FILE" 2>&1
}

update_jobs_db() {
    log "$1": "$2"
    fwagent configure jobs update --job_id $JOB_ID --request 'upgrade-device-sw' --command "$1" --job_error "$2"
}

handle_upgrade_failure() {
    log "Software upgrade failed"
    update_jobs_db "$1" "$2"

    # Revert back to previous version if required
    if [ "$3" == 'revert' ]; then
        log "reverting to previous version ${prev_ver} ..."

        apt_install "${AGENT_SERVICE}=${prev_ver}"
        ret=${PIPESTATUS[0]}
        if [ ${ret} == 1 ]; then
            update_jobs_db 'revert to previous version' "failed to revert to ${prev_ver} with ${ret}"
            exit 1
        elif [ ${ret} == 2 ]; then
            update_jobs_db 'revert to previous version' "failed to revert to ${prev_ver} with ${ret}"
            # Agent must be restarted if revert fails, or otherwise
            # it will remain stopped.
            systemctl restart "$AGENT_SERVICE"
            exit 2
        fi

        log "reverting to previous version ${prev_ver} - restarting agent ..."

        # There is a flow, where "handle_upgrade_failure revert" is called on failure of
        # the "apt-get install <new-version>", but the previous version was not uninstalled
        # and still runs. In this case the "apt-get install <prev-version>"
        # will do nothing and will return OK (zero). As a result, the "if" block above will
        # be not executed and service will be not restarted. In this case, the agent will not
        # connect to the flexiManage after revert, as this script stops the connection loop
        # the before upgarde, and nobody starts it back. To handle this case we just restart
        # service here, so the connection loop should be resumed.
        #
        systemctl restart "$AGENT_SERVICE"

        log "reverting to previous version ${prev_ver} - finished"
        exit 3
    fi

    # Create a file that marks the installation has failed
    #
    echo `date +'%b %e %R:%S'`" $HOSTNAME: $SCRIPT_NAME: failed" >> "${UPGRADE_STATUS_FILE}" 2>&1

    # Reconnect to MGMT
    res=$(fwagent start)
    if [ ${PIPESTATUS[0]} != 0 ]; then
        log $res
        update_jobs_db "revert to previous version" "failed to start agent connection loop"
    fi
    exit 4
}

#######################################
# Retrieves and sets the installed version of router in curr_ver
# Arguments:
#   none
# Returns:
#   0 if version retrieval succeeded, non-zero on error.
#######################################
get_curr_version() {
    if [ ! -f "$VERSIONS_FILE" ]; then
        update_jobs_db "get current version" "${VERSIONS_FILE} not found"
        return 1
    fi

    ver_entry=`grep device "$VERSIONS_FILE"`
    if [ -z "$ver_entry" ]; then
        update_jobs_db "get current version" "device version not found in ${VERSIONS_FILE} not found"
        return 1
    fi

    curr_ver=`echo "$ver_entry" | awk '{split($0, res, " "); print res[2]}'`

    # check and compare version specified in ${VERSIONS_FILE} vs installed package version
    package_ver=$(dpkg-query -W -f='${Version}\n' flexiwan-router)
    log "get current version: ${package_ver} package version installed"

    if [ "$curr_ver" != "$package_ver" ]; then
        update_jobs_db "get current version" "device version mismatch: ${curr_ver} in ${VERSIONS_FILE} vs ${package_ver} as installed package"
        return 1
    fi
}

update_service_conf_file() {
    if [ ! -f "$AGENT_SERVICE_FILE" ]; then
        update_jobs_db "update service.unit file" "${AGENT_SERVICE_FILE} not found"
        return 1
    fi

    # Don't add the configuration if it already exists
    kill_mode_conf=`grep KillMode=process "$AGENT_SERVICE_FILE"`
    if [ -z "$kill_mode_conf" ]; then
        echo -e "\n[Service]\nKillMode=process" >> "$AGENT_SERVICE_FILE"
        systemctl daemon-reload
    fi
}

check_connection_to_sw_repo() {
    ping -c 1 $SW_REPOSITORY >> /dev/null 2>&1
    if [ ${PIPESTATUS[0]} != 0 ]; then
        return 1
    fi
    return 0
}

apt_key_add() {
    if [ -x /usr/bin/curl ]; then
        curl -s $SW_REPOSITORY_GPG_KEY | apt-key add - 2>/dev/null
    else
        wget -qO $SW_REPOSITORY_GPG_KEY | apt-key add - 2>/dev/null
    fi
}

#######################################
# Installs requested version using apt-get.
# Arguments:
#   Package name and its exact version. Example: flexiwan-router=4.2.42
# Returns:
#   0   if install succeeded.
#   1   if pre check of install fails, before running the apt-install.
#   2   if apt-install command fails.
#   100 if other failure.
#######################################
apt_install() {

    # Set "KillMode" option in the service file, to make sure systemd
    # doesn't kill the 'fwupgrade.sh' process itself on stopping the fwagent process,
    # as today the 'fwupgrade.sh' is invoked by the fwagent on receiving
    # 'upgrade-device-sw' request from flexiManage. Note, the vpp and rest processes
    # in the fwagent control group are not stopped too, but we are OK with this for now.
    #
    update_service_conf_file
    ret=${PIPESTATUS[0]}
    if [ ${ret} != 0 ]; then
        update_jobs_db "install new/old version" "update_service_conf_file failed: ${ret}"
        return 1
    fi

    # checking that the requested version is available
    check_cmd="apt-cache show $1"
    log ${check_cmd}
    out=$(${check_cmd} 2>&1); ret=${PIPESTATUS[0]}
    if [ ${ret} == 0 ]; then
        log "${check_cmd} Command succeeded, version $1 found"
    else
        log "${check_cmd} Command failed, version $1 not found"
        update_jobs_db "install new/old version" "${recover_cmd}: failed with ${ret}: ${out}"
        return 1
    fi

    install_cmd="apt-get -o Dpkg::Lock::Timeout=$APT_LOCK_TIMEOUT -o Dpkg::Options::="--force-confold" -y install --allow-downgrades $1"
    log "apt_install: calling ${install_cmd}"
    out=$(${install_cmd} 2>&1); ret=${PIPESTATUS[0]}
    if [ ${ret} == 0 ]; then
        return 0   # return on success
    fi

    # At this point the apt-get failed.
    # Log the failure and try to recover.
    #
    log "apt_install: ${install_cmd}: failed with ${ret}: ${out}"

    # Check, if apt-get proposed to run 'dpkg --configure -a' to fix the problem.
    # If it did, run the 'dpkg --configure -a' and retry the installation.
    #
    if [[ "${out}" == *"dpkg --configure -a"* ]]; then
        recover_cmd="dpkg --configure -a"
        out=$(${recover_cmd} 2>&1); ret=${PIPESTATUS[0]}
        if [ ${ret} != 0 ]; then
            update_jobs_db "install new/old version" "${recover_cmd}: failed with ${ret}: ${out}"
            return 2
        fi
        # retry installation
        out=$(${install_cmd} 2>&1); ret=${PIPESTATUS[0]}
        if [ ${ret} == 0 ]; then
            return 0   # return on success
        fi
        update_jobs_db "install new/old version" "${install_cmd}: failed with ${ret}: ${out}"
    fi

    return 100  # we totally failed
}

# Upgrade process
log "Starting software upgrade process..."

# Remove the file that represents upgrade failure. This file
# is created by either this script (if the failure is during the
# software upgrade process), or by the agent, if post-installation
# checks fail
rm "$UPGRADE_STATUS_FILE" >> /dev/null 2>&1

# Save previous version for revert in case the upgrade process fails
get_curr_version
ret=${PIPESTATUS[0]}
if [ "${ret}" == 1 ]; then
    handle_upgrade_failure 'Device upgrade pre-check' "Failed to extract installed version"
fi
prev_ver="${curr_ver}"
if [ -z "$prev_ver" ]; then
    handle_upgrade_failure 'extract previous version' "Failed to extract previous version from $VERSIONS_FILE"
fi

# Quit upgrade process if device is already running the latest version
dpkg --compare-versions "$TARGET_VERSION" le "$prev_ver"
if [ $? == 0 ]; then
    log "Device is already running the latest version ($prev_ver). Quitting upgrade process"
    exit 0
fi

# Stop agent connection loop to the MGMT, to make sure the
# agent does not process messages during the upgrade process.
log "Closing connection to MGMT..."
res=$(fwagent stop --dont_stop_vpp --dont_stop_applications)
if [ ${PIPESTATUS[0]} != 0 ]; then
    log $res
    handle_upgrade_failure 'stop agent connection' 'Failed to stop agent connection to management'
fi

log "Installing new software..."

# Check connection to the software package repository.
# We have to check excplicitly since the 'apt-get update'
# command returns success status code even if the connection fails.
check_connection_to_sw_repo
if [ ${PIPESTATUS[0]} != 0 ]; then
    handle_upgrade_failure 'check connection to repository' "Failed to connect to software repository $SW_REPOSITORY"
fi

# Add repository GPG key
apt_key_add
if [ ${PIPESTATUS[0]} != 0 ]; then
    handle_upgrade_failure 'add apt repository GPG key' "Failed to add repository's GPG key from $SW_REPOSITORY_GPG_KEY"
fi

# Update debian repositories
res=$(apt-get update)
if [ ${PIPESTATUS[0]} != 0 ]; then
    log $res
    handle_upgrade_failure 'update debian repositories' 'Failed to update debian repositores'
fi

# Upgrade device package. From this stage on, we should
# pass 'revert' to handle_upgrade_failure() upon failure
#
apt_install "${AGENT_SERVICE}=${TARGET_VERSION}"
ret=${PIPESTATUS[0]}
if [ ${ret} == 1 ]; then
    handle_upgrade_failure 'install new version' 'apt_install() failed to install new version'
elif [ ${ret} == 2 ]; then
    handle_upgrade_failure 'install new version' "failed to install latest version (ret=${ret})" 'revert'
fi

# Check installed version against requested.
#
log "Checking installed version against requested"
get_curr_version
ret=${PIPESTATUS[0]}
if [ "${ret}" == 1 ]; then
    handle_upgrade_failure 'Device upgrade post-check' "Failed to get installed version"
fi

if [ "$TARGET_VERSION" != "$curr_ver" ] ; then
    handle_upgrade_failure 'Device upgrade post-check' "Version mismatch, expected ${TARGET_VERSION}, got ${curr_ver}"
fi
log "Installed device version matches the requested one"

# Wait to see if service is up and connected to the MGMT.
# apt is responsible for restarting the service after the upgrade
log "Finished installing new software. waiting for agent check (${AGENT_CHECK_TIMEOUT} sec)"
while ((${AGENT_CHECK_TIMEOUT})); do
    upgrade_status=$(cat ${UPGRADE_STATUS_FILE} 2>&1)
    if [ "$upgrade_status" == "success" ]; then
        log "upgrade succeeded"
        exit 0
    fi
    AGENT_CHECK_TIMEOUT=$((${AGENT_CHECK_TIMEOUT}-1))
    sleep 1
done

handle_upgrade_failure 'agent check' 'post upgrade agent checks failed' 'revert'
exit 100

