#!/bin/bash

set -u
set -o pipefail

CIS_DIR="/root/cis-hardening"
#ironically you can fail a check for having files in your root directory, change this if you want that 100% pass
SCAP_DS="/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml"
CIS_PROFILE="xccdf_org.ssgproject.content_profile_cis"

PRE_REPORT="${CIS_DIR}/cis_scan_before.html"
POST_REPORT="${CIS_DIR}/cis_scan_after.html"
REMEDIATION="${CIS_DIR}/cis_hardening.sh"
LOG="${CIS_DIR}/cis_hardening.log"

mkdir -p "${CIS_DIR}"
chmod 700 "${CIS_DIR}"

exec > >(tee -a "${LOG}") 2>&1

echo "=============================================="
echo " RHEL 9 CIS HARDENING"
echo " Started: $(date)"
echo " Host: $(hostname -f)"
echo "=============================================="

# --------------------------------------------------
# Verify OS
# --------------------------------------------------

if [ ! -f /etc/redhat-release ]; then
    echo "ERROR: This does not appear to be a RHEL system."
    exit 1
fi

if ! grep -qE 'release 9' /etc/redhat-release; then
    echo "ERROR: This script is intended for RHEL 9."
    cat /etc/redhat-release
    exit 1
fi

echo "[OK] RHEL 9 detected."

# --------------------------------------------------
# Install required packages
# --------------------------------------------------

echo
echo "Installing required packages..."

dnf install -y \
    bash-completion \
    sysstat \
    tmux \
    sos \
    scap-security-guide \
    openscap-scanner \
    openscap-utils

if [ $? -ne 0 ]; then
    echo "ERROR: Package installation failed."
    exit 1
fi

echo "[OK] Required packages installed."

# --------------------------------------------------
# Verify SCAP datastream
# --------------------------------------------------

if [ ! -f "${SCAP_DS}" ]; then
    echo "ERROR: SCAP datastream not found:"
    echo "${SCAP_DS}"
    exit 1
fi

echo
echo "[OK] SCAP datastream found:"
echo "${SCAP_DS}"

# --------------------------------------------------
# Verify CIS profile
# --------------------------------------------------

echo
echo "Checking available CIS profiles..."

oscap info "${SCAP_DS}" | grep -i cis

if ! oscap info "${SCAP_DS}" | grep -q "${CIS_PROFILE}"; then
    echo
    echo "ERROR: CIS profile not found:"
    echo "${CIS_PROFILE}"
    exit 1
fi

echo "[OK] CIS profile available."

# --------------------------------------------------
# Pre-hardening scan
# --------------------------------------------------

echo
echo "=============================================="
echo " Running PRE-HARDENING CIS scan"
echo "=============================================="

oscap xccdf eval \
    --profile "${CIS_PROFILE}" \
    --report "${PRE_REPORT}" \
    "${SCAP_DS}"

PRE_RC=$?

echo
echo "Pre-hardening scan return code: ${PRE_RC}"
echo "Report: ${PRE_REPORT}"

# Do not stop here.
# A non-zero result normally means findings exist.

# --------------------------------------------------
# Generate remediation
# --------------------------------------------------

echo
echo "=============================================="
echo " Generating CIS remediation script"
echo "=============================================="

oscap xccdf generate fix \
    --profile "${CIS_PROFILE}" \
    --fix-type bash \
    "${SCAP_DS}" > "${REMEDIATION}"

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to generate remediation script."
    exit 1
fi

chmod 700 "${REMEDIATION}"

echo "[OK] Remediation generated:"
echo "${REMEDIATION}"

# --------------------------------------------------
# Apply remediation
# --------------------------------------------------

echo
echo "=============================================="
echo " Applying CIS remediation"
echo "=============================================="

echo "WARNING: CIS remediation may modify:"
echo "  - SSH configuration"
echo "  - PAM/authentication"
echo "  - Password policies"
echo "  - SELinux settings"
echo "  - Audit configuration"
echo "  - File permissions"
echo "  - Crypto policies"
echo "  - Services"
echo "  - Kernel/sysctl parameters"
echo

read -r -p "Apply CIS remediation now? [yes/NO]: " CONFIRM

if [ "${CONFIRM}" != "yes" ]; then
    echo "Remediation cancelled."
    exit 0
fi

bash "${REMEDIATION}"

REMEDIATION_RC=$?

echo
echo "Remediation return code: ${REMEDIATION_RC}"

# --------------------------------------------------
# Check reboot requirement
# --------------------------------------------------

echo
echo "Checking whether reboot is required..."

if command -v needs-restarting >/dev/null 2>&1; then

    needs-restarting -r

    REBOOT_RC=$?

    if [ "${REBOOT_RC}" -ne 0 ]; then
        echo
        echo "WARNING: System reports that a reboot is required."
        echo "Do NOT reboot automatically."
        echo "Schedule the reboot through your normal change process."
    else
        echo "[OK] Reboot does not appear to be required."
    fi

else
    echo "needs-restarting command unavailable."
fi

# --------------------------------------------------
# Post-hardening scan
# --------------------------------------------------

echo
echo "=============================================="
echo " Running POST-HARDENING CIS scan"
echo "=============================================="

oscap xccdf eval \
    --profile "${CIS_PROFILE}" \
    --report "${POST_REPORT}" \
    "${SCAP_DS}"

POST_RC=$?

echo
echo "Post-hardening scan return code: ${POST_RC}"
echo "Report: ${POST_REPORT}"

# --------------------------------------------------
# Summary
# --------------------------------------------------

echo
echo "=============================================="
echo " CIS HARDENING SUMMARY"
echo "=============================================="

echo "Host:                 $(hostname -f)"
echo "Date:                 $(date)"
echo "Pre-scan RC:          ${PRE_RC}"
echo "Remediation RC:       ${REMEDIATION_RC}"
echo "Post-scan RC:         ${POST_RC}"
echo
echo "Pre-hardening report:"
echo "  ${PRE_REPORT}"
echo
echo "Post-hardening report:"
echo "  ${POST_REPORT}"
echo
echo "Generated remediation:"
echo "  ${REMEDIATION}"
echo
echo "Execution log:"
echo "  ${LOG}"
echo "=============================================="
