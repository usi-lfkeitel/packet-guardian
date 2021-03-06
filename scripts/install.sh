#! /usr/bin/env bash

# Check running as root
if [[ $UID -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

APP_DIR="/opt/packet-guardian"
UPSTART_SERVICE_DIR="/etc/init"
SYSTEMD_SERVICE_DIR="/etc/systemd/system"
LOG_DIR="/var/log/packet-guardian"
DATA_DIR="/var/lib/packet-guardian"
CONFIG_DIR="/etc/packet-guardian"
APPARMOR_DIR="/etc/apparmor.d"

SYSTEMD=""
APPARMOR_INSTALLED=""
APPARMOR_UTILS_INSTALLED=""
ALL_YES=""

if [[ $1 == "-y" ]]; then
    ALL_YES="t"
fi
if which systemctl >/dev/null 2>&1; then
    SYSTEMD="t"
fi
if which apparmor_status >/dev/null 2>&1; then
    APPARMOR_INSTALLED="t"
fi
if which aa-complain >/dev/null 2>&1; then
    APPARMOR_UTILS_INSTALLED="t"
fi

stopService() {
    echo "Stopping any running instances"
    if [[ -n $SYSTEMD ]]; then
        systemctl stop pg-dhcp >/dev/null 2>&1
        systemctl stop pg >/dev/null 2>&1
    else
        service pg-dhcp stop >/dev/null 2>&1
        service pg stop >/dev/null 2>&1
    fi
}

confirm() {
    if [[ -n $ALL_YES ]]; then
        return
    fi
    echo -n "$1 [y/N]: "
    read -n 1 imsure
    echo
    if [[ $imsure != "y" ]]; then
        exit 0
    fi
}

installed() {
    test -f $DATA_DIR/.installed
    return $?
}

installService() {
    cd $APP_DIR
    if [[ -n $SYSTEMD ]]; then
        echo "Installing Systemd Service"
        cp config/service/systemd/pg.service $SYSTEMD_SERVICE_DIR/pg.service
        cp config/service/systemd/dhcp.service $SYSTEMD_SERVICE_DIR/pg-dhcp.service
        chown root:root $SYSTEMD_SERVICE_DIR/pg.service
        chown root:root $SYSTEMD_SERVICE_DIR/pg-dhcp.service
        systemctl daemon-reload
        systemctl enable pg.service
        systemctl enable pg-dhcp.service
    else
        echo "Installing Upstart Service"
        cp config/service/upstart/pg.conf $UPSTART_SERVICE_DIR/pg.conf
        cp config/service/upstart/dhcp.conf $UPSTART_SERVICE_DIR/pg-dhcp.conf
        chown root:root $UPSTART_SERVICE_DIR/pg.conf
        chown root:root $UPSTART_SERVICE_DIR/pg-dhcp.conf
    fi
}

setKernalPermissions() {
    echo "Setting kernel permissions"
    setcap 'cap_net_bind_service=+ep' $APP_DIR/bin/pg
    setcap 'cap_net_bind_service=+ep' $APP_DIR/bin/dhcp
}

installAppArmorProfile() {
    # Install apparmor profile if available
    if [[ -n $APPARMOR_INSTALLED ]]; then
        echo "Installing AppArmor profile"
        mkdir -p $APPARMOR_DIR
        cp config/apparmor/pg/apparmor-ext.conf $APPARMOR_DIR/opt.packet-guardian.bin.pg
        cp config/apparmor/dhcp/apparmor-ext.conf $APPARMOR_DIR/opt.packet-guardian.bin.dhcp
        chown root:root $APPARMOR_DIR/opt.packet-guardian.bin.pg
        chown root:root $APPARMOR_DIR/opt.packet-guardian.bin.dhcp
        if [[ -n $APPARMOR_UTILS_INSTALLED ]]; then
            aa-complain $APP_DIR/bin/pg
            aa-complain $APP_DIR/bin/dhcp
        else
            echo "It appears AppArmor is installed but apparmor-utils is not."
            echo "To enable the AppArmor profile, install apparmor-utils"
            echo "and run:"
            echo "aa-complain $APP_DIR/bin/pg"
            echo "aa-complain $APP_DIR/bin/dhcp"
        fi
    else
        echo "AppArmor doesn't appear to be installed. Skipping."
    fi
}

setPermissions() {
    chown -R packetg:packetg $APP_DIR
    chown -R packetg:packetg $LOG_DIR
    chown -R packetg:packetg $DATA_DIR
    chown -R root:packetg $CONFIG_DIR
}

install() {
    if [[ ! -d $APP_DIR ]]; then
        echo "It appears Packet Guardian is not in the correct place."
        echo "Please extract the Packet Guardian release to $APP_DIR"
        echo "and try again."
        echo
        exit 1
    fi

    if installed; then
        echo "It appears Packet Guardian is already installed."
        confirm "This will overwrite all configuration files and the database. Are you sure?"
    fi

    echo "Creating packetg user"
    id -u packetg >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        useradd -M packetg
    fi

    echo "Creating data directories"
    mkdir -p $LOG_DIR
    mkdir -p $DATA_DIR
    mkdir -p $CONFIG_DIR
    echo "Creating configuration files"
    cp $APP_DIR/config/config-dhcp.sample.toml $CONFIG_DIR
    cp $APP_DIR/config/config-pg.sample.toml $CONFIG_DIR
    cp $APP_DIR/config/config-dhcp.sample.toml $CONFIG_DIR/config-dhcp.toml
    cp $APP_DIR/config/config-pg.sample.toml $CONFIG_DIR/config-pg.toml
    cp $APP_DIR/config/dhcp-config.sample.conf $CONFIG_DIR
    cp $APP_DIR/config/policy.txt $CONFIG_DIR

    cp $APP_DIR/scripts/pg-upgrade.sh /usr/local/bin/pg-upgrade
    cp $APP_DIR/scripts/uninstall.sh $DATA_DIR/uninstall.sh

    setPermissions
    installService
    setKernalPermissions
    installAppArmorProfile

    touch $DATA_DIR/.installed

    echo
    echo "Packet Guardian is now installed"
    echo "Please edit the configurations to your"
    echo "liking and them run using:"
    echo
    echo "service pg start OR systemctl start pg"
    echo "service pg-dhcp start OR systemctl start pg-dhcp"
    echo
}

confirm "This will install Packet Guardian. Are you sure?"
install
