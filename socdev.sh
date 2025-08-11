#!/bin/bash

set -e

SSH_ARGS=${SSH_ARGS:--o StrictHostKeyChecking=no -o "UserKnownHostsFile=/dev/null" -o LogLevel=ERROR }
SSH_USER=${SSH_USER:-onion}
SO_HOST=${SO_HOST:-manager}
TMP_DIR=${TMP_DIR:-/tmp/socdev}

function usage() {
  cat <<USAGE_EOF
  Usage: $0 [parameters]
  
  Available Parameters:
    --manager-ip <manager_ip>
    --stop-agent
    --stop-minion
USAGE_EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  param=$1
  shift
  case "$param" in
    --stop-agent)
      stop_agent=1
      ;;
    --stop-minion)
      stop_minion=1
      ;;
    --manager-ip)
      MANAGER_IP=$1
      shift
      ;;
    *) 
      echo "Encountered unexpected parameter: $param"
      usage
      ;;
  esac
done

run_on_mgr() {
    ssh $SSH_ARGS ${SSH_USER}@${SO_HOST} $@
}

echo "Setting up remote VM for local SOC development."
if [[ -z "$MANAGER_IP" ]]; then
    read -p "Enter your VM's IP: " MANAGER_IP
fi

if [[ "$(uname)" =~ "Darwin" ]]; then
    ext=".old"
    nsmDir=/Volumes/nsm
    echo "Unmounting existing volumes via sudo"
    set +e
    sudo umount $TMP_DIR/so > /dev/null 2>&1
    sudo umount $nsmDir > /dev/null 2>&1
    set -e
    if ! groups | grep -q socore; then
        echo "Creating socore group via sudo"
        sudo dscl . -create /Groups/socore gid 939
        sudo dscl . append /Groups/socore GroupMembership $USER
    fi
else
    ext=
    nsmDir=/nsm
fi

sudo mkdir -p $nsmDir
sudo chown $USER $nsmDir

if grep -q "$MANAGER_IP ${SO_HOST}" /etc/hosts; then
    echo "✓ Verified that /etc/hosts is already setup for this VM."
elif grep -q " ${SO_HOST}" /etc/hosts; then
    echo "✓ Using sudo to update the existing '${SO_HOST}' entry in /etc/hosts."
    sudo sed -i $ext "s/.* ${SO_HOST}/$MANAGER_IP ${SO_HOST}/" /etc/hosts
else
    echo "✓ Using sudo to add a new '${SO_HOST}' entry to /etc/hosts."
    sudo bash -c "echo '$MANAGER_IP ${SO_HOST}' >> /etc/hosts"
fi

echo "✓ Setting up SSH login to VM via certificate."
ssh-copy-id $SSH_ARGS ${SSH_USER}@${SO_HOST} > /dev/null

if ! run_on_mgr sudo find /etc/sudoers.d/$SSH_USER &> /dev/null && ! run_on_mgr "sudo grep $SSH_USER /etc/sudoers | grep NOPASSWD &> /dev/null "; then
    echo "To avoid repeatedly retyping the VM password, copy and paste the following command into the VM terminal:"
    echo ""
    echo "echo '${SSH_USER}	ALL=(ALL)	NOPASSWD: ALL' > /tmp/$SSH_USER && sudo chown root:root /tmp/$SSH_USER && sudo mv /tmp/$SSH_USER /etc/sudoers.d/ && exit"
    echo ""

    read -n 1 -p "Press any key once the above command has been executed in the VM. You can skip this step if it's already been run on this VM. "
    echo ""
fi
set +e

echo "✓ Preparing VM for use with local development."
run_on_mgr 'sudo sed -i "s/- soc\b/#socdev soc/" /opt/so/saltstack/default/salt/top.sls'
run_on_mgr 'sudo sed -i "s/- firewall\b/#socdev firewall/" /opt/so/saltstack/default/salt/top.sls'
run_on_mgr sudo usermod -aG socore $SSH_USER
run_on_mgr sudo usermod -aG elastalert $SSH_USER
run_on_mgr sudo chmod -R g+rw /opt/so/saltstack/local
run_on_mgr sudo chmod g+w /opt/so/state

mkdir -p $TMP_DIR/so

if [ ! -d $TMP_DIR/so/conf ]; then
    if ! which sshfs > /dev/null; then
        if [[ $(uname) =~ "Darwin" ]]; then
            echo "Visit osxfuse.github.io to install macFUSE and SSHFS. Exiting."
            exit 1;
        fi
        echo "Using sudo to install sshfs"
        if which apt; then
            sudo apt install sshfs -y
        elif which pacinstall; then
            sudo pacinstall --yolo sshfs
        else
            echo "Install sshfs manually, then re-run this script. Exiting."
            exit 1;
        fi
    fi

    run_on_mgr sudo chgrp socore /opt/so/conf/soc/
    run_on_mgr sudo chmod -R g+rw /opt/so/conf/soc/
    run_on_mgr sudo chown socore /opt/so/conf/soc/
    run_on_mgr sudo chmod -R g+rw /opt/so/conf/strelka/rules
    run_on_mgr sudo chmod -R g+rw /opt/so/conf/strelka/repos
    run_on_mgr sudo chmod -R g+rw /opt/so/rules/elastalert/rules
    run_on_mgr sudo chmod g+rw /opt/so/saltstack/local/salt/idstools/rules
    run_on_mgr sudo chmod g+rw /opt/so/saltstack/local/salt/suricata/thresholding
    run_on_mgr sudo chmod -R g+rw /opt/so/state
    sshfs -o direct_io $SSH_ARGS $SSH_USER@$MANAGER_IP:/opt/so $TMP_DIR/so
    echo "✓ Mounted remote server /opt/so to local $TMP_DIR/so"

    run_on_mgr "sudo chmod g+w /nsm/soc/uploads"
    sshfs -o direct_io $SSH_ARGS $SSH_USER@$MANAGER_IP:/nsm $nsmDir
    echo "✓ Mounted remote server /nsm to local $nsmDir"

    sshfs -o direct_io $SSH_ARGS $SSH_USER@$MANAGER_IP:/opt/so/rules/nids/suri /opt/sensoroni/nids
    echo "✓ Mounted remote server /opt/so/rules/nids/suri to local /opt/sensoroni/nids"
fi

if [[ "$1" != "cleanup" ]]; then
    if [[ ! -f $TMP_DIR/so/conf/soc/soc.dev.json ]]; then
        echo "✓ Copying soc.json and updating for local dev"

        jq ".logLevel=\"debug\" |
            .server.modules.statickeyauth.anonymousCidr=\"*\" |
            .server.modules.staticrbac.userFiles=[\"$TMP_DIR/so/conf/soc/soc_users_roles\"] |
            .server.modules.salt.queueDir=\"$TMP_DIR/so/conf/soc/queue\" |
            .server.modules.suricataengine.rulesFingerprintFile=\"$TMP_DIR/so/conf/soc/emerging-all.fingerprint\" |
            .server.modules.elastalertengine.elastAlertRulesFolder=\"$TMP_DIR/so/rules/elastalert/rules\" |
            .server.modules.elastalertengine.rulesFingerprintFile=\"$TMP_DIR/so/conf/soc/sigma.fingerprint\" |
            .server.modules.strelkaengine.compileYaraPythonScriptPath=\"$TMP_DIR/so/conf/strelka/compile_yara.py\" |
            .server.modules.strelkaengine.reposFolder=\"$TMP_DIR/so/conf/strelka/repos\" |
            .server.modules.strelkaengine.yaraRulesFolder=\"$TMP_DIR/so/conf/strelka/rules\"" $TMP_DIR/so/conf/soc/soc.json > $TMP_DIR/so/conf/soc/soc.dev.json
    fi
    if ! grep -q "socdev/so/saltstack" $TMP_DIR/so/conf/soc/soc.dev.json; then
        if jq ".server.modules.salt.saltstackDir=\"$TMP_DIR/so/saltstack\"" $TMP_DIR/so/conf/soc/soc.dev.json > $TMP_DIR/so/conf/soc/soc2.dev.json; then
          mv $TMP_DIR/so/conf/soc/soc2.dev.json $TMP_DIR/so/conf/soc/soc.dev.json
        fi
    fi

    run_on_mgr sudo iptables -I DOCKER-USER -p tcp -m tcp -j ACCEPT -s 0.0.0.0/0 --dport 9200 # Elasticsearch
    run_on_mgr sudo iptables -I DOCKER-USER -p tcp -m tcp -j ACCEPT -s 0.0.0.0/0 --dport 4434 # Kratos Admin
    run_on_mgr sudo iptables -I DOCKER-USER -p tcp -m tcp -j ACCEPT -s 0.0.0.0/0 --dport 4445 # Hydra Admin
    run_on_mgr sudo iptables -I DOCKER-USER -p tcp -m tcp -j ACCEPT -s 0.0.0.0/0 --dport 8086 # InfluxDB
    echo "⏳ SOC is being disconnected from Salt. CTRL+C and rerun this script if this step takes longer than 1-2 minutes."
    run_on_mgr sudo docker stop so-soc > /dev/null
    if [[ $stop_agent -eq 1 ]]; then
      echo "Stopping agent"
      run_on_mgr sudo docker stop so-sensoroni > /dev/null
    fi
    run_on_mgr sudo sed -i '/so-soc/d' /opt/so/conf/so-status/so-status.conf
    run_on_mgr "sudo sed -i 's/#GatewayPorts no/GatewayPorts yes/' /etc/ssh/sshd_config"
    run_on_mgr sudo systemctl restart sshd
    if [[ $stop_minion -eq 1 ]]; then
      echo "Stopping minion"
      run_on_mgr sudo salt-call saltutil.kill_all_jobs
      run_on_mgr sudo rm -f /usr/sbin/so-salt-minion-check
      run_on_mgr sudo systemctl stop salt-minion 
    fi

    if [ -d /opt/so ]; then
        sudo unlink /opt/so
    fi
    sudo ln -s $TMP_DIR/so /opt/so
    echo "✓ Created /opt/so link to $TMP_DIR/so for license pillar"

    echo "✓ An SSH redirect session will now remain open to allow the VM to forward web traffic to your local SOC. Local development can commence. When finished, hit CTRL+C."
    echo "    To start SOC locally, run: go cmd/sensoroni.go -c $TMP_DIR/so/conf/soc/soc.dev.json"
    ssh $SSH_ARGS -NR 9822:localhost:9822 ${SSH_USER}@${SO_HOST}

    echo ""
    echo "✓ Local development interrupted due to closing of the SSH port forward session. Re-run this script to resume port forwarding."
else
    echo "Rolling back socdev changes on VM"
fi

run_on_mgr sudo systemctl start salt-minion
run_on_mgr 'sudo sed -i "s/#socdev soc/- soc/" /opt/so/saltstack/default/salt/top.sls'
run_on_mgr 'sudo sed -i "s/#socdev firewall/- firewall/" /opt/so/saltstack/default/salt/top.sls'
run_on_mgr 'echo "so-soc" | sudo tee -a /opt/so/conf/so-status/so-status.conf'
run_on_mgr sudo so-soc-start
run_on_mgr sudo so-sensoroni-start
sudo unlink /opt/so

echo "Finished!"
