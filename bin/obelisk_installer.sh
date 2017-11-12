OBELISK_SRC_FILE="/opt/obelisk_decept/config/"
INIT_FOLDER="/lib/systemd/system"
CONF_FILE=obelisk_decept.service

echo "Copying file: ${OBELISK_SRC_FILE}${CONF_FILE} to ${INIT_FOLDER}"
cp -v ${OBELISK_SRC_FILE}${CONF_FILE} ${INIT_FOLDER}
sleep 10
systemctl daemon-reload
sleep 5
systemctl enable ${CONF_FILE}
sleep 5
systemctl start ${CONF_FILE}
echo "Checking log file."
tail -n 50 /var/log/messages
sleep 3
systemctl status obelisk_decept.service
