OBELISK_SRC_FILE="/opt/obelisk_decept/config/"
INIT_FOLDER="/etc/init/"
CONF_FILE="obelisk_decept.conf"

echo "Copying file: ${OBELISK_SRC_FILE}${CONF_FILE} to ${INIT_FOLDER}"
cp -v ${OBELISK_SRC_FILE}${CONF_FILE} ${INIT_FOLDER}
sleep 10
chmod 755 ${INIT_FOLDER}${CONF_FILE}
chmod 755 /opt/obelisk_decept/odlauncher.py
initctl reload-configuration
sleep 5 
service obelisk_decept start
sleep 5
tail -n 50 /var/log/upstart/obelisk_decept.log
sleep 3
service obelisk_decept status
