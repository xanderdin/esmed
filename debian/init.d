#!/bin/sh
### BEGIN INIT INFO
# Provides:          esmed
# Required-Start:    $local_fs $remote_fs $network $syslog postgresql
# Required-Stop:     $local_fs $remote_fs $network $syslog postgresql
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start/stop esmed
# Description:       Start/stop esmed
### END INIT INFO

PATH=/sbin:/bin:/usr/sbin:/usr/bin

PLUGIN=esmed
pidfile=/var/run/${PLUGIN}.pid
rundir=/var/lib/$PLUGIN/
logfile=/var/log/$PLUGIN/twisted.log
config=/etc/$PLUGIN/$PLUGIN.conf

[ -r /etc/default/$PLUGIN ] && . /etc/default/$PLUGIN

test -x /usr/bin/twistd || exit 0
test -r $file || exit 0
test -r /usr/share/$PLUGIN/package-installed || exit 0

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.2-14) to ensure that this file is present
# and status_of_proc is working.
. /lib/lsb/init-functions

export PYTHONPATH=/usr/share/$PLUGIN:$PYTHONPATH

case "$1" in
    start)
        echo -n "Starting ${PLUGIN}: twistd"
        start-stop-daemon --start --quiet --exec /usr/bin/twistd -- \
                                  --pidfile=$pidfile  \
                                  --rundir=$rundir    \
                                  --logfile=$logfile  \
                                  $PLUGIN -c $config
        echo "."
    ;;

    stop)
        echo -n "Stopping $PLUGIN: twistd"
        start-stop-daemon --stop --quiet              --pidfile $pidfile
        echo "."
    ;;

    restart)
        $0 stop
        $0 start
    ;;

    force-reload)
        $0 restart
    ;;

    *)
        echo "Usage: /etc/init.d/$PLUGIN {start|stop|restart|force-reload}" >&2
        exit 3
    ;;
esac

:
