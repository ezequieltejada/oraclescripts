#!/bin/bash
#
# File Name: backup.sh
# Author: Ezequiel E. Tejada (https://github.com/ezequieltejada)
# Description: Script to make backup and recovery of an Oracle Database painless.
# Call Syntax: -bash-4.1$ ./backup.sh
# Last Modified: 10-26-2017
#
clear

read -p 'Oracle SID: ' OSID
export ORACLE_SID=$OSID
echo 'Oracle Container SID set as:' $OSID

read -p 'Do you want to backup(b), incremental backup(ib), recover(r) or point in time recovery(pt)? [b]' BKPORCV

case $BKPORCV in
	"b"*)
rman target=/ << EOF
RUN {
  ALLOCATE CHANNEL ch1 TYPE 
    DISK FORMAT '/backup/%d_DB_%u_%s_%p'; 
  BACKUP DATABASE PLUS ARCHIVELOG;
  RELEASE CHANNEL ch1;
}
EXIT;
EOF
	;;
	"ib"*)
rman target=/ << EOF
RUN {
  ALLOCATE CHANNEL ch1 TYPE 
    DISK FORMAT '/backup/%d_DB_%u_%s_%p'; 
  BACKUP INCREMENTAL LEVEL 1 DATABASE PLUS ARCHIVELOG;
  RELEASE CHANNEL ch1;
}
EXIT;
EOF
	;;
	"r"*)
rman target=/ << EOF
RUN {
  ALLOCATE CHANNEL ch1 TYPE 
    DISK FORMAT '/backup/%d_DB_%u_%s_%p'; 
  SHUTDOWN IMMEDIATE;
  STARTUP MOUNT;
  RESTORE DATABASE;
  RECOVER DATABASE;
  ALTER DATABASE OPEN RESETLOGS;
  RELEASE CHANNEL ch1;
}
EXIT;
EOF
	;;
	"pt"*)
read -p 'Please specify until when you want to recover. Please respect the format (yyyy-mm-dd:hh24:mi:ss)' POINTINTIME
rman target=/ << EOF
RUN {
  ALLOCATE CHANNEL ch1 TYPE 
    DISK FORMAT '/backup/%d_DB_%u_%s_%p';
  SET UNTIL TIME "to_date('$POINTINTIME', 'yyyy-mm-dd:hh24:mi:ss')";
  SHUTDOWN IMMEDIATE;
  STARTUP MOUNT;
  RESTORE DATABASE;
  RECOVER DATABASE;
  ALTER DATABASE OPEN RESETLOGS;
  RELEASE CHANNEL ch1;
}
EXIT;
EOF
	;;
esac
exit