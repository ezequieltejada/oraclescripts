#!/bin/bash
# The objective of this script is to gather all the pathnames and sizes of all the datafiles, redologs, archivelogs and controlfiles used in a database.
# Author: Ezequiel E. Tejada.

## Tested On: 
#       10.2.0.4

#Usage: Run the script, it requests the SID of the database we want to audit and press enter. It will save the output in a log file with the same name as the SID

echo "Please set the ORACLE_SID:"
read sid

export ORACLE_SID=$sid; sqlplus -s "/ as sysdba" <<EOF
spool $sid.log;
col file_name format a50;
set feedback off;
set heading off;
set pagesize 50000;
select file_name || ',' || bytes/1024/1024 || ',MB' from dba_data_files;
select g.member||','||l.bytes/1024/1024|| ',MB' from v$log l,v$logfile g
where l.group# = g.group#;
select NAME||','||BLOCK_SIZE * FILE_SIZE_BLKS/1024/1024|| ',MB' from v$controlfile;
select NAME||','||BLOCKS * BLOCK_SIZE/1024/1024|| ',MB' from V$ARCHIVED_LOG;
quit
EOF
