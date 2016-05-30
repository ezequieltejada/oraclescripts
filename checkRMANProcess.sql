#This query is useful to check the progress of an RMAN process.

#Example output:
#   SID START_TIME            TOTALWORK      SOFAR       DONE END_AT
#------ -------------------- ---------- ---------- ---------- -----------------
#  1281 30-05-16 10:35:17       3932160    2186237  55.598882 30/05/16 10:59:28

set lines 300
set pages 1000
col START_TIME for a20
col SID for 99999
select SID, to_char(START_TIME,'dd-mm-yy hh24:mi:ss') START_TIME,TOTALWORK, sofar, (sofar/totalwork) * 100 done,
sysdate + TIME_REMAINING/3600/24 end_at
from v$session_longops
where totalwork > sofar
AND opname NOT LIKE '%aggregate%'
AND opname like 'RMAN%';

###############################################################
#Example output:
#      ID DEVICE          DBSIZE_MB        READ_MB     WRITTEN_MB   % ORIG
#-------- ---------- -------------- -------------- -------------- --------
#COMPLETE % ESTIMATED COMPLETION
#---------- --------------------
#      40 DISK           519,443.94     275,316.00      46,591.00    16.92
#     53.00 30-MAY-2016 11:05:20

col dbsize_mbytes      for 99,999,990.00 justify right head "DBSIZE_MB"
col input_mbytes       for 99,999,990.00 justify right head "READ_MB"
col output_mbytes      for 99,999,990.00 justify right head "WRITTEN_MB"
col output_device_type for a10           justify left head "DEVICE"
col complete           for 990.00        justify right head "COMPLETE %" 
col compression        for 990.00        justify right head "COMPRESS|% ORIG"
col est_complete       for a20           head "ESTIMATED COMPLETION"
col recid              for 9999999       head "ID"

select recid
     , output_device_type
     , dbsize_mbytes
     , input_bytes/1024/1024 input_mbytes
     , output_bytes/1024/1024 output_mbytes
     , (output_bytes/input_bytes*100) compression
     , (mbytes_processed/dbsize_mbytes*100) complete
     , to_char(start_time + (sysdate-start_time)/(mbytes_processed/dbsize_mbytes),'DD-MON-YYYY HH24:MI:SS') est_complete
  from v$rman_status rs
     , (select sum(bytes)/1024/1024 dbsize_mbytes from v$datafile) 
 where status='RUNNING'
   and output_device_type is not null;
/
