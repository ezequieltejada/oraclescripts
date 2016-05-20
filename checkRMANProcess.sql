#This query is useful to check the progress of an RMAN process.
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
