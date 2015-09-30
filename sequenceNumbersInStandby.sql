#Get the RESETLOGS_CHANGE# from the primary database:

SELECT RESETLOGS_CHANGE#
FROM V$DATABASE_INCARNATION
WHERE STATUS = 'CURRENT';

#On the target physical standby database, identify any active standby redo logs (SRL’s)

SELECT GROUP#, THREAD#, SEQUENCE#
FROM V$STANDBY_LOG
WHERE STATUS = 'ACTIVE'
ORDER BY THREAD#,SEQUENCE#;

#On the target physical standby database, identify maximum applied sequence number(s).

SELECT THREAD#, MAX(SEQUENCE#)
FROM V$LOG_HISTORY
WHERE RESETLOGS_CHANGE#=< resetlogs_change# from the primary V$DATABASE_INCARNATION.RESETLOGS_CHANGE# >
GROUP BY THREAD#;

#The last SEQUENCE# for each THREAD# from V$LOG_HISTORY on the target physical standby database should be close (the difference in log sequences < 3) to the SEQUENCE# for each THREAD# from V$THREAD on the primary database.
