SET LINESIZE 100
COLUMN spid FORMAT A10
COLUMN username FORMAT A10
COLUMN program FORMAT A45

SELECT s.inst_id,
s.sid,
s.serial#,
p.spid,
s.username,
s.program
FROM gv$session s
JOIN gv$process p ON p.addr = s.paddr AND p.inst_id = s.inst_id
WHERE s.type != 'BACKGROUND';

SELECT username U_NAME, owner OBJ_OWNER,
object_name, object_type, s.osuser,
DECODE(l.block,
0, 'Not Blocking',
1, 'Blocking',
2, 'Global') STATUS,
DECODE(v.locked_mode,
0, 'None',
1, 'Null',
2, 'Row-S (SS)',
3, 'Row-X (SX)',
4, 'Share',
5, 'S/Row-X (SSX)',
6, 'Exclusive', TO_CHAR(lmode)
) MODE_HELD,
s.sid,
s.serial#
FROM gv$locked_object v, dba_objects d,
gv$lock l, gv$session s
WHERE v.object_id = d.object_id
AND (v.object_id = l.id1)
AND v.session_id = s.sid
ORDER BY username, session_id;

SELECT s1.username || '@' || s1.machine
|| ' ( SID=' || s1.sid || ' ) is blocking '
|| s2.username || '@' || s2.machine || ' ( SID=' || s2.sid || ' ) ' AS blocking_status
FROM v$lock l1, v$session s1, v$lock l2, v$session s2
WHERE s1.sid=l1.sid AND s2.sid=l2.sid
AND l1.BLOCK=1 AND l2.request > 0
AND l1.id1 = l2.id1
AND l1.id2 = l2.id2;


Si quieren matar agluna sesion en especifico usar:

ALTER SYSTEM KILL SESSION 'sid,serial#' IMMEDIATE;
