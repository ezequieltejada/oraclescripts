#Audit script for Oracle 9i instances.

DEFINE ORA_DB = &1
set term off
set feed off
set linesize 32767
SET PAGESIZE 0 
set feedback off
set verify off
SET TRIMSPOOL ON
SET TRIMOUT ON
set serveroutput on

spool Reporte_&ORA_DB\.txt

SELECT 'Tablespace,Total,Ocupado,Porcentaje Ocupado' FROM dual;
SELECT definido.tablespace||','||definido.total||','||TRUNC(NVL(usado.total,0),2)||','||TRUNC(NVL(usado.total*100/definido.total,0),2)
		FROM (SELECT t.name AS tablespace, NVL(NULLIF(Sum(bytes)/1048576,0),1) AS total
		FROM v$tablespace t, v$datafile d
		WHERE d.ts#=t.ts#
		GROUP BY (t.name)) definido,
		(SELECT tablespace_name tablespace, NVL(NULLIF(sum(bytes)/1048576,0),1) AS total
		FROM dba_segments
		GROUP BY (tablespace_name)) usado
WHERE definido.tablespace=usado.tablespace(+);

SELECT 'Estado,Nombre,¿Fue creado en el Flash Tamaño del Recovery Area?,Tamaño del Bloque,Tamaño del Controlfile' FROM dual;
select NVL(STATUS, 'OK')||','||NAME from v$controlfile;

SELECT 'Número de Grupo,Número de Secuencia,Tamaño en MB,Miembros,Estado,Estado del Archive,Primer uso' FROM dual;
select (group#)||','||(sequence#)||','||bytes/1048576||','||members||','||status||','||archived||','||to_char(FIRST_TIME, 'dd-mon-yy HH:MI:SS') from v$log;

select 'Se controlaron los archive redo log (copias de los online redo logs) se disponían copias hasta el número de secuencia '||sequence#||' con fecha del '||completion_time||', lo cual es correcto porque es el último archive generado.' from v$archived_log where sequence# = (select max(sequence#) from v$archived_log);

select 'Numero de secuencia '||max(sequence#) from v$log_history where thread# = (select max(thread#) from v$log_history);

EXIT;
