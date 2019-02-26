## in terminal set UTF8
## NLS_LANG=AMERICAN_AMERICA.UTF8; export NLS_LANG

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
DECLARE
	CURSOR audit_tablespaces
	IS 
		SELECT definido.tablespace tablespace, definido.total total, TRUNC(NVL(usado.total,0),2) ocupado, TRUNC(NVL(usado.total*100/definido.total,0),2) porcentaje
		FROM (SELECT t.name AS tablespace, Sum(bytes)/1048576 AS total
		FROM v$tablespace t, v$datafile d
		WHERE d.ts#=t.ts#
		GROUP BY (t.name)) definido,
		(SELECT tablespace_name tablespace, sum(bytes)/1048576 AS total
		FROM dba_segments
		GROUP BY (tablespace_name)) usado
		WHERE definido.tablespace=usado.tablespace(+);

	CURSOR control_files
	IS
		select NVL(STATUS, 'OK') STATUS, NAME, IS_RECOVERY_DEST_FILE, BLOCK_SIZE, FILE_SIZE_BLKS from v$controlfile;

	CURSOR redolog
	IS 
		select (group#) redolog1, (sequence#) redolog2, bytes/1048576 redolog3, members redolog4, status redolog5, archived redolog6, to_char(FIRST_TIME, 'dd-mon-yy HH:MI:SS') redolog7 from v$log;
	
	CURSOR archivedredolog
	IS
		select max(sequence#) sequence, to_char(to_date(RESETLOGS_TIME,'dd-mon-yy'),'dd-mm-yyyy') archivedate from v$log_history where RESETLOGS_CHANGE# = (select max(RESETLOGS_CHANGE#) from v$log_history) group by RESETLOGS_TIME;			

	CURSOR lastbackupsquery
	IS			
		select *
		  from  
		( select session_key, input_type, status, to_char(start_time,'yyyy-mm-dd hh24:mi') start_time,to_char(end_time,'yyyy-mm-dd hh24:mi') end_time, trim(output_bytes_display) output_bytes_display, time_taken_display from v$rman_backup_job_details order by end_time desc ) 
		 where ROWNUM <= 3;

	CURSOR maxsequence
	IS
		select max(sequence#) sequence from v$log_history where thread# = (select max(thread#) from v$log_history);
BEGIN
	dbms_output.put_line('&ORA_DB');
	dbms_output.put_line('Control de espacio en los tablespaces.');
	dbms_output.put_line('Tablespace,Total,Ocupado,Porcentaje Ocupado');
	FOR tablespace_record IN audit_tablespaces LOOP
		dbms_output.put_line(trim(tablespace_record.tablespace||','||tablespace_record.total||','||tablespace_record.ocupado||','||tablespace_record.porcentaje));
	END LOOP;
	
	dbms_output.put_line('Control de estado de archivos.');
	dbms_output.put_line('Archivos de Control.');
	dbms_output.put_line('Estado,Nombre,¿Fue creado en el Flash Tamaño del Recovery Area?,Tamaño del Bloque,Tamaño del Controlfile');
	FOR controlfile_record IN control_files LOOP
		dbms_output.put_line(trim(controlfile_record.status||','||controlfile_record.name||','||controlfile_record.IS_RECOVERY_DEST_FILE||','||controlfile_record.BLOCK_SIZE||','||controlfile_record.FILE_SIZE_BLKS));
	END LOOP;

	dbms_output.put_line('Archivos de Redo Log.');
	dbms_output.put_line('Número de Grupo,Número de Secuencia,Tamaño en MB,Miembros,Estado,Estado del Archive,Primer uso');
	FOR redolog_record IN redolog LOOP
		dbms_output.put_line(trim(redolog_record.redolog1||','||redolog_record.redolog2||','||redolog_record.redolog3||','||redolog_record.redolog4||','||redolog_record.redolog5||','||redolog_record.redolog6||','||redolog_record.redolog7));
	END LOOP;

	dbms_output.put_line('Archivos Archive Redo Logs.');
	FOR record IN archivedredolog LOOP
		dbms_output.put_line(trim('Se controlaron los archive redo log (copias de los online redo logs) se disponían copias hasta el número de secuencia '|| record.sequence ||' con fecha del '|| record.archivedate ||', lo cual es correcto porque es el último archive generado.'));
	END LOOP;

	dbms_output.put_line('Ejecución de backups.');
	dbms_output.put_line('Identificador de sesion,Tipo de backup,Resultado,Hora de inicio,Hora de finalización,Tamaño del backup,Duración del backup');
	FOR record IN lastbackupsquery LOOP
		dbms_output.put_line(trim(record.session_key||','||record.input_type||','||record.status||','||record.start_time||','||record.end_time||','||record.output_bytes_display||','||record.time_taken_display));
	END LOOP;

	dbms_output.put_line('Sincronización de bases.');
	dbms_output.put_line('Numero de secuencia');
	FOR record IN maxsequence LOOP
		dbms_output.put_line(trim(record.sequence));
	END LOOP;
END;
/
EXIT;
