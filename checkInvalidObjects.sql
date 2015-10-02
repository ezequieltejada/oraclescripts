#Chequear objetos invalidos en la base.
#Correr despues de ejecutar: @$ORACLE_HOME/rdbms/admin/utlrp.sql para compilar los objetos
COLUMN object_name FORMAT A30
SELECT owner,
       object_type,
       object_name,
       status
FROM   dba_objects
WHERE  status = 'INVALID'
ORDER BY owner, object_type, object_name;
