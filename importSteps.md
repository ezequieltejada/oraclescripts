#1) Check if the directory that holds the exports is in the dba_directories table
select * from dba_directories;

#2) If it is not created, create it.
create or replace directory exports as '{{DIRECTORY WHERE IS THE DUMP}}';

Get user recreation queries (Run it on origin, then run the result on destination DB):
``` sql
SELECT dbms_metadata.get_ddl('USER', :name)
  FROM dual
UNION ALL
SELECT dbms_metadata.get_granted_ddl('ROLE_GRANT', grantee)
  FROM dba_role_privs
 WHERE grantee = :name
   AND ROWNUM = 1
UNION ALL
SELECT dbms_metadata.get_granted_ddl('DEFAULT_ROLE', grantee)
  FROM dba_role_privs
 WHERE grantee = :name
   AND ROWNUM = 1
UNION ALL
SELECT dbms_metadata.get_granted_ddl('SYSTEM_GRANT', grantee)
  FROM dba_sys_privs          sp,
       system_privilege_map   spm
 WHERE sp.grantee = :name
   AND sp.privilege = spm.name
   AND spm.property <> 1
   AND ROWNUM = 1
UNION ALL
SELECT dbms_metadata.get_granted_ddl('OBJECT_GRANT', grantee)
  FROM dba_tab_privs
 WHERE grantee = :name
   AND ROWNUM = 1
UNION ALL
SELECT dbms_metadata.get_granted_ddl('TABLESPACE_QUOTA', username)
  FROM dba_ts_quotas
 WHERE username = :name
   AND ROWNUM = 1
```

#3) Create parameter file (parfile.lst) and set the parameters:
full=Y
dumpfile=name.dmp
logfile=nameLog.log
directory=exports
table_exists_action=replace

#4 Recreate tablespaces, roles, users (in that order)

#5) Run "impdp" as follows
impdp \"/ as sysdba\" parfile=parfile.lst
