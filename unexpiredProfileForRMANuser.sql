##Create the profile with the desided settings.

CREATE  PROFILE "DEFAULT_UNEXPIRE"  LIMIT CPU_PER_SESSION UNLIMITED
CPU_PER_CALL UNLIMITED
CONNECT_TIME UNLIMITED
IDLE_TIME UNLIMITED
SESSIONS_PER_USER UNLIMITED
LOGICAL_READS_PER_SESSION UNLIMITED
LOGICAL_READS_PER_CALL UNLIMITED
PRIVATE_SGA UNLIMITED
COMPOSITE_LIMIT UNLIMITED
PASSWORD_LIFE_TIME UNLIMITED
PASSWORD_GRACE_TIME 7
PASSWORD_REUSE_MAX UNLIMITED
PASSWORD_REUSE_TIME UNLIMITED
PASSWORD_LOCK_TIME 1
FAILED_LOGIN_ATTEMPTS UNLIMITED 
PASSWORD_VERIFY_FUNCTION NULL;

##Check profile's settings

select resource_name,resource_type, limit from dba_profiles where profile='DEFAULT_UNEXPIRE';

##Attach desired user to profile, where {{user}} is the desired user.

ALTER USER {{user}} PROFILE DEFAULT_UNEXPIRE;

##Check if the user has the correct profile, where {{user}} is the desired user (IN UPPERCASE).

select username, account_status, profile from dba_users where username in ('{{user}}');
