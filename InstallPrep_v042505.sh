####################################################################
# InstallPrep
#
# Author: jpeeken
# corrections/modifications should be addressed to john.peeken@oracle.com
#  042505 - changed TRU64 section to correctly handle vm-mapentries per OS version, starting with 5.0 it is autoset
#  042305 - Added SLES9 to Linux Certification
#  041005 - Added RHEL4 to Linux Certification and Solaris 10
#  040905 - Changed 9.2 TRU64 patchkit requriements to match Metalink Certification
#  031405 - Streamlined HP Memory determination
#  031305 - Changed su from an Alert to a Warning and unsupported to not suggested per TAR 15184152.6
#           Added to TRU64 vm_bigpg_enabled = 0 per RNEVILLE
#  030905 - Corrected dupatch error handling per TAR 15136484.6
#  030805 - Corrected AIX memory detection to be in Mb not Kb
#  030505 - Corrected Linux detection of SHMMAX and other kernel settings to review /proc/sys/kernel
#  030405 - Corrected AIX memory detection, it was truncating at 4 characters
#           Modified the test for a listener to do a 'ps' command
#
#  022305 - Removed the Media Verification portion due to it not being accurate with reference to OTN downloads
#           OTN downloads are fully supported if customer has a valid license
#  010105 - Replace prior InstallPrep script
#  8.7  (10/24/04) - updates to HP Section to handle error output from swlist, memory detection
#  8.6  (10/17/04) - updates to AIX to address, e.g. 5.2 5.3 as detailed in Note: 169706.1
#  8.5  (10/10/04) - changed script name to InstallPrep from preinstckr to be ready for use with Note: 189256.1
#  8.4  (10/09/04) - updated to handle HP-UX 11.22 and 11.23 reqts
#  8.3  (10/09/04) - updated to handle new patch reqts for HP-UX 11.11 and 9.2
#  8.2  (10/03/04) - Update to handle AIX 5.2/5.3 for 9.2
#  8.1  (8/7/03)   - Corrected issue with HP-UX libX symbolic links
#  8.0  (2/10/03)  - Added the required links for HP 9.2
#  7.9  (12/11/02) - Added tail -1 to dc outputs for HP-UX
#  7.8  (12/09/02) - Corrected parsing of the OSF patchkit level
#  7.7  (11/21/02) - Corrected SunOS .cshrc recommendations
#  7.6  (11/18/02) _ Value for SEMMSL on SunOS was set to 100 and was corrected to 256
#  7.5  (10/18/02) - Added java version verification
#  7.4  (10/18/02) - Added bos.perf.libperfstat as a required package for AIX 5L 9.2.0
#  7.3  (10/14/02) - Changing HP-UX kernel gathering to first use kmtune, if not available use /stand/system
#  7.2  (10/10/02) - Corrected certification issue with Sun and 64bit versions
#  7.1  (10/8/02) - Corrected the HP-UX kernel gathering to not use /stand/system but kmtune
#  7    (10/2/02) - Added Linux flavor release checking to fill in the lack of certification checking
#  6.9  (10/1/02) - Added 920 Red Hat certification checking
#  6.8  (9/30/02) - Changed wording of Swap-to-Memory alerts to show present value of SWAP
#  6.7  (9/26/02) - corrected new_wire_method search and patchkit verification
#  6.6  (9/18/02) - Numerous text formatting changes
#  6.5  (9/16/02) - Modified the AIX 5.1 Certification checking
#  6.4  (9/10/02) - Added more specific checking of AIX 920 OS patches per os version
#  6.3  (9/9/02)  - Removed redundant INFO messages about HP-UX patches not being found
#  6.2  (9/9/02)  - Added more thorough HP patch verfication that deals with present
#                   patches and there supercessions.
#  6.1  (8/27/02) - 
#  6    (8/23/02) - Added verification of media and switch user (su'ing to oracle)
#                   Updated HP-UX kernel checking to not check 64bit params when 32bit
#                   Added permission verifications on Oracle_Home
#  5.09 (8/21/02) - Added listener check
#  5.08 (8/21/02) - Changed all kernel parameters undefined to show the value they should be set to
#  5.07 (8/21/02) - Changed determination of the OSF patchkits and Sun SEMMNS check
#  5.06 (8/16/02) - Exception handling for Assembly Tools when not found at all
#  5.05 (8/15/02) - Corrected SWAP determination error on SunOS
#  5.04 (8/14/02) - Corrected checking for 9.2.0.1 LD_LIBRARY_PATH, SHLIB_PATH, and LIBPATH
#  5.03 (8/9/02)- Textual cleanup
#  5.02 (8/9/02)- Completed SWAP checking and handle larger RAM sizes
#  Version 5.01 - Changed SWAP checking algorithm to deal with large RAM
#  Version 5    - Added RAC checking and Display checking from rneville's InstallPrep script
#  Version 4.11 - Added BOXNAME based on running hostname versus using $HOST
#  Version 4.09 - Changed SunOS to add Solaris 2.9 to certification
#                 Added WARNINGCOUNT and changed assembly tools alerts to be warnings
#                 Commented out checking for SHMMIN on HP since it is not setable
#  Version 4.08 - Changed HP-UX 805-816 maxdsiz_64bit to not be checked when a 32bit install
#  Version 4.07 - Changed the location of the output file, InstallPrep.out to not assume that /tmp is set 
#                 and if not located and writable to ask user for alternate location
#  Version 4.06 - Changed SunOS Swap checking to deal better with Swap when it is already over a gig
#  Version 4.05 - Changed ulimit on SunOS for NOFILES from 1024 to 256
#  Version 4.04 - Changed Certification to reflect SHOWSTOPPER when install is uncertified.
#                 Added exception handling for dupatch
#  Version 4.03 - Changed the ALERT total wording.  Changed SWAP to MEMORY checking to reflect better error when SWAP is not determined.
#  Version 4.02 - Changed checking of AIX patches to have it consider the full os release and 
#                 then decide which patches need to be checked.
#  Version 4.01 - Corrected query for determining if the installing user is present in the /etc/passwd, the specified
#                 group is present in /etc/group and also determining the users shell.
#  Version 4.00	- Removing the Spanish version, for now, until the English version 
#                 has complete exception handling.
#  Version 3.10 - Changing handling of Swap
#  Version 3.09 - Added exception handling if /etc/passwd or /etc/group are not readable
#  Version 3.08 - Corrected HPUX 817 patch checking
#  Version 3.07 - Added ALERT counting and code cleanup.
#  Version 3.06 - Correction of logic when verifying TEMP, TMP
#  Version 3.05 - Completed adding checking for TEMP, TMP env variables
#  Version 3.04 - Added checking for TEMP, TMP env variables
#  Version 3.03 - Revised the HP-UX kernel parameter handling, turns out the
#                 shell is able to determine value in formulas and make comparisons within
#                 this script, even though the script cannot display the actual value,
#                 but can show the formula.               
#  Version 3.02 - removed
#  Version 3.01 - Added checking for AIX Maintenance Levels
#  Version 3.00 - Added Spanish version
#  Version 2.04 - corrected ulimit checking error
#  Version 2.03 - added Tru64 920 5.1, 5.1A checking for directio patchkits
#                 added showing present settings for kernel params
#  Version 2.02 - added ulimit checking
#  Version 2.01 - Fixed Linux Certification issue
#                 Note:  For Linux best to ftp via ascii not binary
#  Version 2.00 - Added 9.2.0.1 to script for all platforms
#  Version 1.12 - Added hostname and date to output
#                 show where assembly tools are incorrectly found
#                 Corrected AIX Swap to reflect Mb
#                 Corrected AIX OS Package State 'uniq -d' to 'uniq'
#                 umask to echo what it is set to
#  Version 1.11 - OSF1 Patchkit Verification
#
# This script is designed to check your Server to ensure that it has adequate
# resources to successfully install the Oracle database software.
# This script will generate a reports called InstallPrep.out and InstallPrep.err in /tmp.
# InstallPrep.out is the complete report and InstallPrep.err is just the errors
#
# Instructions:
# 1. Log in as the unix user that will be installing the Oracle software
#    and do not 'su' from another user to this user.
# 2. Run this script.
# 3. Fix any ALERTS that are reported in the /tmp/InstallPrep.out
# 4. You will now be ready to successfully install your Oracle software
####################################################################

if /usr/bin/test -d /tmp || /usr/bin/test -w /tmp
then
  REPORT=/tmp/InstallPrep.out
  REPORTERR=/tmp/InstallPrep.err
else
  echo "The /tmp directory either does not exist or is not writable by this user" 
  echo "Please input an alternate directory that is writable by this user to send the InstallPrep.out file to (i.e. /etc ): " 
  read ALTDIR
  REPORT=$ALTDIR/InstallPrep.out
  REPORTERR=$ALTDIR/InstallPrep.err
fi

OS=`uname -s`
BOXNAME=`hostname`
ALERTCOUNT=0
WARNINGCOUNT=0
SHOWSTOPPERCOUNT=0

case $OS in
"AIX")
OSVER6CHAR=`/usr/bin/oslevel -r | /usr/bin/sed 's/-//''`
OSVER3CHAR=`/usr/bin/oslevel -r | /usr/bin/awk '{print substr($1,1,3)}'`
OSBIT=`/usr/bin/lslpp -L | /usr/bin/grep bos.64bit | /usr/bin/awk '{print $1}' | /usr/bin/sed 's/bos.//' | /usr/bin/sed 's/bit//'`
OSSTATE=`/usr/bin/lslpp -L | /usr/bin/grep bos.64bit | /usr/bin/awk '{print $3}'`
if [ $OSBIT = 64 ] && [ $OSSTATE = "C" ]
then 
  OSBIT=64
elif [ $OSBIT = 64 ] && [ $OSSTATE = "A" ]
then
  OSBIT=32
  /usr/bin/echo "WARNING: bos.64bit package is not committed, so treating OS as 32bit"
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  OSBIT=32
fi



# AIX START ECHO OF SCRIPT TO OUTPUT FILE

`/usr/bin/touch $REPORT; /usr/bin/chmod 777 $REPORT`
/usr/bin/echo "\nOutput from the Oracle InstallPrep Script run on $BOXNAME on `date`.\n \n \n" > $REPORT
/usr/bin/echo "To successfully install the Oracle Database Software you must resolve" >> $REPORT
/usr/bin/echo "each item listed in this Report. \n \n"  >> $REPORT
/usr/bin/echo "\n\n\nInstallPrep now running on your $OS $OSBIT bit box....." | /usr/bin/tee -a $REPORT


#  AIX ORACLE VERSION INPUT

/usr/bin/echo "\n\n\nOracle Version Input" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_______________________\n" | /usr/bin/tee -a $REPORT
/usr/bin/echo "What version of Oracle are you installing?\n (valid values:805,806,815,816,817,901,920):" | /usr/bin/tee -a $REPORT
read ORAVER
/usr/bin/echo $ORAVER >> $REPORT
case $ORAVER in
  "805"|"806"|"815"|"816"|"817"|"901"|"920")
     ;;
  "")
    /usr/bin/echo "\nALERT-  You did not enter a value" | /usr/bin/tee -a $REPORT 
    exit
    ;;
  *)
    /usr/bin/echo "\nALERT-  You have entered an invalid version - enter valid value" | /usr/bin/tee -a $REPORT
    exit
    ;;
esac

# AIX ORACLE BIT SIZE INPUT

/usr/bin/echo "\n\n\nOracle Bit Size Input" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT

/usr/bin/echo "What bit version of Oracle are you installing (32 or 64)?" | /usr/bin/tee -a $REPORT
read ORABIT
/usr/bin/echo $ORABIT >> $REPORT
case $ORABIT in
  "32"|"64")
     ;;
  "")
    /usr/bin/echo "\nALERT-  You did not enter a value" | /usr/bin/tee -a $REPORT
    exit
    ;;
  *)
    /usr/bin/echo "\nALERT-  You have entered an invalid version - enter valid value" | /usr/bin/tee -a $REPORT
    exit
    ;;
esac

# AIX CORRECT USER VERIFICATION

/usr/bin/echo "\n\n\nUser Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
USER=`/usr/bin/who -m | /usr/bin/awk '{print $1}'`
if [ $USER = "root" ]
then
  /usr/bin/echo "\nALERT-  You are logged in as user -- $USER -- " | /usr/bin/tee -a $REPORT
  /usr/bin/echo "Please log in as the user that will be installing the Oracle Database" | /usr/bin/tee -a $REPORT
  /usr/bin/echo "Software. This user should not be root." | /usr/bin/tee -a $REPORT
  /usr/bin/echo "Exiting" | /usr/bin/tee -a $REPORT
  exit;
else
  /usr/bin/echo "\nYou are currently logged on as user -- $USER -- \n" | /usr/bin/tee -a $REPORT
fi

# AIX CONFIRMATION OF USER

/usr/bin/echo "Is user $USER the unix user that will be installing Oracle Software?  (y or n)" | /usr/bin/tee -a $REPORT
read answer
/usr/bin/echo $answer >> $REPORT
case $answer in
  "n"|"N")
    /usr/bin/echo "\nExiting-  Please log in as the user that will be installing Oracle. Then rerun this script \n" | /usr/bin/tee -a $REPORT
    exit
    ;;
  "y"|"Y")
    /usr/bin/echo "\n \n \n Verifying User in /etc/passwd" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "______________________________________\n" | /usr/bin/tee -a $REPORT
    if /usr/bin/test -r /etc/passwd
    then
      if [ "$USER" =  `/usr/bin/cat /etc/passwd | /usr/bin/awk -F: '{print $1}' | /usr/bin/grep -w $USER` ]
      then
        /usr/bin/echo "User $USER correctly exists in /etc/passwd \n" | /usr/bin/tee -a $REPORT
      else
        /usr/bin/echo "ALERT-  The unix user -- $USER -- is not in /etc/passwd - You must add user $USER to the /etc/passwd file. NIS managed users are not recommended" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      fi
    else
      /usr/bin/echo " ALERT-  User $USER is not allowed read access to the /etc/passwd file, verification of user $USER in /etc/passwd can not be performed, please get with your System Administrator to have them verify the presence of the user $USER in the /etc/passwd file" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
    ;;
  "")
    /usr/bin/echo "\nALERT-  You did not enter a value" | /usr/bin/tee -a $REPORT
    exit
    ;;
  *)
    /usr/bin/echo "\nALERT-  You have entered an invalid value - enter valid value" | /usr/bin/tee -a $REPORT
    exit
    ;;
esac

# AIX SU VERIFICATION

/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo "Switching User (su) verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________________" | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo "Are you switching user (su) from another user to become the $USER user? (Y/N):" | /usr/bin/tee -a $REPORT
read SUORACLE
/usr/bin/echo $SUORACLE >> $REPORT
case $SUORACLE in
  "Y"|"y")
      /usr/bin/echo " " | /usr/bin/tee -a $REPORT
      /usr/bin/echo "WARNING: Switching User (su) is not suggested, you should login as $USER user directly when doing the install" | /usr/bin/tee -a $REPORT
      WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
      ;;
  "N"|"n")
      /usr/bin/echo " " | /usr/bin/tee -a $REPORT
      /usr/bin/echo "Passed switch user (su) test" | /usr/bin/tee -a $REPORT
      ;;
  *)
      /usr/bin/echo " " | /usr/bin/tee -a $REPORT
      /usr/bin/echo "You have entered an invalid answer, exiting InstallPrep, please try again" | /usr/bin/tee -a $REPORT
      exit
      ;;
esac

# AIX CONFIRMATION OF GROUP

/usr/bin/echo "\n\n\nGroup Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
/usr/bin/echo "Enter the unix group that will be used during the installation (example: dba)?" | /usr/bin/tee -a $REPORT
read GROUP
/usr/bin/echo $GROUP >> $REPORT
case $GROUP in
  "") 
    /usr/bin/echo "\nALERT- You did not enter a value" | /usr/bin/tee -a $REPORT
    exit
   ;;
  *)
    if /usr/bin/test -r /etc/group
    then
      if [ "$GROUP" = "`/usr/bin/cat /etc/group | /usr/bin/awk -F: '{print $1}' | /usr/bin/grep -w $GROUP`" ]
      then
        /usr/bin/echo "-- $GROUP -- exists in /etc/group" | /usr/bin/tee -a $REPORT
      else
        /usr/bin/echo "ALERT-  You must create the unix group -- $GROUP -- as the root user and add -- $USER -- to this group or select a different unix group that already exists in /etc/group\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      fi
    else
      /usr/bin/echo " ALERT-  User $USER is not allowed read access to the /etc/group file, verification of $GROUP in /etc/group can not be performed, please get with your System Administrator to have them verify the presence of the $GROUP in the /etc/group file" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
    ;;
esac

# AIX CONFIRMATION OF ORACLE_HOME

/usr/bin/echo "\n\n\nSpecify ORACLE_HOME" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT

if /usr/bin/test $ORACLE_HOME
then
  /usr/bin/echo "Presently, your ORACLE_HOME is set to $ORACLE_HOME, is this the correct location that this installation will be using? (Y/N)" | /usr/bin/tee -a $REPORT
  read CFRM
  if [ $CFRM = "Y" -o $CFRM = "y" ]
  then 
    OH=$ORACLE_HOME
    /usr/bin/echo $OH >> $REPORT
  else
    /usr/bin/echo "Enter Location where you will be installing Oracle (example: /u01/app/oracle/product/8.1.7)" | /usr/bin/tee -a $REPORT
    read OH
    /usr/bin/echo $OH >> $REPORT
  fi
else
  /usr/bin/echo "Enter Location where you will be installing Oracle (example: /u01/app/oracle/product/8.1.7)" | /usr/bin/tee -a $REPORT
  read OH
  /usr/bin/echo $OH >> $REPORT
fi
if /usr/bin/test -z "$OH"
then
  /usr/bin/echo "\nALERT-  You did not provide the location that Oracle will be installed, setting your ORACLE_HOME to No_Location_Given" | /usr/bin/tee -a $REPORT
  OH=No_Location_Given
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi

# AIX VERIFICATION OF PERMISSIONS ON INPUT ORACLE_HOME

/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo "ORACLE_HOME permission verifications" | /usr/bin/tee -a $REPORT
/usr/bin/echo "____________________________________" | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT

ALERTCOUNTPRIOR=$ALERTCOUNT
if [ $OH != "No_Location_Given" ]
then
  if /usr/bin/test -x $OH
  then
    if /usr/bin/test -r $OH
    then
      /usr/bin/echo "User $USER has read permission to $OH" | /usr/bin/tee -a $REPORT
    else
      /usr/bin/echo "ALERT: User $USER does not have read permissions for $OH" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
    if /usr/bin/test -w $OH
    then
      /usr/bin/echo "User $USER has write permission to $OH" | /usr/bin/tee -a $REPORT
    else
      /usr/bin/echo "ALERT: User $USER does not have write permissions for $OH" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
    if /usr/bin/test -x $OH
    then
      /usr/bin/echo "User $USER has execute permission to $OH" | /usr/bin/tee -a $REPORT
    else
      /usr/bin/echo "ALERT: User $USER does not have execute permissions for $OH" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
  else
    /usr/bin/echo "ALERT: $OH does not exist, please create the $OH mount point and ensure the permissions are correctly set" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  fi
else
  /usr/bin/echo "ORACLE_HOME permissions cannot be verified since $OH" | /usr/bin/tee -a $REPORT
fi

if [ $ALERTCOUNTPRIOR = $ALERTCOUNT ]
then
  /usr/bin/echo "$OH has correct permissions for user $USER" | /usr/bin/tee -a $REPORT
else
  /usr/bin/echo "ALERT: The specified ORACLE_HOME=$OH does not have correct permissions, please have your System Administrator correct the permissions to "rwx" for the ORACLE_HOME mount point" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi

# AIX LIST WHAT UMASK AND UNIX ENVIRONMENT VARIABLES NEED TO BE SET

/usr/bin/echo "\n\n\nUmask Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
MASK=`umask`
if [ $MASK -eq 022 ]
then
  /usr/bin/echo "umask of $MASK is set correctly \n" | /usr/bin/tee -a $REPORT
else
  /usr/bin/echo "ALERT-  umask is set to $MASK but must be set to 022 \n" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi

# AIX LIST OUT THE PATH, LD_LIBRARY_PATH, and SHLIB_PATH

/usr/bin/echo "\n\n\nEnvironmental Variables (as set in user $USER's environment)" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
if [ $ORAVER != 920 ]
then
  if /usr/bin/test $ORACLE_HOME
  then
    /usr/bin/echo "ORACLE_HOME=$ORACLE_HOME" | /usr/bin/tee -a $REPORT
  fi
  if /usr/bin/test $PATH
  then
    /usr/bin/echo "PATH=$PATH" | /usr/bin/tee -a $REPORT
  fi
  if /usr/bin/test $LD_LIBRARY_PATH
  then
    /usr/bin/echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" | /usr/bin/tee -a $REPORT
  fi
  if /usr/bin/test $LIBPATH
  then
    /usr/bin/echo "LIBPATH=$LIBPATH" | /usr/bin/tee -a $REPORT
  fi
else
  if /usr/bin/test $ORACLE_HOME
  then
    /usr/bin/echo "ORACLE_HOME=$ORACLE_HOME" | /usr/bin/tee -a $REPORT
  fi
  if /usr/bin/test $PATH
  then
    /usr/bin/echo "PATH=$PATH" | /usr/bin/tee -a $REPORT
  fi
  if /usr/bin/test $LIBPATH
  then
    /usr/bin/echo "LIBPATH=$LIBPATH" | /usr/bin/tee -a $REPORT
  fi
fi


/usr/bin/echo "\n\n\n.cshrc or .profile Recommended Variable Settings" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
if [ $ORAVER != 920 ] 
then
  if /usr/bin/test -r /etc/passwd
  then
    SH=`/usr/bin/cat /etc/passwd | /usr/bin/awk -F: '{print $1, $NF}' | /usr/bin/grep -w $USER | /usr/bin/awk -F/ '{print $NF}'`
    /usr/bin/echo "INFO- Your shell is $SH\n" | /usr/bin/tee -a $REPORT 
    if [ "$SH" = csh ]
    then
      /usr/bin/echo "The following environment variables must be set in your .cshrc file for the $USER user." | /usr/bin/tee -a $REPORT
      /usr/bin/echo "setenv ORACLE_HOME $OH" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "setenv LIBPATH $OH/lib:/usr/lib:/lib" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "setenv LD_LIBRARY_PATH $OH/lib:$OH/network/lib" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "setenv PATH $OH/bin:/usr/ccs/bin:$PATH" | /usr/bin/tee -a $REPORT
    else
      /usr/bin/echo "The following environment variables must be set in your .profile file for the $USER user." | /usr/bin/tee -a $REPORT
      /usr/bin/echo "ORACLE_HOME=$OH" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "LIBPATH=$OH/lib:/usr/lib:/lib" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "LD_LIBRARY_PATH=$OH/lib:$OH/network/lib" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "PATH=$OH/bin:/usr/ccs/bin:$PATH" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "export \$ORACLE_HOME" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "export \$LIBPATH" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "export \$LD_LIBRARY_PATH" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "export \$PATH" | /usr/bin/tee -a $REPORT
    fi
  else
    /usr/bin/echo "ALERT- Your shell cannot be determined due to user $USER not having read priviledge to the /etc/passwd file" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  fi
else
  if /usr/bin/test -r /etc/passwd
  then
    SH=`/usr/bin/cat /etc/passwd | /usr/bin/awk -F: '{print $1, $NF}' | /usr/bin/grep -w $USER | /usr/bin/awk -F/ '{print $NF}'`
    /usr/bin/echo "INFO- Your shell is $SH\n" | /usr/bin/tee -a $REPORT 
    if [ "$SH" = csh ]
    then
      /usr/bin/echo "The following environment variables must be set in your .cshrc file for the $USER user." | /usr/bin/tee -a $REPORT
      /usr/bin/echo "setenv ORACLE_HOME $OH" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "setenv LIBPATH $OH/lib32:$OH/lib:/usr/lib:/lib" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "setenv PATH $OH/bin:/usr/ccs/bin:$PATH" | /usr/bin/tee -a $REPORT
    else
      /usr/bin/echo "The following environment variables must be set in your .profile file for the $USER user." | /usr/bin/tee -a $REPORT
      /usr/bin/echo "ORACLE_HOME=$OH" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "LIBPATH=$OH/lib32:$OH/lib:/usr/lib:/lib" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "PATH=$OH/bin:/usr/ccs/bin:$PATH" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "export \$ORACLE_HOME" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "export \$LIBPATH" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "export \$PATH" | /usr/bin/tee -a $REPORT
    fi
  else
    /usr/bin/echo "ALERT- Your shell cannot be determined due to user $USER not having read priviledge to the /etc/passwd file" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  fi
fi

if [ "$OH" = "No_Location_Given" ]
then
  /usr/bin/echo "\nALERT- When running this script you did not provide a location where Oracle will be installed. Change the value of No_Location_Given to the location where Oracle will be installed in." | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi


# AIX /tmp SPACE VERIFICATION

/usr/bin/echo "\n \n \nTMP space Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_______________________\n" | /usr/bin/tee -a $REPORT
/usr/bin/echo "FYI: The runInstaller (OUI) uses/checks for temporary space by checking first for the TEMP environmental variable, then the TMP environmental variable and lastly the actual '/tmp' mount point" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_______________________\n" | /usr/bin/tee -a $REPORT 
TMPMT=`/usr/bin/df -k /tmp | /usr/bin/awk '{print $3}' |  /usr/bin/sed '1d'`
TMPMT=`/usr/bin/expr $TMPMT / 1024`
if [ `/usr/bin/env | /usr/bin/grep -ic "TEMP="` -ne 0 ]
then
  TEMPLOC=`/usr/bin/env | /usr/bin/grep "TEMP=" | /usr/bin/awk -F= '{print $2}'`
  if /usr/bin/test -d $TEMPLOC
  then
    TEMP=`/usr/bin/df -k "$TEMPLOC" | /usr/bin/awk '{print $3}' | /usr/bin/sed '1d'`
    TEMP=`/usr/bin/expr $TEMP / 1024`
    /usr/bin/echo "The TEMP variable was found set to $TEMPLOC in your environment and has $TEMP Mb of free space" | /usr/bin/tee -a $REPORT
  else
    /usr/bin/echo "ALERT- The TEMP variable was found set in your environment but is either an invalid value or is not a directory. Please set TEMP correctly or to a valid, writable directory or unset if the InstallPrep determines you have adequate space in /tmp" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  fi
elif [ `/usr/bin/env | /usr/bin/grep -ic "TMP="` -ne 0 ]
then
  TMPLOC=`/usr/bin/env | /usr/bin/grep "TMP=" | /usr/bin/awk -F= '{print $2}'`
  if /usr/bin/test -d $TMPLOC
  then
    TMP=`/usr/bin/df -k "$TMPLOC" | /usr/bin/awk '{print $3}' | /usr/bin/sed '1d'`
    TMP=`/usr/bin/expr $TMP / 1024`
    /usr/bin/echo "The TMP variable was found set to $TMPLOC in your environment and has $TMP Mb of free space" | /usr/bin/tee -a $REPORT
  else
    /usr/bin/echo "ALERT- The TMP variable was found set in your environment but is either an invalid value or is not a directory.  Please set TMP correctly or to a valid, writable directory or unset if the InstallPrep determines you have adequate space in /tmp" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  fi
fi
case $ORAVER in
  "805"|"806")
     if /usr/bin/test -n "$TEMP" 
     then 
       if [ $TEMP -lt 20 ]
       then
         /usr/bin/echo "ALERT- TEMP is set in the environment and has less than the required 20 Mb.  Please point the TEMP environmental variable to a mount point with at least 20 Mb of free space" | /usr/bin/tee -a $REPORT 
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TEMPLOC"
         then
           /usr/bin/echo "TEMP set to $TEMPLOC has adequate space of $TEMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TEMP is set in the environment; however, $TEMPLOC does not have write permissions for this user" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMP"
     then
       if [ $TMP -lt 20 ]
       then
         /usr/bin/echo "ALERT- TMP is set in the environment and has less than the required 20 Mb.  Please point the TMP environmental variable to a mount point with at least 20 Mb of free space" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TMPLOC"
         then
           /usr/bin/echo "TMP set to $TMPLOC has adequate space of $TMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TMP is set in the environment; however, $TMPLOC does not have write permissions for this user" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMPMT"
     then
       if [ $TMPMT -lt 20 ]
       then
         /usr/bin/echo "ALERT- /tmp space = $TMPMT Mb, please increase /tmp to at least 20 Mb\n" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         /usr/bin/echo "/tmp has adequate space of $TMPMT Mb\n" | /usr/bin/tee -a $REPORT
       fi
     else
       /usr/bin/echo "ALERT-  /tmp is not specified\n" | /usr/bin/tee -a $REPORT
       ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
     fi
     ;;
   "815")
     if /usr/bin/test -n "$TEMP"
     then 
       if [ $TEMP -lt 50 ]
       then
         /usr/bin/echo "ALERT- TEMP is set in the environment and has less than the required 50 Mb.  Please point the TEMP environmental variable to a mount point with at least 50 Mb of free space" | /usr/bin/tee -a $REPORT 
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TEMPLOC"
         then
           /usr/bin/echo "TEMP set to $TEMPLOC has adequate space of $TEMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TEMP is set in the environment; however, $TEMPLOC does not have write permissions for this user" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMP"
     then
       if [ $TMP -lt 50 ]
       then
         /usr/bin/echo "ALERT- TMP is set in the environment and has less than the required 50 Mb.  Please point the TMP environmental variable to a mount point with at least 50 Mb of free space" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TMPLOC"
         then
           /usr/bin/echo "TMP set to $TMPLOC has adequate space of $TMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TMP is set in the environment; however, $TMPLOC does not have write permissions for this user" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMPMT"
     then
       if [ $TMPMT -lt 50 ]
       then
         /usr/bin/echo "ALERT- /tmp space = $TMPMT Mb, please increase /tmp to at least 50 Mb\n" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         /usr/bin/echo "/tmp has adequate space of $TMPMT Mb\n" | /usr/bin/tee -a $REPORT
       fi
     else
       /usr/bin/echo "ALERT-  /tmp is not specified\n" | /usr/bin/tee -a $REPORT
       ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
     fi
     ;;
   "816"|"817")
     if /usr/bin/test -n "$TEMP"
     then 
       if [ $TEMP -lt 75 ]
       then
         /usr/bin/echo "ALERT- TEMP is set in the environment and has less than the required 75 Mb.  Please point the TEMP environmental variable to a mount point with at least 75 Mb of free space" | /usr/bin/tee -a $REPORT 
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TEMPLOC"
         then
           /usr/bin/echo "TEMP set to $TEMPLOC has adequate space of $TEMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TEMP is set in the environment; however, $TEMPLOC does not have write permissions for this user" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMP"
     then
       if [ $TMP -lt 75 ]
       then
         /usr/bin/echo "ALERT- TMP is set in the environment and has less than the required 75 Mb.  Please point the TMP environmental variable to a mount point with at least 75 Mb of free space" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TMPLOC"
         then
           /usr/bin/echo "TMP set to $TMPLOC has adequate space of $TMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TMP is set in the environment; however, $TMPLOC does not have write permissions for this user" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMPMT"
     then
       if [ $TMPMT -lt 75 ]
       then
         /usr/bin/echo "ALERT- /tmp space = $TMPMT Mb, please increase /tmp to at least 75 Mb\n" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         /usr/bin/echo "/tmp has adequate space of $TMPMT Mb\n" | /usr/bin/tee -a $REPORT
       fi
     else
       /usr/bin/echo "ALERT-  /tmp is not specified\n" | /usr/bin/tee -a $REPORT
       ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
     fi
     ;;
   "901"|"920")
     if /usr/bin/test -n "$TEMP"
     then 
       if [ $TEMP -lt 400 ]
       then
         /usr/bin/echo "ALERT- TEMP is set in the environment and has less than the required 400 Mb.  Please point the TEMP environmental variable to a mount point with at least 400 Mb of free space" | /usr/bin/tee -a $REPORT 
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TEMPLOC"
         then
           /usr/bin/echo "TEMP set to $TEMPLOC has adequate space of $TEMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TEMP is set in the environment; however, $TEMPLOC does not have write permissions for this user" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMP"
     then
       if [ $TMP -lt 400 ]
       then
         /usr/bin/echo "ALERT- TMP is set in the environment and has less than the required 400 Mb.  Please point the TMP environmental variable to a mount point with at least 400 Mb of free space" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TMPLOC"
         then
           /usr/bin/echo "TMP set to $TMPLOC has adequate space of $TMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TMP is set in the environment; however, $TMPLOC does not have write permissions for this user" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMPMT"
     then
       if [ $TMPMT -lt 400 ]
       then
         /usr/bin/echo "ALERT- /tmp space = $TMPMT Mb, please increase /tmp to at least 400 Mb\n" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         /usr/bin/echo "/tmp has adequate space of $TMPMT Mb\n" | /usr/bin/tee -a $REPORT
       fi
     else
       /usr/bin/echo "ALERT-  /tmp is not specified\n" | /usr/bin/tee -a $REPORT
       ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
     fi
     ;;
    *)
     /usr/bin/echo ""
     ;;
esac

# AIX SWAP VERIFICATION

/usr/bin/echo "\n\n\nSwap Space Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
if /usr/bin/test -x /usr/sbin/lsps
then
  SWAP=`/usr/sbin/lsps -s | /usr/bin/awk '{print $1}' | /usr/bin/sed '1d' | /usr/bin/sed 's/MB/ /'`
  if /usr/bin/test -z "$SWAP"
  then 
    /usr/bin/echo "ALERT- SWAP has not been setup or specified" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "Swap is $SWAP Mb\n" | /usr/bin/tee -a $REPORT
  fi
else 
  /usr/bin/echo "ALERT- Your Swap cannot be determined due to user $USER not having execute priviledge to run /usr/sbin/lsps, please have your System Administrator grant execute permission on /usr/sbin or have them do '/usr/sbin/lsps -s | /usr/bin/awk '{print $1}' | /usr/bin/sed '1d' | /usr/bin/sed 's/MB/ /' to determine the amount of Swap" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi

# AIX MEMORY VERIFICATION

/usr/bin/echo "\n\n\nMemory Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "___________________\n" | /usr/bin/tee -a $REPORT

if /usr/bin/test -x /usr/sbin/lsattr
then
  MEM=`/usr/sbin/lsattr -HE -l sys0 -a realmem | /usr/bin/sed '1d' | /usr/bin/sed '1d' | /usr/bin/awk '{print substr($2,1,8)}'`
  MEM=`/usr/bin/expr $MEM / 1024`
  TWOM=`/usr/bin/expr $MEM \* 2`
  THREM=`/usr/bin/expr $MEM \* 3`
  MEMBY=`/usr/bin/expr $MEM \* 1024 \* 1024`
  if [ $ORAVER = "805" -o $ORAVER = "806" -o $ORAVER = "815" -o $ORAVER = "816" ]
  then
    if [ $MEM -lt 128 ]
    then
      /usr/bin/echo "ALERT-  You have $MEM Mb of memory. This is not enough to install Oracle $ORAVER $ORABIT bit.  You must have at least 128Mb\n" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /usr/bin/echo "You have $MEM Mb of memory which is adequate to install Oracle $ORAVER $ORABIT bit" | /usr/bin/tee -a $REPORT
    fi
  elif [ $ORAVER = "817" ]
  then
    if [ $MEM -lt 512 ]
    then
      /usr/bin/echo "ALERT-  You have $MEM Mb of memory. This is not enough to install Oracle $ORAVER $ORABIT bit.  You must have at least 256Mb\n" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /usr/bin/echo "You have $MEM Mb of memory which is adequate to install Oracle $ORAVER $ORABIT bit" | /usr/bin/tee -a $REPORT
    fi
  elif [ $ORAVER = "901" -o $ORAVER = "920" ]
  then
    if [ $MEM -lt 512 ]
    then
      /usr/bin/echo "ALERT-  You have $MEM Mb of memory. This is not enough to install Oracle $ORAVER $ORABIT bit.  You must have at least 256Mb\n" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /usr/bin/echo "You have $MEM Mb of memory which is adequate to install Oracle $ORAVER $ORABIT bit" | /usr/bin/tee -a $REPORT
    fi
  fi
else
  /usr/bin/echo "ALERT- Required memory cannot be evaluated because user $USER does not have execute permission for /usr/sbin/lsattr, please have your System Administrator add execute priviledge to lsattr or have them run '/usr/sbin/lsattr -HE -l sys0 -a realmem' to see how much memory you have" | /usr/bin/tee -a $REPORT
fi

# AIX CALCULATE MEMORY AND SWAP

/usr/bin/echo "\n\n\nChecking Swap to Memory Ratio" | /usr/bin/tee -a $REPORT
/usr/bin/echo "___________________\n" | /usr/bin/tee -a $REPORT

if /usr/bin/test $SWAP
then
  if [ $ORAVER = "805" -o $ORAVER = "806" -o $ORAVER = "815" -o $ORAVER = "816" ]
  then
    if [ $MEM -le 128 ]
    then 
      if [ $SWAP -lt $THREM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $THREM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb\n" | /usr/bin/tee -a $REPORT
      fi
    elif [ $MEM -gt 128 -a $MEM -lt 1024 ]
    then
      if [ $SWAP -lt $TWOM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $TWOM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb\n" | /usr/bin/tee -a $REPORT
      fi
    elif [ $MEM -ge 1024 ]
    then
      if [ $SWAP -lt $MEM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP MB to at least $MEM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb\n" | /usr/bin/tee -a $REPORT
      fi
    fi
  elif [ $ORAVER = "817" or $ORAVER = "901" ] 
  then
    if [ $MEM -le 1024 ]
    then
      if [ $SWAP -lt $TWOM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $TWOM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb.\n" | /usr/bin/tee -a $REPORT
      fi
    elif [ $MEM -gt 1024 ]
    then
      if [ $SWAP -lt $MEM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP MB to at least $MEM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb.\n" | /usr/bin/tee -a $REPORT
      fi
    fi
  elif [ $ORAVER = "920" ] 
  then
    if [ $SWAP -lt 1024 ]
    then
      /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least 1Gb.\n" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $SWAP -lt $MEM ]
    then
      /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $MEM Mb.\n" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb.\n" | /usr/bin/tee -a $REPORT
    fi
  fi 
else
  /usr/bin/echo "ALERT- A Swap to Memory ratio cannot be determined because swap has not been setup or user $USER does not have execute permission to determine swap" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi 

# AIX KERNEL PARAMETER VERIFICATION

/usr/bin/echo "\n \n \nUnix Kernel Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________\n" | /usr/bin/tee -a $REPORT
/usr/bin/echo "Checking Required Kernel Parameters."  | /usr/bin/tee -a $REPORT
/usr/bin/echo "\n\nNow verifying kernel settings....please wait" | /usr/bin/tee -a $REPORT

if /usr/bin/test -z "$LINK_CNTRL" 
then
  if [ $OSVER3CHAR = "430" ] || [ $OSVER3CHAR = "432" ] || [ $OSVER3CHAR = "433" ]
  then
    if [ $ORAVER = "805" ] || [ $ORAVER = "806" ] || [ $ORAVER = "815" ]
    then           
      /usr/bin/echo "ALERT-  LINK_CNTRL has not been defined and needs to be set with $OSVER6CHAR and running $ORAVER" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
  fi
else
  if [ $ORAVER = "816" -o $ORAVER = "817" -o $ORAVER = "901" -o $ORAVER = "920" ] 
  then
    /usr/bin/echo "ALERT-  LINK_CNTRL should not be set for Oracle version $ORAVER and running $OSVER6CHAR, please unset this environmental variable" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  fi
fi

# AIX ASSEMBLY TOOL VERIFICATION

/usr/bin/echo "\n \n \nAssembly Tool Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________\n" | /usr/bin/tee -a $REPORT

arvalue=`/usr/bin/which ar`
if [ "$arvalue" != "/bin/ar" ]
then
  /usr/bin/echo "WARNING-  ar not found in /bin directory but was found in '$arvalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /usr/bin/echo "ar - found correctly in /bin" | /usr/bin/tee -a $REPORT
fi

ldvalue=`/usr/bin/which ld`
if [ "$ldvalue" != "/bin/ld" ]
then
  /usr/bin/echo "WARNING-  ld not found in /bin directory but was found in '$ldvalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /usr/bin/echo "ld - found correctly in /bin" | /usr/bin/tee -a $REPORT
fi

nmvalue=`/usr/bin/which nm`
if [ "$nmvalue" != "/bin/nm" ]
then
  /usr/bin/echo "WARNING-  nm not found in /bin directory but was found in '$nmvalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /usr/bin/echo "nm - found correctly in /bin" | /usr/bin/tee -a $REPORT
fi

makevalue=`/usr/bin/which make`
if [ "$makevalue" != "/bin/make" ]
then
  /usr/bin/echo "WARNING-  make not found in /bin directory but was found in '$makevalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /usr/bin/echo "make - found correctly in /bin" | /usr/bin/tee -a $REPORT
fi

# AIX ULIMIT VERIFICATION

/usr/bin/echo "\n \n \nVerification of ulimits" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_______________________________\n" | /usr/bin/tee -a $REPORT

TIMERAW=`/usr/bin/ulimit -t`
TIME=`/usr/bin/ulimit -t | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$TIME"
then
  /usr/bin/echo "ALERT- ulimit(TIME) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $TIME -lt 1000000000 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(TIME) to unlimited from the present $TIMERAW" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(TIME) set to $TIMERAW is adequate" | /usr/bin/tee -a $REPORT
fi

FILERAW=`/usr/bin/ulimit -f`
FILE=`/usr/bin/ulimit -f | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$FILE"
then
  /usr/bin/echo "ALERT- ulimit(FILE) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $FILE -lt 1000000000 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(FILE) to unlimited from the present $FILERAW" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(FILE) set to $FILERAW is adequate" | /usr/bin/tee -a $REPORT
fi

DATARAW=`/usr/bin/ulimit -d`
DATA=`/usr/bin/ulimit -d | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$DATA"
then
  /usr/bin/echo "ALERT- ulimit(DATA) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $DATA -lt 1000000000 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(DATA) to unlimited from the present $DATARAW" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(DATA) set to $DATARAW is adequate" | /usr/bin/tee -a $REPORT
fi

STACKRAW=`/usr/bin/ulimit -s`
STACK=`/usr/bin/ulimit -s | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$STACK"
then
  /usr/bin/echo "ALERT- ulimit(STACK) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $STACK -lt 1000000000 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(STACK) to unlimited from the present $STACKRAW" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(STACK) set to $STACKRAW is adequate" | /usr/bin/tee -a $REPORT
fi

NOFILESRAW=`/usr/bin/ulimit -n`
NOFILES=`/usr/bin/ulimit -n | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$NOFILES"
then
  /usr/bin/echo "ALERT- ulimit(NOFILES) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $NOFILES -lt 1000000000 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(NOFILES) to unlimited from the present $NOFILESRAW" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(NOFILES) set to $NOFILESRAW is adequate" | /usr/bin/tee -a $REPORT
fi

MEMORYRAW=`/usr/bin/ulimit -m`
MEMORY=`/usr/bin/ulimit -m | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$MEMORY"
then
  /usr/bin/echo "ALERT- ulimit(MEMORY) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $MEMORY -lt 1000000000 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(MEMORY) to unlimited from the present $MEMORY" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(MEMORY) set to $MEMORYRAW is adequate" | /usr/bin/tee -a $REPORT
fi


# AIX CERTIFICATION VERIFICATION

/usr/bin/echo "\n \n \nCertification of Oracle and OS Version Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________________________________________\n" | /usr/bin/tee -a $REPORT
case $OSVER3CHAR in
  "414"|"415"|"420")
     if [ $ORABIT = 64 ]
     then
       /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER6CHAR $OSBIT bit is not certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
       SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
     elif [ $ORAVER = "805" ]
     then
       /usr/bin/echo "$OS $OSVER6CHAR $OSBIT bit is certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
     else
       /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER6CHAR $OSBIT bit is not certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
       SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
     fi        
     ;;
  "421")
     if [ $ORABIT = 64 ]
     then
       /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER6CHAR $OSBIT bit is not certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
       SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
     elif [ $ORAVER = "805" ] || [ $ORAVER = "806" ] || [ $ORAVER = "815" ]
     then
       /usr/bin/echo "$OS $OSVER6CHAR $OSBIT bit is certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
     else
       /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER6CHAR $OSBIT bit is not certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
       SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
     fi
     ;;
  "432")
     if [ $ORABIT = 64 ] 
     then
       if [ $ORAVER = "901" -o $ORAVER = "920" ]
       then
         /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER6CHAR $OSBIT bit is not certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
         SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
       elif [ $OSBIT = "64" ]
       then
         /usr/bin/echo "$OS $OSVER6CHAR $OSBIT bit is certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
       else
         /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER6CHAR $OSBIT bit is not certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
         SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
       fi  
     elif [ $ORAVER = "901" ]
     then
       /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER6CHAR $OSBIT bit is not certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
       SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
     else
       /usr/bin/echo "$OS $OSVER6CHAR $OSBIT bit is certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
     fi
     ;;
  "433")
     if [ $ORABIT = 64 ] 
     then
       if [ $OSBIT = 64 ]
       then
         /usr/bin/echo "$OS $OSVER6CHAR $OSBIT bit is certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
       else
         /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER6CHAR $OSBIT bit is not certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
         SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
       fi  
     elif [ $ORAVER != "901" -o $ORAVER != "920" ]
     then
       /usr/bin/echo "$OS $OSVER6CHAR $OSBIT bit is certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
     else
       /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER6CHAR $OSBIT bit is not certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
       SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
     fi
     ;;
  "510"|"520"|"530")
     if [ $ORAVER = "817" ]
     then
       if /usr/bin/test -x /usr/sbin/bootinfo
       then
         if [ `/usr/sbin/bootinfo -y` = 32 ]           
         then  
           /usr/bin/echo "$OS $OSVER6CHAR $OSBIT bit is certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
         elif [ `/usr/sbin/bootinfo -y` = 64 ]
         then  
           /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER6CHAR $OSBIT bit is not certified to run Oracle $ORAVER $ORABIT bit configuration because your system has been booted in 64bit mode not the required 32bit mode" | /usr/bin/tee -a $REPORT
           SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
         fi
       else
         /usr/bin/echo "!!SHOWSTOPPER!! The user $USER does not have execute permission for /usr/sbin/bootinfo to determine if your box is booted in 32 or 64 , please have your System Administrator add execute priviledge to /usr/sbin/bootinfo or have them run '/usr/sbin/bootinfo -y' to see what mode you are in" | /usr/bin/tee -a $REPORT
         SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
       fi  
     elif [ $ORAVER = "920" ]
     then
       if /usr/bin/test -x /usr/sbin/bootinfo
       then
         if [ `/usr/sbin/bootinfo -y` = 32 ]           
         then  
           /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER6CHAR $OSBIT bit is not certified to run Oracle $ORAVER $ORABIT bit configuration because your system has been booted in 64bit mode not the required 32bit mode" | /usr/bin/tee -a $REPORT
           SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
         elif [ `/usr/sbin/bootinfo -y` = 64 ]
         then  
           /usr/bin/echo "$OS $OSVER6CHAR $OSBIT bit is certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "!!SHOWSTOPPER!! The user $USER does not have execute permission for /usr/sbin/bootinfo to determine if your box is booted in 32 or 64 , please have your System Administrator add execute priviledge to /usr/sbin/bootinfo or have them run '/usr/sbin/bootinfo -y' to see what mode you are in" | /usr/bin/tee -a $REPORT
         SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
       fi  
     else
       /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER6CHAR $OSBIT bit is not certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT | /usr/bin/tee -a $REPORT
       SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
     fi
     ;;
  *)
    /usr/bin/echo "ALERT-  The OS Version was not determinable or is incorrect\n" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    ;;
esac

# AIX Verify OS patches are installed

/usr/bin/echo "\n \n \nOS Patches Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________\n" | /usr/bin/tee -a $REPORT

if /usr/bin/test -x /usr/sbin/instfix
then
case $ORAVER in
  "805")
     if [ $OSVER3CHAR = "414" ]
     then
       for PATCH in IX54124 IX58455 IX61237 IX55203 IX62330 IX67074 IX61933 IX70194
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
        done
     elif [ $OSVER6CHAR = "415000" ]
     then
       for PATCH in IX55203 IX62330 IX67074 IX61933 IX70194
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
        done
     elif [ $OSVER6CHAR = "415001" ]
     then
       for PATCH in IX70194
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
        done
     elif [ $OSVER3CHAR = "420" ]
     then
       for PATCH in IX62429 IX67174 IX67978 IX68932 IX70737
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
     elif [ $OSVER3CHAR = "421" ]
     then
       for PATCH in IX67978 IX68932 IX70737
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
     elif [ $OSVER3CHAR = "430" ]
     then
       for PATCH in IX71948
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
     else
       /usr/bin/echo "Since your OS level is `/usr/bin/oslevel -r`, all $ORAVER required OS patches are already included" | /usr/bin/tee -a $REPORT
     fi
     ;;
  "806"|"815")
     if [ $OSVER3CHAR = "420" ]
     then
       for PATCH in IX62429 IX67174 IX67978 IX68932 IX70737 IX78933 IX81957 IX86229 IX88178
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
     elif [ $OSVER6CHAR -ge "421000" -a $OSVER6CHAR -le "421002" ]
     then
       for PATCH in IX67978 IX68932 IX70737 IX78933 IX81957 IX86229 IX88178
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
     elif [ $OSVER6CHAR = "421003" ]
     then
       for PATCH in IX78933 IX81957 IX86229 IX88178
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
     elif [ $OSVER6CHAR = "421005" ]
     then
       for PATCH in IX86229 IX88178
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
     elif [ $OSVER6CHAR = "421006" ]
     then
       for PATCH in IX88178
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed"  tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
     elif [ $OSVER3CHAR = "430" ]
     then
       for PATCH in IX71948 IX79690 IX81863 IX87313 IX87382 IX89087 IY02407 
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
     elif [ $OSVER3CHAR = "431" ]
     then
       for PATCH in IX81863 IX87313 IX87382 IX89087 IY02407 
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
     elif [ $OSVER6CHAR = "432001" ]
     then
       for PATCH in IX87313 IX87382 IX89087 IY02407 
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
     elif [ $OSVER6CHAR = "432002" ]
     then
       for PATCH in IX89087 IY02407 
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
     else
       /usr/bin/echo "Since your OS level is `/usr/bin/oslevel -r`, all $ORAVER required OS patches are already included" | /usr/bin/tee -a $REPORT
     fi
     ;;
  "816"|"817")
     if [ $OSVER6CHAR = "432000" -o $OSVER6CHAR = "432001" ]
     then
       for PATCH in IX89552 IX87382 IX87313 IX85104 IY03412 IX89087 IY02407
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
        done
     elif [ $OSVER6CHAR = "432002" ]
     then
       for PATCH in IY03412 IX89087 IY02407
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
        done
     elif [ $OSVER6CHAR = "433000" ]
     then
       for PATCH in IY07018 IY05995 IY07276 IY01050
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
        done
     elif [ $OSVER6CHAR = "433001" ]
     then
       for PATCH in IY05995 IY07276 IY01050
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
     elif [ $OSVER6CHAR = "433002" ]
     then
       for PATCH in IY07276 IY01050
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
     elif [ $OSVER6CHAR = "433003" ]
     then
       for PATCH in IY01050
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
    else
       /usr/bin/echo "Since your OS level is `/usr/bin/oslevel -r`, all $ORAVER required OS patches are already included" | /usr/bin/tee -a $REPORT
     fi
    ;;    
  "901")
     if [ $OSVER6CHAR = "433002" ]
     then
       for PATCH in IY07276 IY01050
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
     elif [ $OSVER6CHAR = "433003" ]
     then
       for PATCH in IY01050
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
     else
       /usr/bin/echo "Since your OS level is `/usr/bin/oslevel -r`, all $ORAVER required OS patches are already included" | /usr/bin/tee -a $REPORT
     fi
    
     for ML in 7 8 9
       do
         if [ `/usr/sbin/instfix -ik 4330-0"$ML"_AIX_ML | /usr/bin/grep -ic not` = 0 ]
         then
           /usr/bin/echo "The OS has all filesets related to 4330-0"$ML"_AIX_ML maintenance level installed" | /usr/bin/tee -a $REPORT
         else 
           if [ $ML -eq 7 ]  
           then   
             /usr/bin/echo "ALERT-  The OS does not have all filesets related to 4330-0"$ML"_AIX_ML maintenance level installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           fi
         fi
      done
    ;;
  "920")
     if [ $OSVER3CHAR = "433" ]
     then
       if [ $OSVER6CHAR -lt "433010" ]
       then
         for PATCH in IY30927 IY24568 IY25282 IY27614 IY30151 
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
       elif [ $OSVER6CHAR -gt "433010" ]
       then 
         for PATCH in IY30151 
         do
           if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
       fi
       if [ `/usr/sbin/instfix -ik 4330-09_AIX_ML | /usr/bin/grep -ic not` = 0 ]
       then
         /usr/bin/echo "The OS has all filesets related to 4330-09_AIX_ML maintenance level installed" | /usr/bin/tee -a $REPORT
       else      
         /usr/bin/echo "ALERT-  The OS does not have all filesets related to 4330-09_AIX_ML maintenance level installed" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       fi
     elif [ $OSVER3CHAR = "510" ]
     then
       if [ $OSVER6CHAR -lt "510002" ]
       then
         for PATCH in IY26778 IY28766 IY28949 IY29965 IY30150 IY22854 IY59082
           do
             if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
             then
               /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
               ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
             else
               /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
             fi
           done
       elif [ $OSVER6CHAR -eq "510002" ]
       then 
         for PATCH in IY29965 IY30150 IY59082

           do
             if [ `/usr/sbin/instfix -ia -ivk $PATCH | /usr/bin/grep -c $PATCH` = 0 ]
             then
               /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
               ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
             else
               /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
             fi
           done
       fi  
       if [ `/usr/sbin/instfix -ik 5100-01_AIX_ML | /usr/bin/grep -ic not` = 0 ]
       then
         /usr/bin/echo "The OS has all filesets related to 5100-01_AIX_ML maintenance level installed" | /usr/bin/tee -a $REPORT
       else      
         /usr/bin/echo "ALERT-  The OS does not have all filesets related to 5100-01_AIX_ML maintenance level installed" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       fi 
     fi
     ;;
  *)
    /usr/bin/echo " "
    ;;
esac
else
  /usr/bin/echo "ALERT-  OS Patches cannot be verified, user $USER does not have execute permission on /usr/sbin/instfix, please have your System Administrator add execute permission to /usr/sbin/instfix" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/exprt $ALERTCOUNT + 1`
fi

# AIX Verify OS Packages

if /usr/bin/test -x /usr/bin/lslpp
then
  case $ORAVER in
  "805"|"806"|"815"|"816"|"817")
     for PACKAGE in "bos.adt.base" "bos.adt.libm"
     do
       if [ `/usr/bin/lslpp -l | /usr/bin/grep -c $PACKAGE` != 0 ]
       then
         STATE=`/usr/bin/lslpp -l | /usr/bin/grep $PACKAGE | /usr/bin/awk '{print $3}' | /usr/bin/uniq`
         if [ $STATE = "COMMITTED" -o $STATE = "APPLIED" ]
         then
           /usr/bin/echo "The $PACKAGE package is present and the state is $STATE" | /usr/bin/tee -a $REPORT 
         else
           /usr/bin/echo "WARNING: The $PACKAGE package is present but the state is $STATE" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "ALERT-  The $PACKAGE package needs to be installed" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       fi
     done
     ;;
  "901")
    for PACKAGE in "bos.adt.base" "bos.adt.lib" "bos.adt.libm" "bos.perf.perfstat" "X11.apps.rte" "X11.apps.xterm" "X11.base.rte" "X11.motif.lib" "X11.motif.mwm"
    do
      if [ `/usr/bin/lslpp -l | /usr/bin/grep -c $PACKAGE` != 0 ]
      then
        STATE=`/usr/bin/lslpp -l | /usr/bin/grep $PACKAGE | /usr/bin/awk '{print $3}' | /usr/bin/uniq`
        if [ $STATE = "COMMITTED" -o $STATE = "APPLIED" ]
        then
          /usr/bin/echo "The $PACKAGE package is present and the state is $STATE" | /usr/bin/tee -a $REPORT 
        else
          /usr/bin/echo "WARNING: The $PACKAGE package is present but the state is $STATE" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "ALERT-  The $PACKAGE package needs to be installed" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      fi
    done
    ;;
  "920")
    if [ $OSVER3CHAR = "433" ] 
    then
      for PACKAGE in "bos.adt.base" "bos.adt.lib" "bos.adt.libm" "bos.perf.perfstat"
      do
        if [ `/usr/bin/lslpp -l | /usr/bin/grep -c $PACKAGE` != 0 ]
        then
          STATE=`/usr/bin/lslpp -l | /usr/bin/grep $PACKAGE | /usr/bin/awk '{print $3}' | /usr/bin/uniq`
          if [ $STATE = "COMMITTED" -o $STATE = "APPLIED" ]
          then
            /usr/bin/echo "The $PACKAGE package is present and the state is $STATE" | /usr/bin/tee -a $REPORT 
          else
            /usr/bin/echo "WARNING: The $PACKAGE package is present but the state is $STATE" | /usr/bin/tee -a $REPORT
          fi
        else
          /usr/bin/echo "ALERT-  The $PACKAGE package needs to be installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        fi
      done
    elif [ $OSVER3CHAR = "510" -o $OSVER3CHAR = "520" -o $OSVER3CHAR = "530" ] 
    then
      for PACKAGE in "bos.adt.base" "bos.adt.lib" "bos.adt.libm" "bos.perf.perfstat" "bos.perf.libperfstat"
      do
        if [ `/usr/bin/lslpp -l | /usr/bin/grep -c $PACKAGE` != 0 ]
        then
          STATE=`/usr/bin/lslpp -l | /usr/bin/grep $PACKAGE | /usr/bin/awk '{print $3}' | /usr/bin/uniq`
          if [ $STATE = "COMMITTED" -o $STATE = "APPLIED" ]
          then
            /usr/bin/echo "The $PACKAGE package is present and the state is $STATE" | /usr/bin/tee -a $REPORT 
          else
            /usr/bin/echo "WARNING: The $PACKAGE package is present but the state is $STATE" | /usr/bin/tee -a $REPORT
          fi
        else
          /usr/bin/echo "ALERT-  The $PACKAGE package needs to be installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        fi
      done
    fi
    ;;
  *)
    /usr/bin/echo " "
    ;;
  esac
else
  /usr/bin/echo "ALERT:  User $USER does not have permission to verify OS packages, please have your System Administrator do '/usr/bin/lslpp -l' and upload the output via Metalink" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi

# VERIFY libc IF RUNNING 4.2.1

if [ "$OSVER3CHAR" = "421" ] && [ `/usr/bin/lslpp -l bos.rte.libc | /usr/bin/sed '1d' | /usr/bin/sed '1d' | /usr/bin/sed '1d' | /usr/bin/awk '{print substr($2,7,2)}'` -lt 10 ]
then
  /usr/bin/echo "ALERT-  The bos.rte.libc version needs to be 4.2.1.10 or higher" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi


# AIX VERIFY EXTENDED SHARED MEMORY

/usr/bin/echo "\n \n \nExtended Shared Memory Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________\n" | /usr/bin/tee -a $REPORT
if [ `/usr/bin/env | /usr/bin/grep -c EXTSHM` = 1 ]
then
  /usr/bin/echo "ALERT-  Extended Shared Memory has been set in your environment and must be unset prior to installing Oracle\n" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "Extended Shared Memory is correctly unset in the environment" | /usr/bin/tee -a $REPORT
fi
;;

"HP-UX")
USER=`/usr/bin/who -m | awk '{print $1}'`
OSVER=`/usr/bin/uname -r | awk '{print substr($1,3)}'`

if [ `/usr/bin/getconf KERNEL_BITS` = 64 ]
then 
  OSBIT=64
else
  OSBIT=32
fi

# HPUX START ECHO OF SCRIPT TO OUTPUT FILE

`/usr/bin/touch $REPORT; /usr/bin/chmod 777 $REPORT`
/usr/bin/echo "\nOutput from the Oracle InstallPrep Script run on $BOXNAME on `date`.\n \n \n" > $REPORT
/usr/bin/echo "To successfully install the Oracle Database Software you must resolve" >> $REPORT
/usr/bin/echo "each item listed in this Report. \n \n"  >> $REPORT
/usr/bin/echo "\n\n\nInstallPrep now running on your $OS $OSBIT bit box....." | /usr/bin/tee -a $REPORT


#  HPUX ORACLE VERSION INPUT

/usr/bin/echo "\n\n\nOracle Version Input" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_______________________\n" | /usr/bin/tee -a $REPORT
/usr/bin/echo "What version of Oracle are you installing?\n (valid values:805,806,815,816,817,901,920):" | /usr/bin/tee -a $REPORT
read ORAVER
/usr/bin/echo $ORAVER >> $REPORT
case $ORAVER in
  "805"|"806"|"815"|"816"|"817"|"901"|"920")
    ;;
  "")
    /usr/bin/echo "\nALERT-  You did not enter a value" | /usr/bin/tee -a $REPORT 
    exit
    ;;
  *)
    /usr/bin/echo "\nALERT-  You have entered an invalid version - enter valid value" | /usr/bin/tee -a $REPORT
    exit
    ;;
esac

# HPUX ORACLE BIT SIZE INPUT

/usr/bin/echo "\n\n\nOracle Bit Size Input" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT

/usr/bin/echo "What bit version of Oracle are you installing (32 or 64)?" | /usr/bin/tee -a $REPORT
read ORABIT
/usr/bin/echo $ORABIT >> $REPORT
case $ORABIT in
  "32"|"64")
     ;;
  "")
    /usr/bin/echo "\nALERT-  You did not enter a value" | /usr/bin/tee -a $REPORT
    exit
    ;;
  *)
    /usr/bin/echo "\nALERT-  You have entered an invalid version - enter valid value" | /usr/bin/tee -a $REPORT
    exit
    ;;
esac

# HPUX CORRECT USER VERIFICATION

/usr/bin/echo "\n\n\nUser Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
if [ $USER = "root" ]
then
  /usr/bin/echo "\nALERT-  You are logged in as user -- $USER --.  Please log in as the user that will be installing the Oracle Database Software. This user should not be root." | /usr/bin/tee -a $REPORT
  /usr/bin/echo "Exiting" | /usr/bin/tee -a $REPORT
  exit;
else
  /usr/bin/echo "\nYou are currently logged on as user -- $USER -- \n" | /usr/bin/tee -a $REPORT
fi

# HPUX CONFIRMATION OF USER

/usr/bin/echo "Is user $USER the unix user that will be installing Oracle Software?  (y or n)" | /usr/bin/tee -a $REPORT
read answer
/usr/bin/echo $answer >> $REPORT
case $answer in
  "n"|"N")
    /usr/bin/echo "\nALERT-  Please log in as the user that will be installing Oracle.  Then rerun this script \n" | /usr/bin/tee -a $REPORT
    exit
    ;;
  "y"|"Y")
    /usr/bin/echo "\n \n \n Verifying User in /etc/passwd" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "______________________________________\n" | /usr/bin/tee -a $REPORT
    if /usr/bin/test -r /etc/passwd
    then
      if [ "$USER" =  `/usr/bin/cat /etc/passwd | /usr/bin/awk -F: '{print $1}' | /usr/bin/grep -e $USER` ]
      then
        /usr/bin/echo "-- $USER -- correctly exists in /etc/passwd \n" | /usr/bin/tee -a $REPORT
      else
        /usr/bin/echo "ALERT-  The unix user -- $USER -- is not in /etc/passwd.  You must add user $USER to the /etc/passwd file. NIS managed users are not recommended" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      fi
    else
      /usr/bin/echo " ALERT-  User $USER is not allowed read access to the /etc/passwd file, verification of user $USER in /etc/passwd can not be performed.  Please get with your System Administrator to have them verify the presence of the user $USER in the /etc/passwd file" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
    ;;
  "")
    /usr/bin/echo "\nALERT-  You did not enter a value" | /usr/bin/tee -a $REPORT
    exit
    ;;
  *)
    /usr/bin/echo "\nALERT-  You have entered an invalid value - enter valid value" | /usr/bin/tee -a $REPORT
    exit
    ;;
esac

# HPUX SU VERIFICATION

/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo "Switching User (su) verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________________" | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo "Are you switching user (su) from another user to become the $USER user? (Y/N):" | /usr/bin/tee -a $REPORT
read SUORACLE
/usr/bin/echo $SUORACLE >> $REPORT
case $SUORACLE in
  "Y"|"y")
      /usr/bin/echo " " | /usr/bin/tee -a $REPORT
      /usr/bin/echo "WARNING: Switching User (su) is not suggested, you should login as $USER user directly when doing the install" | /usr/bin/tee -a $REPORT
      WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
      ;;
  "N"|"n")
      /usr/bin/echo " " | /usr/bin/tee -a $REPORT
      /usr/bin/echo "Passed switch user (su) test" | /usr/bin/tee -a $REPORT
      ;;
  *)
      /usr/bin/echo " " | /usr/bin/tee -a $REPORT
      /usr/bin/echo "You have entered an invalid answer, exiting InstallPrep, please try again" | /usr/bin/tee -a $REPORT
      exit
      ;;
esac

# HPUX CONFIRMATION OF GROUP

/usr/bin/echo "\n\n\nGroup Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
/usr/bin/echo "Enter the unix group that will be used during the installation (example: dba)?" | /usr/bin/tee -a $REPORT
read GROUP
/usr/bin/echo $GROUP >> $REPORT
case $GROUP in
  "") 
    /usr/bin/echo "\nALERT- You did not enter a value" | /usr/bin/tee -a $REPORT
    exit
   ;;
  *)
    if /usr/bin/test -r /etc/group
    then
      if [ "$GROUP" = "`/usr/bin/cat /etc/group | /usr/bin/awk -F: '{print $1}' | /usr/bin/grep -e $GROUP`" ]
      then
        /usr/bin/echo "-- $GROUP -- exists in /etc/group" | /usr/bin/tee -a $REPORT
      else
        /usr/bin/echo "ALERT-  You must create the unix group -- $GROUP -- as the root user and add -- $USER -- to this group or select a different unix group that already exists in /etc/group\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      fi
    else 
      /usr/bin/echo " ALERT-  User $USER is not allowed read access to the /etc/group file, verification of $GROUP in /etc/group can not be performed.  Please get with your System Administrator to have them verify the presence of the $GROUP in the /etc/group file" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
    ;;
esac

# HPUX CONFIRMATION OF ORACLE_HOME

/usr/bin/echo "\n\n\nSpecify ORACLE_HOME" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
if /usr/bin/test $ORACLE_HOME
then
  /usr/bin/echo "Presently, your ORACLE_HOME is set to $ORACLE_HOME, is this the correct location that this installation will be using? (Y/N)" | /usr/bin/tee -a $REPORT
  read CFRM
  if [ $CFRM = "Y" -o $CFRM = "y" ]
  then 
    OH=$ORACLE_HOME
    /usr/bin/echo $OH >> $REPORT
  else
    /usr/bin/echo "Enter Location where you will be installing Oracle (example: /u01/app/oracle/product/8.1.7)" | /usr/bin/tee -a $REPORT
    read OH
    /usr/bin/echo $OH >> $REPORT
  fi
else
  /usr/bin/echo "Enter Location where you will be installing Oracle (example: /u01/app/oracle/product/8.1.7)" | /usr/bin/tee -a $REPORT
  read OH
  /usr/bin/echo $OH >> $REPORT
fi
if /usr/bin/test -z "$OH"
then
  /usr/bin/echo "\nALERT-  You did not provide the location that Oracle will be installed.  Setting your ORACLE_HOME to No_Location_Given" | /usr/bin/tee -a $REPORT
  OH=No_Location_Given
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi

# HPUX VERIFICATION OF PERMISSIONS ON INPUT ORACLE_HOME

/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo "ORACLE_HOME permission verifications" | /usr/bin/tee -a $REPORT
/usr/bin/echo "____________________________________" | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT

ALERTCOUNTPRIOR=$ALERTCOUNT
if [ $OH != "No_Location_Given" ]
then
  if /usr/bin/test -x $OH
  then
    if /usr/bin/test -r $OH
    then
      /usr/bin/echo "User $USER has read permission to $OH" | /usr/bin/tee -a $REPORT
    else
      /usr/bin/echo "ALERT: User $USER does not have read permissions for $OH" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
    if /usr/bin/test -w $OH
    then
      /usr/bin/echo "User $USER has write permission to $OH" | /usr/bin/tee -a $REPORT
    else
      /usr/bin/echo "ALERT: User $USER does not have write permissions for $OH" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
    if /usr/bin/test -x $OH
    then
      /usr/bin/echo "User $USER has execute permission to $OH" | /usr/bin/tee -a $REPORT
    else
      /usr/bin/echo "ALERT: User $USER does not have execute permissions for $OH" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
  else
    /usr/bin/echo "ALERT: $OH does not exist, please create the $OH mount point and ensure the permissions are correctly set" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  fi
else
  /usr/bin/echo "ORACLE_HOME permissions cannot be verified since $OH" | /usr/bin/tee -a $REPORT
fi

if [ $ALERTCOUNTPRIOR = $ALERTCOUNT ]
then
  /usr/bin/echo "$OH has correct permissions for user $USER" | /usr/bin/tee -a $REPORT
else
  /usr/bin/echo "ALERT: The specified ORACLE_HOME=$OH does not have correct permissions.  Please have your System Administrator correct the permissions to "rwx" for the ORACLE_HOME mount point" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi

# HPUX LIST WHAT UMASK AND UNIX ENVIRONMENT VARIABLES NEED TO BE SET

/usr/bin/echo "\n\n\nUmask Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
MASK=`umask`
if [ $MASK -eq 022 ]
then
  /usr/bin/echo "umask of $MASK is set correctly \n" | /usr/bin/tee -a $REPORT
else
  /usr/bin/echo "ALERT-  umask is set to $MASK but must be set to 022 \n" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi

# HPUX LIST OUT THE PATH, LD_LIBRARY_PATH, and SHLIB_PATH

/usr/bin/echo "\n\n\nEnvironmental Variables (as set in user $USER's environment)" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
if /usr/bin/test $ORACLE_HOME
then
  /usr/bin/echo "ORACLE_HOME=$ORACLE_HOME" | /usr/bin/tee -a $REPORT
fi
if /usr/bin/test $PATH
then
  /usr/bin/echo "PATH=$PATH" | /usr/bin/tee -a $REPORT
fi
if /usr/bin/test $LD_LIBRARY_PATH
then
  /usr/bin/echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" | /usr/bin/tee -a $REPORT
fi
if /usr/bin/test $SHLIB_PATH
then
  /usr/bin/echo "SHLIB_PATH=$SHLIB_PATH" | /usr/bin/tee -a $REPORT
fi


/usr/bin/echo "\n\n\n.cshrc or .profile Recommended Variable Settings" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
SH=`/usr/bin/cat /etc/passwd | /usr/bin/awk -F: '{print $1, $NF}' | /usr/bin/grep -e $USER | /usr/bin/awk -F/ '{print $NF}'`
/usr/bin/echo "INFO- Your shell is $SH\n" | /usr/bin/tee -a $REPORT
if [ $ORAVER != "817" -o $ORAVER != "901" -o $ORAVER != "920" ]
then
  if [ $ORABIT = 32 ]
  then
    if [ "$SH" = csh ]
    then
      /usr/bin/echo "The following environment variables must be set in your .cshrc file for the $USER user." | /usr/bin/tee -a $REPORT
      /usr/bin/echo "setenv ORACLE_HOME $OH" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "setenv SHLIB_PATH $OH/lib:/usr/lib:/lib" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "setenv PATH $OH/bin:/usr/bin:/usr/ccs/bin:/etc:$PATH" | /usr/bin/tee -a $REPORT
    else
      /usr/bin/echo "The following environment variables must be set in your .profile file for the $USER user." | /usr/bin/tee -a $REPORT
      /usr/bin/echo "ORACLE_HOME=$OH" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "SHLIB_PATH=$OH/lib:/usr/lib:/lib" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "PATH=$OH/bin:$PATH" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "export \$ORACLE_HOME" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "export \$SHLIB_PATH" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "export \$PATH" | /usr/bin/tee -a $REPORT
    fi
  else
    if [ "$SH" = csh ]
    then
      /usr/bin/echo "The following environment variables must be set in your .cshrc file for the $USER user." | /usr/bin/tee -a $REPORT
      /usr/bin/echo "setenv ORACLE_HOME $OH" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "setenv SHLIB_PATH $OH/lib:/usr/lib:/lib" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "setenv LD_LIBRARY_PATH $OH/lib64:$OH/network/lib" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "setenv PATH $OH/bin:/usr/bin:/usr/ccs/bin:/etc:$PATH" | /usr/bin/tee -a $REPORT
    else
      /usr/bin/echo "The following environment variables must be set in your .profile file for the $USER user." | /usr/bin/tee -a $REPORT
      /usr/bin/echo "ORACLE_HOME=$OH" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "SHLIB_PATH=$OH/lib:/usr/lib:/lib" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "LD_LIBRARY_PATH=$OH/lib64:$OH/network/lib" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "PATH=$OH/bin:$PATH" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "export \$ORACLE_HOME" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "export \$SHLIB_PATH" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "export \$LD_LIBRARY_PATH" | /usr/bin/tee -a $REPORT
      /usr/bin/echo "export \$PATH" | /usr/bin/tee -a $REPORT
   fi
 fi
else
  if [ "$SH" = csh ]
  then
    /usr/bin/echo "The following environment variables must be set in your .cshrc file for the $USER user." | /usr/bin/tee -a $REPORT
    /usr/bin/echo "setenv ORACLE_HOME $OH" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "setenv SHLIB_PATH $OH/lib32:$OH/rdbms/lib32:/lib" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "setenv LD_LIBRARY_PATH $OH/lib:/usr/lib:/lib" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "setenv PATH $OH/bin:/usr/bin:/usr/ccs/bin:/etc:$PATH" | /usr/bin/tee -a $REPORT
  else
    /usr/bin/echo "The following environment variables must be set in your .profile file for the $USER user." | /usr/bin/tee -a $REPORT
    /usr/bin/echo "ORACLE_HOME=$OH" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "SHLIB_PATH=$OH/lib32:$OH/rdbms/lib32:/lib " | /usr/bin/tee -a $REPORT
    /usr/bin/echo "LD_LIBRARY_PATH=$OH/lib:/usr/lib:/lib " | /usr/bin/tee -a $REPORT
    /usr/bin/echo "PATH=$OH/bin:$PATH" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "export \$ORACLE_HOME" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "export \$SHLIB_PATH" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "export \$LD_LIBRARY_PATH" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "export \$PATH" | /usr/bin/tee -a $REPORT
  fi
fi


if [ "$OH" = "No_Location_Given" ]
then
  /usr/bin/echo "\nALERT- When running this script you did not provide a location where Oracle will be installed" | /usr/bin/tee -a $REPORT
  /usr/bin/echo "Change the value of No_Location_Given to the location where Oracle will be installed in." | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi


# HPUX /tmp SPACE VERIFICATION

/usr/bin/echo "\n \n \nTMP space Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_______________________\n" | /usr/bin/tee -a $REPORT
/usr/bin/echo "FYI: The runInstaller (OUI) uses/checks for temporary space by checking first for the TEMP environmental variable, then the TMP environmental variable and lastly the actual '/tmp' mount point" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_______________________\n" | /usr/bin/tee -a $REPORT
TMPMT=`/usr/bin/df -k | /usr/bin/grep '/tmp' | /usr/bin/awk '{print $5}'`
TMPMT=`/usr/bin/expr $TMPMT / 1024`
if [ `/usr/bin/env | /usr/bin/grep -ic "TEMP="` -ne 0 ]
then
  TEMPLOC=`/usr/bin/env | /usr/bin/grep "TEMP=" | /usr/bin/awk -F= '{print $2}'`
  if /usr/bin/test -d $TEMPLOC
  then
    TEMP=`/usr/bin/df -k "$TEMPLOC" | /usr/bin/grep free | /usr/bin/awk '{print $1}'`
    TEMP=`/usr/bin/expr $TEMP / 1024`
    /usr/bin/echo "The TEMP variable was found set to $TEMPLOC in your environment and has $TEMP Mb of free space" | /usr/bin/tee -a $REPORT
  else
    /usr/bin/echo "ALERT- The TEMP variable was found set in your environment but is either an invalid value or is not a directory.  Please set TEMP correctly or to a valid, writable directory or unset if the InstallPrep determines you have adequate space in /tmp" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  fi
elif [ `/usr/bin/env | /usr/bin/grep -ic "TMP="` -ne 0 ]
then
  TMPLOC=`/usr/bin/env | /usr/bin/grep "TMP=" | /usr/bin/awk -F= '{print $2}'`
  if /usr/bin/test -d $TMPLOC
  then
    TMP=`/usr/bin/df -k "$TMPLOC" | /usr/bin/grep free | /usr/bin/awk '{print $1}'`
    TMP=`/usr/bin/expr $TMP / 1024`
    /usr/bin/echo "The TMP variable was found set to $TMPLOC in your environment and has $TMP Mb of free space" | /usr/bin/tee -a $REPORT
  else
    /usr/bin/echo "ALERT- The TMP variable was found set in your environment but is either an invalid value or is not a directory.  Please set TMP correctly or to a valid, writable directory or unset if the InstallPrep determines you have adequate space in /tmp" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  fi
fi
case $ORAVER in
  "805"|"806")
     if /usr/bin/test "$TEMP"
     then 
       if [ $TEMP -lt 50 ]
       then
         /usr/bin/echo "ALERT- TEMP is set in the environment and has less than the required 50 Mb.  Please point the TEMP environmental variable to a mount point with at least 50 Mb of free space" | /usr/bin/tee -a $REPORT 
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TEMPLOC"
         then 
           /usr/bin/echo "TEMP has adequate space of $TEMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TEMP is set in the environment; however, $TEMPLOC does not have write permissions for this user" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test "$TMP" 
     then
       if [ $TMP -lt 50 ]
       then
         /usr/bin/echo "ALERT- TMP is set in the environment and has less than the required 50 Mb.  Please point the TMP environmental variable to a mount point with at least 50 Mb of free space" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TMPLOC"
         then
           /usr/bin/echo "TMP has adequate space of $TMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TMP is set in the environment; however, $TMPLOC does not have write permissions for this user" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test "$TMPMT"
     then
       if [ $TMPMT -lt 50 ]
       then
         /usr/bin/echo "ALERT- /tmp space = $TMPMT Mb, please increase /tmp to at least 50 Mb\n" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         /usr/bin/echo "/tmp has adequate space of $TMPMT Mb\n" | /usr/bin/tee -a $REPORT
       fi
     else
       /usr/bin/echo "ALERT-  /tmp is not specified\n" | /usr/bin/tee -a $REPORT
       ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
     fi
     ;;
   "815"|"816"|"817")
     if /usr/bin/test "$TEMP" 
     then 
       if [ $TEMP -lt 75 ]
       then
         /usr/bin/echo "ALERT- TEMP is set in the environment and has less than the required 75 Mb.  Please point the TEMP environmental variable to a mount point with at least 75 Mb of free space" | /usr/bin/tee -a $REPORT 
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TEMPLOC"
         then
           /usr/bin/echo "TEMP has adequate space of $TEMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TEMP is set in the environment; however, $TEMPLOC does not have write permissions for this user" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test "$TMP"
     then
       if [ $TMP -lt 75 ]
       then
         /usr/bin/echo "ALERT- TMP is set in the environment and has less than the required 75 Mb.  Please point the TMP environmental variable to a mount point with at least 75 Mb of free space" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TMPLOC"
         then
           /usr/bin/echo "TMP has adequate space of $TMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TMP is set in the environment; however, $TMPLOC does not have write permissions for this user" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test "$TMPMT"
     then
       if [ $TMPMT -lt 75 ]
       then
         /usr/bin/echo "ALERT- /tmp space = $TMPMT Mb, please increase /tmp to at least 75 Mb\n" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         /usr/bin/echo "/tmp has adequate space of $TMPMT Mb\n" | /usr/bin/tee -a $REPORT
       fi
     else
       /usr/bin/echo "ALERT-  /tmp is not specified\n" | /usr/bin/tee -a $REPORT
       ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
     fi
     ;;
   "901"|"920")
     if /usr/bin/test "$TEMP" 
     then 
       if [ $TEMP -lt 400 ]
       then
         /usr/bin/echo "ALERT- TEMP is set in the environment and has less than the required 400 Mb.  Please point the TEMP environmental variable to a mount point with at least 400 Mb of free space" | /usr/bin/tee -a $REPORT 
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TEMPLOC"
         then 
           /usr/bin/echo "TEMP has adequate space of $TEMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TEMP is set in the environment; however, $TEMPLOC does not have write permissions for this user" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test "$TMP"
     then
       if [ $TMP -lt 400 ]
       then
         /usr/bin/echo "ALERT- TMP is set in the environment and has less than the required 400 Mb.  Please point the TMP environmental variable to a mount point with at least 400 Mb of free space" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TMPLOC"
         then
           /usr/bin/echo "TMP has adequate space of $TMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TMP is set in the environment; however, $TMPLOC does not have write permissions for this user" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test "$TMPMT"
     then
       if [ $TMPMT -lt 400 ]
       then
         /usr/bin/echo "ALERT- /tmp space = $TMPMT Mb, please increase /tmp to at least 400 Mb\n" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         /usr/bin/echo "/tmp has adequate space of $TMPMT Mb\n" | /usr/bin/tee -a $REPORT
       fi
     else
       /usr/bin/echo "ALERT-  /tmp is not specified\n" | /usr/bin/tee -a $REPORT
       ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
     fi
     ;;
    *)
     /usr/bin/echo ""
     ;;
esac


# HPUX SWAP SPACE VERIFICATION

/usr/bin/echo "\n\n\nSwap Space Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
if /usr/bin/test -x /usr/sbin/swapinfo
then
  SWAP=`/usr/sbin/swapinfo -q`
  SWAP=`/usr/bin/expr $SWAP / 1024`
  if /usr/bin/test -z "$SWAP"
  then 
    /usr/bin/echo "ALERT- SWAP has not been setup or specified" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "Swap is $SWAP Mb\n" | /usr/bin/tee -a $REPORT
  fi
else
  /usr/bin/echo "ALERT- User $USER does not have execute permission to determine amount of swap, please have your System Administator allow execute to user $USER, or have them run '/usr/sbin/swapinfo -q' " | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi

# HPUX MEMORY SPACE VERIFICATION


/usr/bin/echo "\n\n\nMemory Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "___________________\n" | /usr/bin/tee -a $REPORT
MEM1=`/usr/bin/grep Physical /var/adm/syslog/syslog.log | /usr/bin/awk '{print $7}' | /usr/bin/sed 'q'`
if /usr/bin/test $MEM1
then
  MEM=$MEM1
else 
  MEM2=`/usr/bin/grep Physical /var/adm/syslog/OLDsyslog.log | /usr/bin/awk '{print $7}' | /usr/bin/sed 'q'`
  if /usr/bin/test $MEM2
  then 
    MEM=$MEM2
  else 
    MEM3=`/usr/sbin/dmesg | /usr/bin/grep "Physical:" | /usr/bin/awk '{print $2}'`
    if /usr/bin/test $MEM3
    then
      MEM=$MEM3
    else
      MEM4=`/usr/bin/echo 'selall;info;wait;infolog;view;done' | /usr/sbin/cstm | /usr/bin/grep 'Total Configured Memory' | /usr/bin/awk -F: '{print $2}' | /usr/bin/awk '{print $1}'`
      if /usr/bin/test $MEM4
      then
        MEM=`/usr/bin/expr $MEM4 \* 1024`
      fi
    fi
  fi
fi

if /usr/bin/test $MEM
then
  MEM=`/usr/bin/expr $MEM / 1024`
else
  MEM=1
fi
TWOM=`/usr/bin/expr $MEM \* 2`
THREM=`/usr/bin/expr $MEM \* 3`
if [ $ORAVER != "817" -o $ORAVER != "901" -o $ORAVER != "920" ]
then
  if [ $MEM -lt 128 ]
  then
    /usr/bin/echo "ALERT-  You have $MEM Mb of memory. This is not enough to install Oracle.  You must have at least 128 Mb\n" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "You have sufficient $MEM Mb of memory.  This is enough to install Oracle\n" | /usr/bin/tee -a $REPORT
  fi
elif [ $ORAVER = "817" -o $ORAVER = "901" ]
then
  if [ $MEM -lt 255 ]
  then
    /usr/bin/echo "ALERT-  You have $MEM Mb of memory. This is not enough to install Oracle.  You must have at least 256 Mb\n" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "You have sufficient $MEM Mb of memory.  This is enough to install Oracle\n" | /usr/bin/tee -a $REPORT
  fi
elif [ $ORAVER = "920" ]
then
  if [ $MEM -lt 512 ]
  then
    /usr/bin/echo "ALERT-  You have $MEM Mb of memory. This is not enough to install Oracle.  You must have at least 512 Mb\n" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "You have sufficient $MEM Mb of memory.  This is enough to install Oracle\n" | /usr/bin/tee -a $REPORT
  fi
fi

# HPUX SWAP TO MEMORY RATIO VERIFICATION

/usr/bin/echo "\n\n\nChecking Swap to Memory Ratio" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT

if /usr/bin/test $SWAP
then
  if [ $ORAVER = "805" -o $ORAVER = "806" -o $ORAVER = "815" -o $ORAVER = "816" ]
  then
    if [ $MEM -le 512 ]
    then 
      if [ $SWAP -lt $THREM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP MB to at least $THREM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb\n" | /usr/bin/tee -a $REPORT
      fi
    elif [ $MEM -gt 512 -a $MEM -lt 1024 ]
    then
      if [ $SWAP -lt $TWOM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $TWOM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb\n" | /usr/bin/tee -a $REPORT
      fi
    elif [ $MEM -ge 1024 ]
    then
      if [ $SWAP -lt $MEM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $MEM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb\n" | /usr/bin/tee -a $REPORT
      fi
    fi
  elif [ $ORAVER = "817" or $ORAVER = "901" ] 
  then
    if [ $MEM -le 1024 ]
    then
      if [ $SWAP -lt $TWOM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $TWOM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb.\n" | /usr/bin/tee -a $REPORT
      fi
    elif [ $MEM -gt 1024 ]
    then
      if [ $SWAP -lt $MEM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP MB to at least $MEM Mb since you have $MEM MB of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb.\n" | /usr/bin/tee -a $REPORT
      fi
    fi
  elif [ $ORAVER = "920" ] 
  then
    if [ $SWAP -lt 1024 ]
    then
      /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least 1Gb.\n" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $SWAP -lt $MEM ]
    then
      /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $MEM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb.\n" | /usr/bin/tee -a $REPORT
    fi
  fi 
else
  /usr/bin/echo "ALERT- A Swap to Memory ratio cannot be determined because swap has not been setup or user $USER does not have execute permission to determine swap" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi 

# HPUX KERNEL PARAMETER VERIFICATION

/usr/bin/echo "\n \n \nUnix Kernel Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________\n" | /usr/bin/tee -a $REPORT
/usr/bin/echo "Checking Required Kernel Parameters...\n"  | /usr/bin/tee -a $REPORT

# HPUX SET KERNEL PARAMETERS

if /usr/bin/test -x /usr/sbin/kmtune
then
  /usr/bin/echo "INFO-  Using /usr/sbin/kmtune for determining kernel settings" | /usr/bin/tee -a $REPORT
  /usr/bin/echo " " | /usr/bin/tee -a $REPORT
  MAXUSERS=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep maxusers | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  NPROC=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep nproc | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MSGTQL=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep msgtql | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  VX_NCSIZE=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep vx_ncsize | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  SHMMAX=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep shmmax | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  SHMMIN=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep shmmin | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  SHMMNI=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep shmmni | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  SHMSEG=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep shmseg | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  SEMMAP=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep semmap | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  SEMMNI=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep semmni | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  SEMMNS=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep semmns | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  SEMMNU=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep semmnu | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  SEMVMX=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep semvmx | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  KSI_ALLOC_MAX=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep ksi_alloc_max | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MAX_THREAD_PROC=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep max_thread_proc | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MAXSWAPCHUNKS=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep maxswapchunks | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MAXUPRC=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep maxuprc | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MSGMAP=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep msgmap | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MSGMNI=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep msgmni | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MSGSEG=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep msgseg | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  NCALLOUT=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep ncallout | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  NCSIZE=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep ncsize | /usr/bin/grep -v vx | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  NFILE=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep nfile | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  NFLOCKS=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep nflocks | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  NINODE=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep ninode | /usr/bin/grep -v vx | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  NKTHREAD=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep nkthread | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  VPS_CEILING=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep vps_ceiling | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MAXDSIZ=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep "maxdsiz " | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MAXDSIZ_64BIT=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep "maxdsiz_64bit" | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MAXSSIZ=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep "maxssiz " | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MAXSSIZ_64BIT=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep "maxssiz_64bit" | /usr/bin/grep -v "pa" | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MAXTSIZ=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep "maxtsiz " | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MAXTSIZ_64BIT=`/usr/sbin/kmtune 2>/dev/null | /usr/bin/grep "maxtsiz_64bit" | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
elif /usr/bin/test /stand/system 
then
  /usr/bin/echo "INFO-  Using /stand/system for kernel settings because /usr/sbin/kmtune was not found" | /usr/bin/tee -a $REPORT
  /usr/bin/echo " " | /usr/bin/tee -a $REPORT
  MAXUSERS=`/usr/bin/cat /stand/system | /usr/bin/grep maxusers | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  NPROC=`/usr/bin/cat /stand/system | /usr/bin/grep nproc | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MSGTQL=`/usr/bin/cat /stand/system | /usr/bin/grep msgtql | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  VX_NCSIZE=`/usr/bin/cat /stand/system | /usr/bin/grep vx_ncsize | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  SHMMAX=`/usr/bin/cat /stand/system | /usr/bin/grep shmmax | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  SHMMIN=`/usr/bin/cat /stand/system | /usr/bin/grep shmmin | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  SHMMNI=`/usr/bin/cat /stand/system | /usr/bin/grep shmmni | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  SHMSEG=`/usr/bin/cat /stand/system | /usr/bin/grep shmseg | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  SEMMAP=`/usr/bin/cat /stand/system | /usr/bin/grep semmap | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  SEMMNI=`/usr/bin/cat /stand/system | /usr/bin/grep semmni | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  SEMMNS=`/usr/bin/cat /stand/system | /usr/bin/grep semmns | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  SEMMNU=`/usr/bin/cat /stand/system | /usr/bin/grep semmnu | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  SEMVMX=`/usr/bin/cat /stand/system | /usr/bin/grep semvmx | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  KSI_ALLOC_MAX=`/usr/bin/cat /stand/system | /usr/bin/grep ksi_alloc_max | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MAX_THREAD_PROC=`/usr/bin/cat /stand/system | /usr/bin/grep max_thread_proc | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MAXSWAPCHUNKS=`/usr/bin/cat /stand/system | /usr/bin/grep maxswapchunks | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MAXUPRC=`/usr/bin/cat /stand/system | /usr/bin/grep maxuprc | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MSGMAP=`/usr/bin/cat /stand/system | /usr/bin/grep msgmap | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MSGMNI=`/usr/bin/cat /stand/system | /usr/bin/grep msgmni | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MSGSEG=`/usr/bin/cat /stand/system | /usr/bin/grep msgseg | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  NCALLOUT=`/usr/bin/cat /stand/system | /usr/bin/grep ncallout | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  NCSIZE=`/usr/bin/cat /stand/system | /usr/bin/grep ncsize | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  NFILE=`/usr/bin/cat /stand/system | /usr/bin/grep nfile | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  NFLOCKS=`/usr/bin/cat /stand/system | /usr/bin/grep nflocks | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  NINODE=`/usr/bin/cat /stand/system | /usr/bin/grep ninode | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  NKTHREAD=`/usr/bin/cat /stand/system | /usr/bin/grep nkthread | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  VPS_CEILING=`/usr/bin/cat /stand/system | /usr/bin/grep vps_ceiling | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MAXDSIZ=`/usr/bin/cat /stand/system | /usr/bin/grep "maxdsiz " | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MAXDSIZ_64BIT=`/usr/bin/cat /stand/system | /usr/bin/grep "maxdsiz_64bit" | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MAXSSIZ=`/usr/bin/cat /stand/system | /usr/bin/grep "maxssiz " | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MAXSSIZ_64BIT=`/usr/bin/cat /stand/system | /usr/bin/grep "maxssiz_64bit" | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MAXTSIZ=`/usr/bin/cat /stand/system | /usr/bin/grep "maxtsiz " | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
  MAXTSIZ_64BIT=`/usr/bin/cat /stand/system | /usr/bin/grep "maxtsiz_64bit" | /usr/bin/awk '{print $2}' | /usr/bin/tr '[:lower:]' '[:upper:]'`
fi


if [ $ORAVER != "901" -a $ORAVER != "920" ]
then
  if [ `/usr/bin/echo $SHMMAX | /usr/bin/grep -ic 0x` != 0 ]   
  then
    SHMMAX=`/usr/bin/echo 16i $SHMMAX p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$SHMMAX"
  then
    /usr/bin/echo "ALERT-  SHMMAX has not been defined and needs to be set to 1073741824" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $SHMMAX -lt 1073741824 ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter SHMMAX to 1073741824 from present setting of $SHMMAX, Note: on HP there is an issue with manipulating large values so this may not be correct, and your setting is correct" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SHMMAX set to $SHMMAX is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $SHMMNI | /usr/bin/grep -ic 0x` != 0 ]   
  then
    SHMMNI=`/usr/bin/echo 16i $SHMMNI p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$SHMMNI"
  then
    /usr/bin/echo "ALERT- SHMMNI has not been defined and needs to be set to 100" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $SHMMNI -lt 100 ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter SHMMNI to at least 100 from present setting of $SHMMNI" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SHMMNI set to $SHMMNI is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $SHMSEG | /usr/bin/grep -ic 0x` != 0 ]   
  then
    SHMSEG=`/usr/bin/echo 16i $SHMSEG p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$SHMSEG"
  then
    /usr/bin/echo "ALERT- SHMSEG has not been defined  and needs to be set to 10" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $SHMSEG -lt 10 ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter SHMSEG to at least 10 from present setting of $SHMSEG" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SHMSEG set to $SHMSEG is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $SEMMNI | /usr/bin/grep -ic 0x` != 0 ]   
  then
    SEMMNI=`/usr/bin/echo 16i $SEMMNI p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$SEMMNI"
  then
    /usr/bin/echo "ALERT- SEMMNI has not been defined  and needs to be set to 70" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $SEMMNI -lt 70 ]
  then
    /usr/bin/echo "ALERT- Increase the kernel parameter SEMMNI to at least 70 from present setting of $SEMMNI" | /usr/bin/tee -a $REPORT     
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SEMMNI set to $SEMMNI is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $SEMMNS | /usr/bin/grep -ic 0x` != 0 ]   
  then
    SEMMNS=`/usr/bin/echo 16i $SEMMNS p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$SEMMNS"
  then
    /usr/bin/echo "ALERT- SEMMNS has not been defined  and needs to be set to 200 or more" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $SEMMNS -lt 200 ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter SEMMNS to at least 200 from present setting of $SEMMNS" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SEMMNS set to $SEMMNS is adequate" | /usr/bin/tee -a $REPORT
  fi
elif [ $ORAVER = "901" ]
then
  if [ `/usr/bin/echo $SHMMAX | /usr/bin/grep -ic 0x` != 0 ]   
  then
    SHMMAX=`/usr/bin/echo 16i $SHMMAX p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$SHMMAX"
  then
    /usr/bin/echo "ALERT-  SHMMAX has not been defined and needs to be set to $MEM Mb" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $SHMMAX -lt $MEM ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter SHMMAX to $MEM Mb from present setting of $SHMMAX, Note: on HP there is an issue with manipulating large values so this may not be correct, and your setting is correct" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SHMMAX set to $SHMMAX is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $SHMMNI | /usr/bin/grep -ic 0x` != 0 ]   
  then
    SHMMNI=`/usr/bin/echo 16i $SHMMNI p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$SHMMNI"
  then
    /usr/bin/echo "ALERT- SHMMNI has not been defined and needs to be set to 512" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $SHMMNI -lt 512 ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter SHMMNI to at least 512 from present setting of $SHMMNI" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SHMMNI set to $SHMMNI is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $SHMSEG | /usr/bin/grep -ic 0x` != 0 ]   
  then
    SHMSEG=`/usr/bin/echo 16i $SHMSEG p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$SHMSEG"
  then
    /usr/bin/echo "ALERT- SHMSEG has not been defined and needs to be set to 32" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $SHMSEG -lt 32 ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter SHMSEG to at least 32 from present setting of $SHMSEG" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SHMSEG set to $SHMSEG is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $SEMMNI | /usr/bin/grep -ic 0x` != 0 ]   
  then
    SEMMNI=`/usr/bin/echo 16i $SEMMNI p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$SEMMNI"
  then
    /usr/bin/echo "ALERT- SEMMNI has not been defined and needs to be set to 8192" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $SEMMNI -lt 8192 ]
  then
    /usr/bin/echo "ALERT- Increase the kernel parameter SEMMNI to at least 8192 from present setting of $SEMMNI" | /usr/bin/tee -a $REPORT     
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SEMMNI set to $SEMMNI is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $SEMMNS | /usr/bin/grep -ic 0x` != 0 ]   
  then
    SEMMNS=`/usr/bin/echo 16i $SEMMNS p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$SEMMNS"
  then
    /usr/bin/echo "ALERT- SEMMNS has not been defined and needs to be set to 16384" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $SEMMNS -lt 16384 ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter SEMMNS to at least 16384 from present setting of $SEMMNS" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SEMMNS set to $SEMMNS is adequate" | /usr/bin/tee -a $REPORT
  fi
elif [ $ORAVER = "920" ]
then
  if [ `/usr/bin/echo $KSI_ALLOC_MAX | /usr/bin/grep -ic 0x` != 0 ]   
  then
    KSI_ALLOC_MAX=`/usr/bin/echo 16i $KSI_ALLOC_MAX p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$KSI_ALLOC_MAX"
  then
    /usr/bin/echo "ALERT-  KSI_ALLOC_MAX has not been defined and needs to be set to 32768" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $KSI_ALLOC_MAX -lt 32768 ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter KSI_ALLOC_MAX to 32768 from present setting of $KSI_ALLOC_MAX" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "KSI_ALLOC_MAX set to $KSI_ALLOC_MAX is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $MAX_THREAD_PROC | /usr/bin/grep -ic 0x` != 0 ]   
  then
    MAX_THREAD_PROC=`/usr/bin/echo 16i $MAX_THREAD_PROC p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MAX_THREAD_PROC"
  then
    /usr/bin/echo "ALERT- MAX_THREAD_PROC has not been defined and needs to be set to 256" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MAX_THREAD_PROC -lt 256 ]
  then
    /usr/bin/echo "ALERT- Increase the kernel parameter MAX_THREAD_PROC to 256 from present setting of $MAX_THREAD_PROC" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MAX_THREAD_PROC set to $MAX_THREAD_PROC is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $MAXSWAPCHUNKS | /usr/bin/grep -ic 0x` != 0 ]   
  then
    MAXSWAPCHUNKS=`/usr/bin/echo 16i $MAXSWAPCHUNKS p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MAXSWAPCHUNKS"
  then
    /usr/bin/echo "ALERT- MAXSWAPCHUNKS has not been defined and needs to be set to 16384" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MAXSWAPCHUNKS -lt 16384 ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter MAXSWAPCHUNKS to at least 16384 from present setting of $MAXSWAPCHUNKS" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MAXSWAPCHUNKS set to $MAXSWAPCHUNKS is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $MAXUPRC | /usr/bin/grep -ic 0x` != 0 ]   
  then
    MAXUPRC=`/usr/bin/echo 16i $MAXUPRC p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MAXUPRC"
  then
    /usr/bin/echo "ALERT- MAXUPRC has not been defined and needs to be set to 3687" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MAXUPRC -lt 3687 ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter MAXUPRC to at least 3687 from present setting of $MAXUPRC" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MAXUPRC set to $MAXUPRC is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $MSGMAP | /usr/bin/grep -ic 0x` != 0 ]   
  then
    MSGMAP=`/usr/bin/echo 16i $MSGMAP p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MSGMAP"
  then
    /usr/bin/echo "ALERT- MSGMAP has not been defined and needs to be set to 4098" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MSGMAP -lt 4098 ]
  then
    /usr/bin/echo "ALERT- Increase the kernel parameter MSGMAP to at least 4098 from present setting of $MSGMAP" | /usr/bin/tee -a $REPORT     
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MSGMAP set to $MSGMAP is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $MSGMNI | /usr/bin/grep -ic 0x` != 0 ]   
  then
    MSGMNI=`/usr/bin/echo 16i $MSGMNI p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MSGMNI"
  then
    /usr/bin/echo "ALERT- MSGMNI has not been defined and needs to be set to 4096" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MSGMNI -lt 4096 ]
  then
    /usr/bin/echo "ALERT- Increase the kernel parameter MSGMNI to at least 4096 from present setting of $MSGMNI" | /usr/bin/tee -a $REPORT     
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MSGMNI set to $MSGMNI is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $MSGSEG | /usr/bin/grep -ic 0x` != 0 ]   
  then
    MSGSEG=`/usr/bin/echo 16i $MSGMNI p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MSGSEG"
  then
    /usr/bin/echo "ALERT- MSGSEG has not been defined and needs to be set to 32767" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MSGSEG -lt 32767 ]
  then
    /usr/bin/echo "ALERT- Increase the kernel parameter MSGSEG to at least 32767 from present setting of $MSGSEG" | /usr/bin/tee -a $REPORT     
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MSGSEG set to $MSGSEG is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $MSGTQL | /usr/bin/grep -ic 0x` != 0 ]   
  then
    MSGTQL=`/usr/bin/echo 16i $MSGTQL p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MSGTQL"
  then
    /usr/bin/echo "ALERT- MSGTQL has not been defined and needs to be set to 4096" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MSGTQL -lt 4096 ]
  then
    /usr/bin/echo "ALERT- Increase the kernel parameter MSGTQL to at least 4096 from present setting of $MSGTQL" | /usr/bin/tee -a $REPORT     
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MSGTQL set to $MSGTQL is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $NCALLOUT | /usr/bin/grep -ic 0x` != 0 ]   
  then
    NCALLOUT=`/usr/bin/echo 16i $NCALLOUT p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$NCALLOUT"
  then
    /usr/bin/echo "ALERT- NCALLOUT has not been defined and needs to be set to 5012" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $NCALLOUT -lt 5012 ]
  then
    /usr/bin/echo "ALERT- Increase the kernel parameter NCALLOUT to at least 5012 from present setting of $NCALLOUT" | /usr/bin/tee -a $REPORT     
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "NCALLOUT set to $NCALLOUT is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $NCSIZE | /usr/bin/grep -ic 0x` != 0 ]   
  then
    NCSIZE=`/usr/bin/echo 16i $NCSIZE p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$NCSIZE"
  then
    /usr/bin/echo "ALERT- NCSIZE has not been defined and needs to be set to 35840" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $NCSIZE -lt 35840 ]
  then
    /usr/bin/echo "ALERT- Increase the kernel parameter NCSIZE to at least 35840 from present setting of $NCSIZE" | /usr/bin/tee -a $REPORT     
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "NCSIZE set to $NCSIZE is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $NFILE | /usr/bin/grep -ic 0x` != 0 ]   
  then
    NFILE=`/usr/bin/echo 16i $NFILE p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$NFILE"
  then
    /usr/bin/echo "ALERT- NFILE has not been defined and needs to be set to 63488" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $NFILE -lt 63488 ]
  then
    /usr/bin/echo "ALERT- Increase the kernel parameter NFILE to at least 63488 from present setting of $NFILE" | /usr/bin/tee -a $REPORT     
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "NFILE set to $NFILE is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $NFLOCKS | /usr/bin/grep -ic 0x` != 0 ]   
  then
    NFLOCKS=`/usr/bin/echo 16i $NFLOCKS p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$NFLOCKS"
  then
    /usr/bin/echo "ALERT- NFLOCKS has not been defined and needs to be set to 4096" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $NFLOCKS -lt 4096 ]
  then
    /usr/bin/echo "ALERT- Increase the kernel parameter NFLOCKS to at least 4096 from present setting of $NFLOCKS" | /usr/bin/tee -a $REPORT     
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "NFLOCKS set to $NFLOCKS is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $NINODE | /usr/bin/grep -ic 0x` != 0 ]   
  then
    NINODE=`/usr/bin/echo 16i $NINODE p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$NINODE"
  then
    /usr/bin/echo "ALERT- NINODE has not been defined and needs to be set to 34816" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $NINODE -lt 34816 ]
  then
    /usr/bin/echo "ALERT- Increase the kernel parameter NINODE to at least 34816 from present setting of $NINODE" | /usr/bin/tee -a $REPORT     
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "NINODE set to $NINODE is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $NKTHREAD | /usr/bin/grep -ic 0x` != 0 ]   
  then
    NKTHREAD=`/usr/bin/echo 16i $NKTHREAD p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$NKTHREAD"
  then
    /usr/bin/echo "ALERT- NKTHREAD has not been defined and needs to be set to 7184" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $NKTHREAD -lt 7184 ]
  then
    /usr/bin/echo "ALERT- Increase the kernel parameter NKTHREAD to at least 7184 from present setting of $NKTHREAD" | /usr/bin/tee -a $REPORT     
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "NKTHREAD set to $NKTHREAD is adequate" | /usr/bin/tee -a $REPORT
  fi

if [ `/usr/bin/echo $NPROC | /usr/bin/grep -ic 0x` != 0 ]   
  then
    NPROC=`/usr/bin/echo 16i $NPROC p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$NPROC"
  then
    /usr/bin/echo "ALERT- NPROC has not been defined and needs to be set to 4096" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $NPROC -lt 4096 ]
  then
    /usr/bin/echo "ALERT- Increase the kernel parameter NPROC to at least 4096 from present setting of $NPROC" | /usr/bin/tee -a $REPORT     
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "NPROC set to $NPROC is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $SEMMAP | /usr/bin/grep -ic 0x` != 0 ]   
  then
    SEMMAP=`/usr/bin/echo 16i $SEMMAP p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$SEMMAP"
  then
    /usr/bin/echo "ALERT- SEMMAP has not been defined and needs to be set to 4098" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $SEMMAP -lt 4098 ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter SEMMAP to at least 4098 from present setting of $SEMMAP" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SEMMAP set to $SEMMAP is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $SEMMNI | /usr/bin/grep -ic 0x` != 0 ]   
  then
    SEMMNI=`/usr/bin/echo 16i $SEMMNI p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$SEMMNI"
  then
    /usr/bin/echo "ALERT- SEMMNI has not been defined and needs to be set to 4096" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $SEMMNI -lt 4096 ]
  then
    /usr/bin/echo "ALERT- Increase the kernel parameter SEMMNI to at least 4096 from present setting of $SEMMNI" | /usr/bin/tee -a $REPORT     
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SEMMNI set to $SEMMNI is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $SEMMNS | /usr/bin/grep -ic 0x` != 0 ]   
  then
    SEMMNS=`/usr/bin/echo 16i $SEMMNS p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$SEMMNS"
  then
    /usr/bin/echo "ALERT- SEMMNS has not been defined and needs to be set to 8192" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $SEMMNS -lt 8192 ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter SEMMNS to at least 8192 from present setting of $SEMMNS" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SEMMNS set to $SEMMNS is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $SEMMNU | /usr/bin/grep -ic 0x` != 0 ]   
  then
    SEMMNU=`/usr/bin/echo 16i $SEMMNU p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$SEMMNU"
  then
    /usr/bin/echo "ALERT- SEMMNU has not been defined and needs to be set to 4092" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $SEMMNU -lt 4092 ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter SEMMNU to at least 4092 from present setting of $SEMMNU" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SEMMNU set to $SEMMNU is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $SEMVMX | /usr/bin/grep -ic 0x` != 0 ]   
  then
    SEMVMX=`/usr/bin/echo 16i $SEMVMX p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$SEMVMX"
  then
    /usr/bin/echo "ALERT- SEMVMX has not been defined and needs to be set to 32768" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $SEMVMX -lt 32768 ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter SEMVMX to at least 32768 from present setting of $SEMVMX" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SEMVMX set to $SEMVMX is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $SHMMAX | /usr/bin/grep -ic 0x` != 0 ]   
  then
    SHMMAX=`/usr/bin/echo 16i $SHMMAX p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$SHMMAX"
  then
    /usr/bin/echo "ALERT-  SHMMAX has not been defined and needs to be set to $MEM Mb" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $SHMMAX -lt $MEM ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter SHMMAX to $MEM Mb from present setting of $SHMMAX, Note: on HP there is an issue with manipulating large values so this may not be correct, and your setting is correct" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SHMMAX set to $SHMMAX is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $SHMMNI | /usr/bin/grep -ic 0x` != 0 ]   
  then
    SHMMNI=`/usr/bin/echo 16i $SHMMNI p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$SHMMNI"
  then
    /usr/bin/echo "ALERT- SHMMNI has not been defined and needs to be set to 512" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $SHMMNI -lt 512 ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter SHMMNI to at least 512 from present setting of $SHMMNI" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SHMMNI set to $SHMMNI is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $SHMSEG | /usr/bin/grep -ic 0x` != 0 ]   
  then
    SHMSEG=`/usr/bin/echo 16i $SHMSEG p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$SHMSEG"
  then
    /usr/bin/echo "ALERT- SHMSEG has not been defined and needs to be set to 32" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $SHMSEG -lt 32 ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter SHMSEG to at least 32 from present setting of $SHMSEG" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SHMSEG set to $SHMSEG is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $VPS_CEILING | /usr/bin/grep -ic 0x` != 0 ]   
  then
    VPS_CEILING=`/usr/bin/echo 16i $VPS_CEILING p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$VPS_CEILING"
  then
    /usr/bin/echo "ALERT- VPS_CEILING has not been defined and needs to be set to 64" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $VPS_CEILING -lt 64 ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter VPS_CEILING to at least 64 from present setting of $VPS_CEILING" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "VPS_CEILING set to $VPS_CEILING is adequate" | /usr/bin/tee -a $REPORT
  fi
fi

if [ $ORAVER = "805" -o $ORAVER = "806" -o $ORAVER = "815" -o $ORAVER = "816" ] && [ $ORABIT = 64 ]
then
  if [ `/usr/bin/echo $MAXDSIZ | /usr/bin/grep -ic 0x` != 0 ]   
  then
    MAXDSIZ=`/usr/bin/echo 16i $MAXDSIZ p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MAXDSIZ"
  then
    /usr/bin/echo "ALERT- MAXDSIZ has not been defined and needs to be set to 128 Mb" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MAXDSIZ -lt 131072000 ]
  then
    /usr/bin/echo "ALERT-  MAXDSIZ set at $MAXDSIZ needs to be increased to at least 128 Mb" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MAXDSIZ set to $MAXDSIZ is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $MAXDSIZ_64BIT | /usr/bin/grep -ic 0x` != 0 ]
  then
    MAXDSIZ_64BIT=`/usr/bin/echo 16i $MAXDSIZ_64BIT p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MAXDSIZ_64BIT"
  then
    /usr/bin/echo "ALERT- MAXDSIZ_64BIT has not been defined and needs to be set to 128 Mb" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MAXDSIZ_64BIT -lt 131072000 ]
  then
    /usr/bin/echo "ALERT-  MAXDSIZ_64BIT set at $MAXDSIZ_64BIT needs to be increased to at least 128 Mb" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MAXDSIZ_64BIT set to $MAXDSIZ_64BIT is adequate" | /usr/bin/tee -a $REPORT
  fi
elif [ $ORAVER = "805" -o $ORAVER = "806" -o $ORAVER = "815" -o $ORAVER = "816" ] && [ $ORABIT = 32 ]
then
  if [ `/usr/bin/echo $MAXDSIZ | /usr/bin/grep -ic 0x` != 0 ]   
  then
    MAXDSIZ=`/usr/bin/echo 16i $MAXDSIZ p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MAXDSIZ"
  then
    /usr/bin/echo "ALERT- MAXDSIZ has not been defined and needs to be set to 128 Mb" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MAXDSIZ -lt 131072000 ]
  then
    /usr/bin/echo "ALERT-  MAXDSIZ set at $MAXDSIZ needs to be increased to at least 128 Mb" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MAXDSIZ set to $MAXDSIZ is adequate" | /usr/bin/tee -a $REPORT
  fi
elif [ $ORAVER = "817" -a $ORABIT = "64" ]
then
  if [ `/usr/bin/echo $MAX_THREAD_PROC | /usr/bin/grep -ic 0x` != 0 ]   
  then
    MAX_THREAD_PROC=`/usr/bin/echo 16i $MAX_THREAD_PROC p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MAX_THREAD_PROC"
  then
    /usr/bin/echo "ALERT- MAX_THREAD_PROC has not been defined and needs to be set to 256" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MAX_THREAD_PROC -lt 256 ]
  then
    /usr/bin/echo "ALERT- Increase the kernel parameter MAX_THREAD_PROC to 256 from present setting of $MAX_THREAD_PROC" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MAX_THREAD_PROC set to $MAX_THREAD_PROC is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $NFLOCKS | /usr/bin/grep -ic 0x` != 0 ]   
  then
    NFLOCKS=`/usr/bin/echo 16i $NFLOCKS p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$NFLOCKS"
  then
    /usr/bin/echo "ALERT- NFLOCKS has not been defined and needs to be set to 200 or more" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $NFLOCKS -lt 300 ]
  then
    /usr/bin/echo "ALERT- Increase the kernel parameter NFLOCKS to at least 200 from present setting of $NFLOCKS" | /usr/bin/tee -a $REPORT     
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "NFLOCKS set to $NFLOCKS is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $MAXDSIZ | /usr/bin/grep -ic 0x` != 0 ]   
  then
    MAXDSIZ=`/usr/bin/echo 16i $MAXDSIZ p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MAXDSIZ"
  then
    /usr/bin/echo "ALERT- MAXDSIZ has not been defined and needs to be set to 1073741824" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MAXDSIZ -lt 1073741824 ]
  then
    /usr/bin/echo "ALERT-  MAXDSIZ set at $MAXDSIZ needs to be increased to at least 1073741824" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MAXDSIZ set to $MAXDSIZ is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $MAXDSIZ_64BIT | /usr/bin/grep -ic 0x` != 0 ]
  then
        MAXDSIZ_64BIT=`/usr/bin/echo 16i $MAXDSIZ_64BIT p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MAXDSIZ_64BIT"
  then
    /usr/bin/echo "ALERT- MAXDSIZ_64BIT has not been defined and needs to be set to 1717986918" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MAXDSIZ_64BIT -lt 1717986918 ]
  then
    /usr/bin/echo "ALERT-  MAXDSIZ_64BIT set at $MAXDSIZ_64BIT needs to be increased to at least 1717986918" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MAXDSIZ_64BIT set to $MAXDSIZ_64BIT is adequate" | /usr/bin/tee -a $REPORT
  fi
    
  if [ `/usr/bin/echo $MAXSSIZ | /usr/bin/grep -ic 0x` != 0 ]   
  then
    MAXSSIZ=`/usr/bin/echo 16i $MAXSSIZ p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MAXSSIZ"
  then
    /usr/bin/echo "ALERT- MAXSSIZ has not been defined and needs to be set to 209715200" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MAXSSIZ -lt 209715200 ]
  then
    /usr/bin/echo "ALERT-  MAXSSIZ set at $MAXSSIZ needs to be increased to at least 209715200" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MAXSSIZ set to $MAXSSIZ is adequate" | /usr/bin/tee -a $REPORT
  fi
    
  if [ `/usr/bin/echo $MAXSSIZ_64BIT | /usr/bin/grep -ic 0x` != 0 ]
  then
    MAXSSIZ_64BIT=`/usr/bin/echo 16i $MAXSSIZ_64BIT p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MAXSSIZ_64BIT"
  then
    /usr/bin/echo "ALERT- MAXSSIZ_64BIT has not been defined and needs to be set to 209715200" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MAXSSIZ_64BIT -lt 209715200 ]
  then
    /usr/bin/echo "ALERT-  MAXSSIZ_64BIT set at $MAXSSIZ_64BIT needs to be increased to at least 209715200" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MAXSSIZ_64BIT set to $MAXSSIZ_64BIT is adequate" | /usr/bin/tee -a $REPORT
  fi
    
  if [ `/usr/bin/echo $MAXTSIZ | /usr/bin/grep -ic 0x` != 0 ]   
  then
    MAXTSIZ=`/usr/bin/echo 16i $MAXTSIZ p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MAXTSIZ"
  then
    /usr/bin/echo "ALERT- MAXTSIZ has not been defined and needs to be set to 209715200" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MAXTSIZ -lt 209715200 ]
  then
    /usr/bin/echo "ALERT-  MAXTSIZ set at $MAXTSIZ needs to be increased to at least 1073741824" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MAXTSIZ set to $MAXTSIZ is adequate" | /usr/bin/tee -a $REPORT
  fi
    
  if [ `/usr/bin/echo $MAXTSIZ_64BIT | /usr/bin/grep -ic 0x` != 0 ]
  then
    MAXTSIZ_64BIT=`/usr/bin/echo 16i $MAXTSIZ_64BIT p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MAXTSIZ_64BIT"
  then
    /usr/bin/echo "ALERT- MAXTSIZ_64BIT has not been defined and needs to be set to 1073741824" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MAXTSIZ_64BIT -lt 1073741824 ]
  then
    /usr/bin/echo "ALERT-  MAXTSIZ_64BIT set at $MAXTSIZ_64BIT needs to be increased to at least 1073741824" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MAXTSIZ_64BIT set to $MAXTSIZ_64BIT is adequate" | /usr/bin/tee -a $REPORT
  fi
elif [ $ORAVER = "817" -a $ORABIT = "32" ]
then
  if [ `/usr/bin/echo $MAX_THREAD_PROC | /usr/bin/grep -ic 0x` != 0 ]   
  then
    MAX_THREAD_PROC=`/usr/bin/echo 16i $MAX_THREAD_PROC p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MAX_THREAD_PROC"
  then
    /usr/bin/echo "ALERT- MAX_THREAD_PROC has not been defined and needs to be set to 256" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MAX_THREAD_PROC -lt 256 ]
  then
    /usr/bin/echo "ALERT- Increase the kernel parameter MAX_THREAD_PROC to 256 from present setting of $MAX_THREAD_PROC" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MAX_THREAD_PROC set to $MAX_THREAD_PROC is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $NFLOCKS | /usr/bin/grep -ic 0x` != 0 ]   
  then
    NFLOCKS=`/usr/bin/echo 16i $NFLOCKS p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$NFLOCKS"
  then
    /usr/bin/echo "ALERT- NFLOCKS has not been defined and needs to be set to 200 or more" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $NFLOCKS -lt 300 ]
  then
    /usr/bin/echo "ALERT- Increase the kernel parameter NFLOCKS to at least 200 from present setting of $NFLOCKS" | /usr/bin/tee -a $REPORT     
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "NFLOCKS set to $NFLOCKS is adequate" | /usr/bin/tee -a $REPORT
  fi

  if [ `/usr/bin/echo $MAXDSIZ | /usr/bin/grep -ic 0x` != 0 ]   
  then
    MAXDSIZ=`/usr/bin/echo 16i $MAXDSIZ p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MAXDSIZ"
  then
    /usr/bin/echo "ALERT- MAXDSIZ has not been defined and needs to be set to 1073741824" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MAXDSIZ -lt 1073741824 ]
  then
    /usr/bin/echo "ALERT-  MAXDSIZ set at $MAXDSIZ needs to be increased to at least 1073741824" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MAXDSIZ set to $MAXDSIZ is adequate" | /usr/bin/tee -a $REPORT
  fi
  
  if [ `/usr/bin/echo $MAXSSIZ | /usr/bin/grep -ic 0x` != 0 ]   
  then
    MAXSSIZ=`/usr/bin/echo 16i $MAXSSIZ p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MAXSSIZ"
  then
    /usr/bin/echo "ALERT- MAXSSIZ has not been defined and needs to be set to 209715200" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MAXSSIZ -lt 209715200 ]
  then
    /usr/bin/echo "ALERT-  MAXSSIZ set at $MAXSSIZ needs to be increased to at least 209715200" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MAXSSIZ set to $MAXSSIZ is adequate" | /usr/bin/tee -a $REPORT
  fi
        
  if [ `/usr/bin/echo $MAXTSIZ | /usr/bin/grep -ic 0x` != 0 ]   
  then
    MAXTSIZ=`/usr/bin/echo 16i $MAXTSIZ p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MAXTSIZ"
  then
    /usr/bin/echo "ALERT- MAXTSIZ has not been defined and needs to be set to 209715200" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MAXTSIZ -lt 209715200 ]
  then
    /usr/bin/echo "ALERT-  MAXTSIZ set at $MAXTSIZ needs to be increased to at least 1073741824" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MAXTSIZ set to $MAXTSIZ is adequate" | /usr/bin/tee -a $REPORT
  fi
elif [ $ORAVER = "901" -o $ORAVER = "920" ]
then
  if [ `/usr/bin/echo $MAXDSIZ | /usr/bin/grep -ic 0x` != 0 ]   
  then
    MAXDSIZ=`/usr/bin/echo 16i $MAXDSIZ p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MAXDSIZ"
  then
    /usr/bin/echo "ALERT- MAXDSIZ has not been defined and needs to be set to 1073741824" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MAXDSIZ -lt 1073741824 ]
  then
    /usr/bin/echo "ALERT-  MAXDSIZ set at $MAXDSIZ needs to be increased to at least 1073741824" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MAXDSIZ set to $MAXDSIZ is adequate" | /usr/bin/tee -a $REPORT
  fi
 
  if [ `/usr/bin/echo $MAXDSIZ_64BIT | /usr/bin/grep -ic 0x` != 0 ]
  then
    MAXDSIZ_64BIT=`/usr/bin/echo 16i $MAXDSIZ_64BIT p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MAXDSIZ_64BIT"
  then
    /usr/bin/echo "ALERT- MAXDSIZ_64BIT has not been defined and needs to be set to 2147483648" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MAXDSIZ_64BIT -lt 2147483648 ]
  then
    /usr/bin/echo "ALERT-  MAXDSIZ_64BIT set at $MAXDSIZ_64BIT needs to be increased to at least 2147483648" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MAXDSIZ_64BIT set to $MAXDSIZ_64BIT is adequate" | /usr/bin/tee -a $REPORT
  fi
    
  if [ `/usr/bin/echo $MAXSSIZ | /usr/bin/grep -ic 0x` != 0 ]   
  then
    MAXSSIZ=`/usr/bin/echo 16i $MAXSSIZ p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MAXSSIZ"
  then
    /usr/bin/echo "ALERT- MAXSSIZ has not been defined and needs to be set to 134217728" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MAXSSIZ -lt 134217728 ]
  then
    /usr/bin/echo "ALERT-  MAXSSIZ set at $MAXSSIZ needs to be increased to at least 134217728" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MAXSSIZ set to $MAXSSIZ is adequate" | /usr/bin/tee -a $REPORT
  fi
    
  if [ `/usr/bin/echo $MAXSSIZ_64BIT | /usr/bin/grep -ic 0x` != 0 ]
  then
    MAXSSIZ_64BIT=`/usr/bin/echo 16i $MAXSSIZ_64BIT p | /usr/bin/dc | /usr/bin/tail -1`
  fi
  if /usr/bin/test -z "$MAXSSIZ_64BIT"
  then
    /usr/bin/echo "ALERT- MAXSSIZ_64BIT has not been defined and needs to be set to 1073741824" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $MAXSSIZ_64BIT -lt 1073741824 ]
  then
    /usr/bin/echo "ALERT-  MAXSSIZ_64BIT set at $MAXSSIZ_64BIT needs to be increased to at least 1073741824" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "MAXSSIZ_64BIT set to $MAXSSIZ_64BIT is adequate" | /usr/bin/tee -a $REPORT
  fi
fi

/usr/bin/echo "\nFor formula calculations, here are the values of other related kernel parameters:" | /usr/bin/tee -a $REPORT
/usr/bin/echo "NPROC = $NPROC" | /usr/bin/tee -a $REPORT
/usr/bin/echo "MAXUSERS = $MAXUSERS" | /usr/bin/tee -a $REPORT
/usr/bin/echo "VX_NCSIZE = $VX_NCSIZE" | /usr/bin/tee -a $REPORT


# HPUX HP REQUIRED LINKS THAT MUST BE CREATED BY CUSTOMERS FOR 9.2

if [ $ORAVER = 920 ] && [ $OSVER != "11.22" ] && [ $OSVER != "11.23" ]
then
  /usr/bin/echo "\n \n \nRequired HP-UX OS Links/Libraries Verification" | /usr/bin/tee -a $REPORT
  /usr/bin/echo "_____________________________________________\n" | /usr/bin/tee -a $REPORT

  for NEEDEDLIB in libX11.sl libXIE.sl libXext.sl libXhp11.sl libXi.sl libXm.sl libXp.sl libXt.sl libXtst.sl
  do
    if /usr/bin/test -x /usr/lib/$NEEDEDLIB
    then
      /usr/bin/echo "Library $NEEDEDLIB was found as required in /usr/lib" | /usr/bin/tee -a $REPORT
    else
      /usr/bin/echo "ALERT- Library $NEEDEDLIB was NOT found as required in /usr/lib" | /usr/bin/tee -a $REPORT
    fi
  done
fi


# HPUX ASSEMBLY TOOL VERIFICATION

/usr/bin/echo "\n \n \nAssembly Tool Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________\n" | /usr/bin/tee -a $REPORT

arvalue=`/usr/bin/which ar`
if [ "$arvalue" != "/usr/ccs/bin/ar" ]
then
  /usr/bin/echo "WARNING-  ar not found in /usr/ccs/bin directory but was found in '$arvalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /usr/bin/echo "ar - found correctly in /usr/ccs/bin" | /usr/bin/tee -a $REPORT
fi

ldvalue=`/usr/bin/which ld`
if [ "$ldvalue" != "/usr/ccs/bin/ld" ]
then
  /usr/bin/echo "WARNING-  ld not found in /usr/ccs/bin directory but was found in '$ldvalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /usr/bin/echo "ld - found correctly in /usr/ccs/bin" | /usr/bin/tee -a $REPORT
fi

nmvalue=`/usr/bin/which nm`
if [ "$nmvalue" != "/usr/ccs/bin/nm" ]
then
  /usr/bin/echo "WARNING-  nm not found in /usr/ccs/bin directory but was found in '$nmvalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /usr/bin/echo "nm - found correctly in /usr/ccs/bin" | /usr/bin/tee -a $REPORT
fi

makevalue=`/usr/bin/which make`
if [ "$makevalue" != "/usr/ccs/bin/make" ]
then
  /usr/bin/echo "WARNING-  make not found in /usr/ccs/bin directory but was found in '$makevalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /usr/bin/echo "make - found correctly in /usr/ccs/bin" | /usr/bin/tee -a $REPORT
fi

ccvalue=`/usr/bin/which cc`
if [ "$ccvalue" != "/usr/ccs/bin/cc" ]
then
  /usr/bin/echo "WARNING-  cc not found in /usr/ccs/bin directory but was found in '$ccvalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /usr/bin/echo "cc - found correctly in /usr/ccs/bin" | /usr/bin/tee -a $REPORT
fi

# HPUX ULIMIT VERIFICATION

/usr/bin/echo "\n \n \nVerification of ulimits" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_______________________________\n" | /usr/bin/tee -a $REPORT

TIMERAW=`/usr/bin/ulimit -t`
TIME=`/usr/bin/ulimit -t | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$TIME"
then
  /usr/bin/echo "ALERT- ulimit(TIME) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $TIME -lt 1000000000 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(TIME) to unlimited from the present $TIMERAW" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(TIME) set to $TIMERAW is adequate" | /usr/bin/tee -a $REPORT
fi

FILERAW=`/usr/bin/ulimit -f`
FILE=`/usr/bin/ulimit -f | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$FILE"
then
  /usr/bin/echo "ALERT- ulimit(FILE) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $FILE -lt 1000000000 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(FILE) to unlimited from the present $FILERAW" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(FILE) set to $FILERAW is adequate" | /usr/bin/tee -a $REPORT
fi

DATARAW=`/usr/bin/ulimit -d`
DATA=`/usr/bin/ulimit -d | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$DATA"
then
  /usr/bin/echo "ALERT- ulimit(DATA) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $DATA -lt 1572864 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(DATA) to 1572864 from the present $DATARAW" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(DATA) set to $DATARAW is adequate" | /usr/bin/tee -a $REPORT
fi

STACKRAW=`/usr/bin/ulimit -s`
STACK=`/usr/bin/ulimit -s | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$STACK"
then
  /usr/bin/echo "ALERT- ulimit(STACK) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $STACK -lt 32768 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(STACK) to 32768 from the present $STACKRAW" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(STACK) set to $STACKRAW is adequate" | /usr/bin/tee -a $REPORT
fi

NOFILESRAW=`/usr/bin/ulimit -n`
NOFILES=`/usr/bin/ulimit -n | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$NOFILES"
then
  /usr/bin/echo "ALERT- ulimit(NOFILES) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $NOFILES -lt 2048 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(NOFILES) to 2048 from the present $NOFILESRAW" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(NOFILES) set to $NOFILESRAW is adequate" | /usr/bin/tee -a $REPORT
fi

MEMORYRAW=`/usr/bin/ulimit -m`
MEMORY=`/usr/bin/ulimit -m | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$MEMORY"
then
  /usr/bin/echo "ALERT- ulimit(MEMORY) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $MEMORY -lt 1000000000 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(MEMORY) to unlimited from the present $MEMORY" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(MEMORY) set to $MEMORYRAW is adequate" | /usr/bin/tee -a $REPORT
fi



# HPUX CERTIFICATION VERIFICATION

/usr/bin/echo "\n \n \nCertification of Oracle and OS Version Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________________________________________\n" | /usr/bin/tee -a $REPORT
case $OSVER in
      "10.20")
        if [ $ORABIT = 64 ]
        then
          /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER $OSBIT bit is not certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
          SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
        elif [ $ORAVER = "805" -o $ORAVER = "806" ]
        then
          /usr/bin/echo "$OS $OSVER $OSBIT bit is certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
        else
          /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER $OSBIT bit is not certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
          SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
        fi        
        ;;
      "11.00")
        if [ $OSBIT = 32 -a $ORAVER = "901" ] || [ $OSBIT = 32 -a $ORAVER = "920" ] || [ $ORABIT = 32 -a $ORAVER = "901" ] || [ $ORABIT = 32 -a $ORAVER = "920" ]
        then
          /usr/bin/echo "!!SHOWSTOPPER!!-  $OS $OSVER $OSBIT bit is not certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
          SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
        else
          /usr/bin/echo "$OS $OSVER $OSBIT bit is certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
        fi
        ;;
      "11.11")
        if [ $ORAVER = "805" -o $ORAVER = "815" ]
        then
          /usr/bin/echo "!!SHOWSTOPPER!!  Oracle $ORAVER is not certified to run on $OS $OSVER\n" | /usr/bin/tee -a $REPORT
          SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
        elif [ $OSBIT = 32 -a $ORAVER = "901" ] || [ $OSBIT = 32 -a $ORAVER = "920" ] || [ $ORABIT = 32 -a $ORAVER = "901" ] || [ $ORABIT = 32 -a $ORAVER = "920" ]
        then 
          /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER $OSBIT bit is not certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
          SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
        else
          /usr/bin/echo "$OS $OSVER $OSBIT bit is certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
        fi
        ;;
      "11.22"|"11.23")
        if [ $ORAVER != "920" ]
        then
          /usr/bin/echo "!!SHOWSTOPPER!!  Oracle $ORAVER is not certified to run on $OS $OSVER\n" | /usr/bin/tee -a $REPORT
          SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
        else
          /usr/bin/echo "$OS $OSVER $OSBIT bit is certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
        fi
        ;;
      *)
        /usr/bin/echo "ALERT-  The $OS OS Version was not determinable or is incorrect\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1` 
        ;;
esac

# HPUX Verify OS patches are installed

/usr/bin/echo "\n \n \nOS Patches Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________\n" | /usr/bin/tee -a $REPORT

case $ORAVER in
  "805")
    PACKAGE1=PHNE_15995
    PACKAGE2=PHNE_21767
    PACKAGE3=PHNE_26771
    if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
    then
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
        then
          /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        else
          /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
      fi
    else
      /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
    fi
    if [ $OSBIT = 64 -a $OSVER = "11.00" ]
    then
      PACKAGE1=PHSS_15316
      PACKAGE2=PHSS_24303
      PACKAGE3=PHSS_26262
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
          then
            /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
            ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
          else
            /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
          fi
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
   fi
   ;;
  "806")
    if [ $OSVER != "11.11" ]
    then
      PACKAGE1=PHNE_15995
      PACKAGE2=PHNE_21767
      PACKAGE3=PHNE_26771
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
          then
            /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
            ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
          else
            /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
          fi
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      if [ $OSBIT = 64 -a $OSVER = "11.00" ]
      then
        PACKAGE1=PHSS_15316
        PACKAGE2=PHSS_24303
        PACKAGE3=PHSS_26262
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
        then
          if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
          then
            if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
            then
              /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
              ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
            else
              /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
            fi
          else
            /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
          fi
        else
          /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
        fi
      fi
    else
      /usr/bin/echo "INFO- no patches need to be verified since OS version is $OSVER" | /usr/bin/tee -a $REPORT
    fi
   ;;

  "815")
     if [ $OSVER != "11.11" ]
     then
       PACKAGE1=PHKL_14750
       PACKAGE2=PHKL_25475
       PACKAGE3=PHKL_27510
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHKL_17709
       PACKAGE2=PHKL_23792
       PACKAGE3=PHKL_26960
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHKL_17869
       PACKAGE2=PHKL_18543
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHNE_17446
       PACKAGE2=PHNE_21767
       PACKAGE3=PHNE_26771
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
              ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
     else
      /usr/bin/echo "INFO- no patches need to be verified since OS version is $OSVER" | /usr/bin/tee -a $REPORT
     fi
      ;;
  "816")
     if [ $OSVER != "11.11" ]
     then
       PACKAGE1=PHCO_17556
       PACKAGE2=PHCO_23651
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHCO_17792
       PACKAGE2=PHCO_21187
       PACKAGE3=PHCO_25902
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHCO_18229
       PACKAGE2=PHCO_23963
       PACKAGE3=PHCO_26111
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHCO_19491
       PACKAGE2=PHCO_25707
       PACKAGE3=PHCO_27608
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHCO_19666
       PACKAGE2=PHCO_23792
       PACKAGE3=PHCO_26960
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHKL_14750
       PACKAGE2=PHKL_25475
       PACKAGE3=PHKL_27510
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHKL_17038
       PACKAGE2=PHKL_25525
       PACKAGE3=PHKL_27364
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       for PATCH in PHKL_18543
         do
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
       PACKAGE1=PHKL_19800
       PACKAGE2=PHKL_24027
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       for PATCH in PHKL_20016
         do
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
       PACKAGE1=PHKL_20079
       PACKAGE2=PHKL_24027
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHNE_19616
       PACKAGE2=PHNE_24100
       PACKAGE3=PHNE_25385
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHSS_14582
       PACKAGE2=PHSS_26320
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHSS_15853
       PACKAGE2=PHSS_23546
       PACKAGE3=PHSS_26566
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHSS_16849
       PACKAGE2=PHSS_25718
       PACKAGE3=PHSS_27469
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHSS_17535
       PACKAGE2=PHSS_25091
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       for PATCH in PHSS_18066
         do
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
       PACKAGE1=PHSS_18110
       PACKAGE2=PHSS_26213
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHSS_18430
       PACKAGE2=PHSS_25199
       PACKAGE3=PHSS_26495
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHSS_18649
       PACKAGE2=PHSS_26320
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHSS_19593
       PACKAGE2=PHSS_25447
       PACKAGE3=PHSS_27230
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHSS_19178
       PACKAGE2=PHSS_25249
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHSS_19748
       PACKAGE2=PHSS_25149
       PACKAGE3=PHSS_26490
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHSS_19866
       PACKAGE2=PHSS_24303
       PACKAGE3=PHSS_26262
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHSS_20544
       PACKAGE2=PHSS_26138
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHSS_20014
       PACKAGE2=PHSS_24303
       PACKAGE3=PHSS_26262
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       for PATCH in PHKL_21180
         do
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
     else
      /usr/bin/echo "INFO- no patches need to be verified since OS version is $OSVER" | /usr/bin/tee -a $REPORT
     fi
   ;;
  "817")
     if [ $OSVER != "11.11" ]
     then
       PACKAGE1=PHSS_21947
       PACKAGE2=PHSS_24303
       PACKAGE3=PHSS_26559
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHNE_20316
       PACKAGE2=PHNE_22566
       PACKAGE3=PHNE_25440
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHKL_21392
       PACKAGE2=PHKL_24027
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHKL_22145
       PACKAGE2=PHKL_25475
       PACKAGE3=PHKL_27510
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHKL_22266
       PACKAGE2=PHKL_27178
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
     else
      /usr/bin/echo "INFO- no patches need to be verified since OS version is $OSVER" | /usr/bin/tee -a $REPORT
     fi 
    ;;
  "901")
    if [ $OSVER = "11.00" ]
    then
       PACKAGE1=PHCO_23092
       PACKAGE2=PHCO_23963
       PACKAGE3=PHCO_26111
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHCO_23770
       PACKAGE2=PHCO_25707
       PACKAGE3=PHCO_27608
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHCO_23919
       PACKAGE2=PHCO_27340
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       for PATCH in PHKL_18543
         do
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PATCH` = 0 ]
           then
             /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
           fi
         done
       PACKAGE1=PHKL_23226
       PACKAGE2=PHKL_27510
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHKL_23813
       PACKAGE2=PHKL_25525
       PACKAGE3=PHKL_27364
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHKL_23814
       PACKAGE2=PHKL_24729
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHKL_23815
       PACKAGE2=PHKL_26337
       PACKAGE3=PHKL_27553
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
       PACKAGE1=PHKL_23857
       PACKAGE2=PHKL_25525
       PACKAGE3=PHKL_27364
       if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
       then
         if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
         then
           if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
           then
             /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
           else
             /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
           fi
         else
           /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
         fi
       else
         /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
       fi
    fi
    if [ $OSVER = "11.11" ]
    then
      PACKAGE1=PHCO_23094
      PACKAGE2=PHCO_24402
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHCO_23772
      PACKAGE2=PHCO_26124
      PACKAGE3=PHCO_27910
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
          then
            /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
            ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
          else
            /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
          fi
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHSS_23441
      PACKAGE2=PHSS_26263
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHNE_23502
      PACKAGE2=PHNE_25625
      PACKAGE3=PHNE_26388
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
          then
            /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
            ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
          else
            /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
          fi
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
    fi
    ;;
 "920")
    if [ $OSVER = "11.00" ]
    then
      for PATCH in PHSS_24627 PHSS_22868
        do
          if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PATCH` = 0 ]
          then
            /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
            ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
          else
            /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
          fi
        done
      PACKAGE1=PHCO_23792
      PACKAGE2=PHCO_26960
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHCO_24148
      PACKAGE2=PHCO_25707
      PACKAGE3=PHCO_27608
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
          then
            /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
            ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
          else
            /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
          fi
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHKL_24268
      PACKAGE2=PHKL_27178
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHKL_24729
      PACKAGE2=PHKL_29256
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHKL_25475
      PACKAGE2=PHKL_27510
      PACKAGE3=PHKL_30553
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
          then
            /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
            ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
          else
            /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
          fi
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHKL_25525
      PACKAGE2=PHKL_27364
      PACKAGE3=PHKL_31867
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
          then
            /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
            ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
          else
            /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
          fi
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHNE_24715
      PACKAGE2=PHNE_26771
      PACKAGE3=PHNE_29473
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
          then
            /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
            ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
          else
            /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
          fi
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHSS_23670
      PACKAGE2=PHSS_26138
      PACKAGE3=PHSS_27858
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
          then
            /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
            ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
          else
            /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
          fi
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHSS_24301
      PACKAGE2=PHSS_26273
      PACKAGE3=PHSS_28433
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
          then
            /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
            ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
          else
            /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
          fi
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHSS_24303
      PACKAGE2=PHSS_26559
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
    fi
    if [ $OSVER = "11.11" ]
    then
      PACKAGE1=PHCO_24404
      PACKAGE2=PHCO_25569
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHCO_28427
      PACKAGE2=PHCO_29029
      PACKAGE3=PHCO_31903
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE3` = 0 ]
          then
            /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 or it's successor $PACKAGE3 are installed" | /usr/bin/tee -a $REPORT
            ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
          else
            /usr/bin/echo "The $PACKAGE3 package (which supercedes $PACKAGE1 and $PACKAGE2) is installed" | /usr/bin/tee -a $REPORT
          fi
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      for PATCH in PHKL_25506
        do
          if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PATCH` = 0 ]
          then
            /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
            ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
          else
            /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
          fi
        done
      PACKAGE1=PHNE_27745
      PACKAGE2=PHNE_30580
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed - These patches are for RAC only" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHNE_28568
      PACKAGE2=PHNE_30378
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHSS_26560
      PACKAGE2=PHSS_30966
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      for PATCH in PHSS_26946
        do
          if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PATCH` = 0 ]
          then
            /usr/bin/echo "ALERT-  The $PATCH package needs to be installed" | /usr/bin/tee -a $REPORT
            ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
          else
            /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
          fi
        done
      for PATCH in PHSS_28849
        do
          if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PATCH` = 0 ]
          then
            /usr/bin/echo "ALERT-  The $PATCH package needs to be installed.  This patch is needed, applicable for Service Guard 11.13" | /usr/bin/tee -a $REPORT
            ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
          else
            /usr/bin/echo "The $PATCH package is installed" | /usr/bin/tee -a $REPORT
          fi
        done
    fi
    if [ $OSVER = "11.22" ]
    then
      PACKAGE1=PHSS_27284
      PACKAGE2=PHSS_28977
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHSS_27285
      PACKAGE2=PHSS_28970
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHSS_27286
      PACKAGE2=PHSS_28978
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHSS_27287
      PACKAGE2=PHSS_29652
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHSS_27288
      PACKAGE2=PHSS_28971
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHSS_27289
      PACKAGE2=PHSS_29653
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHSS_27290
      PACKAGE2=PHSS_28973
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHSS_27291
      PACKAGE2=PHSS_28969
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHSS_27292
      PACKAGE2=PHSS_29654
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHSS_27293
      PACKAGE2=PHSS_28975
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE2` = 0 ]
        then
          /usr/bin/echo "ALERT-  Neither $PACKAGE1 or it's successor $PACKAGE2 are installed" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        else
          /usr/bin/echo "The $PACKAGE2 package (which supercedes $PACKAGE1) is installed" | /usr/bin/tee -a $REPORT
        fi
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
      PACKAGE1=PHKL_28465
      if [ `/usr/sbin/swlist -l fileset 2>/dev/null | /usr/bin/grep -ic $PACKAGE1` = 0 ]
      then
        /usr/bin/echo "ALERT- $PACKAGE1 is not installed" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "The $PACKAGE1 package is installed" | /usr/bin/tee -a $REPORT
      fi
    fi
    if [ $OSVER = "11.23" ]
    then
      /usr/bin/echo "$OSVER does not require additional patches at this time" | /usr/bin/tee -a $REPORT
    fi
    ;;
  *)
    /usr/bin/echo " "
    ;;
esac
;;

"Linux"|"LINUX")
OSVER=`/bin/uname -r`

# Linux START ECHO OF SCRIPT TO OUTPUT FILE

`/bin/touch $REPORT; /bin/chmod 777 $REPORT` 
/bin/echo "Output from the Oracle InstallPrep Script run on $BOXNAME on `date`." > $REPORT 
/bin/echo; /bin/echo; /bin/echo >> $REPORT
/bin/echo "To successfully install the Oracle Database Software you must resolve each item listed in this Report." >> $REPORT
/bin/echo; /bin/echo; /bin/echo >> $REPORT
/bin/echo "InstallPrep now running on your $OS box ....." | /usr/bin/tee -a $REPORT
/bin/echo; /bin/echo | /usr/bin/tee -a $REPORT


# Linux  ORACLE VERSION INPUT
/bin/echo; /bin/echo; /bin/echo | /usr/bin/tee -a $REPORT
/bin/echo "Oracle Version Input" | /usr/bin/tee -a $REPORT
/bin/echo "_______________________" | /usr/bin/tee -a $REPORT
/bin/echo " " | /usr/bin/tee -a $REPORT
/bin/echo "What version of Oracle are you installing?" | /usr/bin/tee -a $REPORT
/bin/echo "(valid values:805,806,815,816,817,901,920):" | /usr/bin/tee -a $REPORT
read ORAVER
/bin/echo $ORAVER >> $REPORT
case $ORAVER in
  "805"|"806"|"815"|"816"|"817"|"901"|"920")
    ;;
  "")
    /bin/echo; /bin/echo "ALERT-  You did not enter a value" | /usr/bin/tee -a $REPORT 
    exit
    ;;
  *)
    /bin/echo; /bin/echo "ALERT-  You have entered an invalid version - enter valid value" | /usr/bin/tee -a $REPORT
    exit
    ;;
esac

# Linux CORRECT USER VERIFICATION

/bin/echo; /bin/echo; /bin/echo | /usr/bin/tee -a $REPORT
/bin/echo "User Verification" | /usr/bin/tee -a $REPORT
/bin/echo "_________________________" | /usr/bin/tee -a $REPORT; /bin/echo
USER=`/usr/bin/id -nu`
if [ $USER = "root" ]
then
  /bin/echo | /usr/bin/tee -a $REPORT
  /bin/echo "ALERT-  You are logged in as user -- $USER --.  Please log in as the user that will be installing the Oracle Database Software. This user should not be root." | /usr/bin/tee -a $REPORT
  /bin/echo "Exiting" | /usr/bin/tee -a $REPORT
  exit;
else
  /bin/echo | /usr/bin/tee -a $REPORT
  /bin/echo "You are currently logged on as user -- $USER -- " | /usr/bin/tee -a $REPORT
  /bin/echo | /usr/bin/tee -a $REPORT
fi

# Linux CONFIRMATION OF USER

/bin/echo "Is user $USER the Linux user that will be installing Oracle Software?  (y or n)" | /usr/bin/tee -a $REPORT
read answer
/bin/echo $answer >> $REPORT
case $answer in
  "n"|"N")
    /bin/echo | /usr/bin/tee -a $REPORT
    /bin/echo "ALERT-  Please log in as the user that will be installing Oracle.  Then rerun this script" | /usr/bin/tee -a $REPORT
    /bin/echo | /usr/bin/tee -a $REPORT
    exit
    ;;
  "y"|"Y")
    /bin/echo; /bin/echo; /bin/echo | /usr/bin/tee -a $REPORT
    /bin/echo "Verifying User in /etc/passwd" | /usr/bin/tee -a $REPORT
    /bin/echo "______________________________________" | /usr/bin/tee -a $REPORT
    /bin/echo | /usr/bin/tee -a $REPORT
    if /usr/bin/test -r /etc/passwd
    then
      if [ "$USER" =  "`/bin/cat /etc/passwd | /bin/gawk -F: '{print $1}' | /bin/grep  $USER`" ]
      then
        /bin/echo "-- $USER -- correctly exists in /etc/passwd " | /usr/bin/tee -a $REPORT
        /bin/echo | /usr/bin/tee -a $REPORT
      else
        /bin/echo "ALERT-  The Linux user -- $USER -- is not in /etc/passwd.  You must add user $USER to the /etc/passwd file. NIS managed users are not recommended" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      fi
    else
      /bin/echo "ALERT-  User $USER is not allowed read access to the /etc/passwd file, verification of user $USER in /etc/passwd can not be performed.  Please get with your System Administrator to have them verify the presence of the user $USER in the /etc/passwd file" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
    ;;
  "")
    /bin/echo | /usr/bin/tee -a $REPORT
    /bin/echo "ALERT-  You did not enter a value" | /usr/bin/tee -a $REPORT
    exit
    ;;
  *)
    /bin/echo | /usr/bin/tee -a $REPORT
    /bin/echo "ALERT:  You have entered an invalid value - enter valid value" | /usr/bin/tee -a $REPORT
    exit
    ;;
esac

# Linux SU VERIFICATION

/bin/echo " " | /usr/bin/tee -a $REPORT
/bin/echo " " | /usr/bin/tee -a $REPORT
/bin/echo " " | /usr/bin/tee -a $REPORT
/bin/echo "Switching User (su) verification" | /usr/bin/tee -a $REPORT
/bin/echo "________________________________" | /usr/bin/tee -a $REPORT
/bin/echo " " | /usr/bin/tee -a $REPORT
/bin/echo "Are you switching user (su) from another user to become the $USER user? (Y/N):" | /usr/bin/tee -a $REPORT
read SUORACLE
/bin/echo $SUORACLE >> $REPORT
case $SUORACLE in
  "Y"|"y")
      /bin/echo " " | /usr/bin/tee -a $REPORT
      /bin/echo "WARNING: Switching User (su) is not suggested, you should login as $USER user directly when doing the install" | /usr/bin/tee -a $REPORT
      WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
      ;;
  "N"|"n")
      /bin/echo " " | /usr/bin/tee -a $REPORT
      /bin/echo "Passed switch user (su) test" | /usr/bin/tee -a $REPORT
      ;;
  *)
      /bin/echo " " | /usr/bin/tee -a $REPORT
      /bin/echo "You have entered an invalid answer, exiting InstallPrep, please try again" | /usr/bin/tee -a $REPORT
      exit
      ;;
esac

# Linux CONFIRMATION OF GROUP
/bin/echo; /bin/echo; /bin/echo | /usr/bin/tee -a $REPORT
/bin/echo "Group Verification" | /usr/bin/tee -a $REPORT
/bin/echo "_________________________" | /usr/bin/tee -a $REPORT
/bin/echo | /usr/bin/tee -a $REPORT
/bin/echo "Enter the Linux group that will be used during the installation (example: dba)?" | /usr/bin/tee -a $REPORT
read GROUP
/bin/echo $GROUP >> $REPORT
case $GROUP in
  "") 
    /bin/echo | /usr/bin/tee -a $REPORT
    /bin/echo "ALERT- You did not enter a value" | /usr/bin/tee -a $REPORT
    exit
   ;;
  *)
    if /usr/bin/test -r /etc/group
    then
      if [ "$GROUP" = "`/usr/bin/id -ng`" ]
      then
        /bin/echo "-- $GROUP -- exists in /etc/group" | /usr/bin/tee -a $REPORT
      else
        /bin/echo "ALERT-  You must create the Linux group -- $GROUP -- as the root user and add -- $USER -- to this group or select a different Linux group that already exists in /etc/group" | /usr/bin/tee -a $REPORT
        /bin/echo | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      fi
    else
      /bin/echo "ALERT-  User $USER is not allowed read access to the /etc/group file, verification of $GROUP in /etc/group can not be performed.  Please get with your System Administrator to have them verify the presence of the $GROUP in the /etc/group file" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
    ;;
esac

# Linux CONFIRMATION OF ORACLE_HOME

/bin/echo; /bin/echo; /bin/echo | /usr/bin/tee -a $REPORT
/bin/echo "Specify ORACLE_HOME" | /usr/bin/tee -a $REPORT
/bin/echo "_________________________" | /usr/bin/tee -a $REPORT
/bin/echo | /usr/bin/tee -a $REPORT
if /usr/bin/test $ORACLE_HOME
then
  /bin/echo "Presently, your ORACLE_HOME is set to $ORACLE_HOME, is this the correct location that this installation will be using? (Y/N)" | /usr/bin/tee -a $REPORT
  read CFRM
  if [ $CFRM = "Y" -o $CFRM = "y" ]
  then 
    OH=$ORACLE_HOME
    /bin/echo $OH >> $REPORT
  else
    /bin/echo "Enter Location where you will be installing Oracle (example: /u01/app/oracle/product/8.1.7)" | /usr/bin/tee -a $REPORT
    read OH
    /bin/echo $OH >> $REPORT
  fi
else
  /bin/echo "Enter Location where you will be installing Oracle (example: /u01/app/oracle/product/8.1.7)" | /usr/bin/tee -a $REPORT
  read OH
  /bin/echo $OH >> $REPORT
fi
if /usr/bin/test -z "$OH"
then
  /bin/echo | /usr/bin/tee -a $REPORT
  /bin/echo "ALERT-  You did not provide the location that Oracle will be installed.  Setting your ORACLE_HOME to No_Location_Given" | /usr/bin/tee -a $REPORT
  OH=No_Location_Given
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi

# Linux VERIFICATION OF PERMISSIONS ON INPUT ORACLE_HOME

/bin/echo " " | /usr/bin/tee -a $REPORT
/bin/echo " " | /usr/bin/tee -a $REPORT
/bin/echo " " | /usr/bin/tee -a $REPORT
/bin/echo "ORACLE_HOME permission verifications" | /usr/bin/tee -a $REPORT
/bin/echo "____________________________________" | /usr/bin/tee -a $REPORT
/bin/echo " " | /usr/bin/tee -a $REPORT

ALERTCOUNTPRIOR=$ALERTCOUNT
if [ $OH != "No_Location_Given" ]
then
  if /usr/bin/test -x $OH
  then
    if /usr/bin/test -r $OH
    then
      /bin/echo "User $USER has read permission to $OH" | /usr/bin/tee -a $REPORT
    else
      /bin/echo "ALERT: User $USER does not have read permissions for $OH" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
    if /usr/bin/test -w $OH
    then
      /bin/echo "User $USER has write permission to $OH" | /usr/bin/tee -a $REPORT
    else
      /bin/echo "ALERT: User $USER does not have write permissions for $OH" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
    if /usr/bin/test -x $OH
    then
      /bin/echo "User $USER has execute permission to $OH" | /usr/bin/tee -a $REPORT
    else
      /bin/echo "ALERT: User $USER does not have execute permissions for $OH" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
  else
    /bin/echo "ALERT: $OH does not exist, please create the $OH mount point and ensure the permissions are correctly set" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  fi
else
  /bin/echo "ORACLE_HOME permissions cannot be verified since $OH" | /usr/bin/tee -a $REPORT
fi

if [ $ALERTCOUNTPRIOR = $ALERTCOUNT ]
then
  /bin/echo "$OH has correct permissions for user $USER" | /usr/bin/tee -a $REPORT
else
  /bin/echo "ALERT: The specified ORACLE_HOME=$OH does not have correct permissions.  Please have your System Administrator correct the permissions to "rwx" for the ORACLE_HOME mount point" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi

# Linux LIST WHAT UMASK AND LINUX ENVIRONMENT VARIABLES NEED TO BE SET

/bin/echo; /bin/echo; /bin/echo | /usr/bin/tee -a $REPORT
/bin/echo "Umask Verification" | /usr/bin/tee -a $REPORT
/bin/echo "_________________________" | /usr/bin/tee -a $REPORT
/bin/echo " " | /usr/bin/tee -a $REPORT
MASK=`umask`
if [ $MASK -eq 022 ]
then
  /bin/echo "umask of $MASK is set correctly" | /usr/bin/tee -a $REPORT
  /bin/echo | /usr/bin/tee -a $REPORT
else
  /bin/echo "ALERT-  umask is set to $MASK but must be set to 022" | /usr/bin/tee -a $REPORT
  /bin/echo | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi

# Linux LIST OUT THE PATH, LD_LIBRARY_PATH, and SHLIB_PATH
/bin/echo; /bin/echo; /bin/echo | /usr/bin/tee -a $REPORT
/bin/echo "Environmental Variables (as set in user $USER's environment)" | /usr/bin/tee -a $REPORT
/bin/echo "_________________________" | /usr/bin/tee -a $REPORT
/bin/echo " " | /usr/bin/tee -a $REPORT
if /usr/bin/test $ORACLE_HOME
then
  /bin/echo "ORACLE_HOME=$ORACLE_HOME" | /usr/bin/tee -a $REPORT
fi
if /usr/bin/test $PATH
then
  /bin/echo "PATH=$PATH" | /usr/bin/tee -a $REPORT
fi
if /usr/bin/test $LD_LIBRARY_PATH
then
  /bin/echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" | /usr/bin/tee -a $REPORT
fi


/bin/echo; /bin/echo; /bin/echo | /usr/bin/tee -a $REPORT
/bin/echo ".cshrc or .profile or .bash_profile Recommended Variable Settings" | /usr/bin/tee -a $REPORT
/bin/echo "_________________________" | /usr/bin/tee -a $REPORT
/bin/echo | /usr/bin/tee -a $REPORT
SH=`/bin/cat /etc/passwd | /bin/gawk -F: '{print $1, $NF}' | /bin/grep  $USER | /bin/gawk -F/ '{print $NF}'`
/bin/echo "INFO- Your shell is $SH" | /usr/bin/tee -a $REPORT
/bin/echo | /usr/bin/tee -a $REPORT
if [ $SH = csh ]
  then
    /bin/echo "The following environment variables must be set in your .cshrc file for the user $USER user." | /usr/bin/tee -a $REPORT
    /bin/echo "setenv ORACLE_HOME $OH" | /usr/bin/tee -a $REPORT
    /bin/echo "setenv LD_LIBRARY_PATH $OH/lib"| /usr/bin/tee -a $REPORT
    /bin/echo "setenv PATH $OH/bin:/usr/bin:/bin:$PATH" | /usr/bin/tee -a $REPORT
else
    /bin/echo "The following environment variables must be set in your .profile or .bash_profile file for the $USER user." | /usr/bin/tee -a $REPORT
    /bin/echo "ORACLE_HOME=$OH" | /usr/bin/tee -a $REPORT
    /bin/echo "LD_LIBRARY_PATH=$OH/lib" | /usr/bin/tee -a $REPORT
    /bin/echo "PATH=$OH/bin:/usr/bin:/bin:$PATH" | /usr/bin/tee -a $REPORT
    /bin/echo "export \$ORACLE_HOME" | /usr/bin/tee -a $REPORT
    /bin/echo "export \$LD_LIBRARY_PATH" | /usr/bin/tee -a $REPORT
    /bin/echo "export \$PATH" | /usr/bin/tee -a $REPORT
fi

if [ "$OH" = "No_Location_Given" ]
then
  /bin/echo | /usr/bin/tee -a $REPORT
  /bin/echo "ALERT- When running this script you did not provide a location where Oracle will be installed.  Change the value of No_Location_Given to the location where Oracle will be installed in." | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi


# Linux /tmp SPACE VERIFICATION

/bin/echo; /bin/echo; /bin/echo | /usr/bin/tee -a $REPORT
/bin/echo "TMP space Verification" | /usr/bin/tee -a $REPORT
/bin/echo "_______________________" | /usr/bin/tee -a $REPORT
/bin/echo " " | /usr/bin/tee -a $REPORT
/bin/echo "FYI: The runInstaller (OUI) uses/checks for temporary space by checking first for the TEMP environmental variable, then the TMP environmental variable and lastly the actual '/tmp' mount point" | /usr/bin/tee -a $REPORT
/bin/echo " " | /usr/bin/tee -a $REPORT
/bin/echo "_______________________" | /usr/bin/tee -a $REPORT
/bin/echo " " | /usr/bin/tee -a $REPORT
TMPMT=`/bin/df -k | grep "/tmp" | /bin/gawk '{print $4}'`
if /usr/bin/test $TMPMT
then
  TMPMT=`/usr/bin/expr $TMPMT / 1024`
else
  TMPMT=0
fi
if [ `/bin/env | /bin/grep -ic "TEMP="` -ne 0 ]
then
 TEMPLOC=`/bin/env | /bin/grep "TEMP=" | /bin/gawk -F= '{print $2}'`
 if /usr/bin/test -d $TEMPLOC
 then
   TEMP=`/bin/df -k "$TEMPLOC" | /bin/gawk '{print $4}' | /bin/sed '1d'`
   TEMP=`/usr/bin/expr $TEMP / 1024`
   /bin/echo "The TEMP variable was found set in your environment and has $TEMP Mb of free space" | /usr/bin/tee -a $REPORT
   /bin/echo | /usr/bin/tee -a $REPORT
 else
   /bin/echo "ALERT- The TEMP variable was found set in your environment but is either an invalid value or is not a directory.  Please set TEMP correctly or to a valid, writable directory or unset if the InstallPrep determines you have adequate space in /tmp" | /usr/bin/tee -a $REPORT
   /bin/echo | /usr/bin/tee -a $REPORT
   ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
 fi
elif [ `/bin/env | /bin/grep -ic "TMP="` -ne 0 ]
then
  TMPLOC=`/bin/env | /bin/grep "TMP=" | /bin/gawk -F= '{print $2}'`
  if /usr/bin/test -d $TMPLOC
  then
    TMP=`/bin/df -k "$TMPLOC" | /bin/gawk '{print $4}' | /bin/sed '1d'`
    TMP=`/usr/bin/expr $TMP / 1024`
    /bin/echo "The TMP variable was found set in your environment and has $TMP Mb of free space" | /usr/bin/tee -a $REPORT
    /bin/echo | /usr/bin/tee -a $REPORT
  else
    /bin/echo "ALERT- The TMP variable was found set in your environment but is either an invalid value or is not a directory.  Please set TMP correctly or to a valid, writable directory or unset if the InstallPrep determines you have adequate space in /tmp" | /usr/bin/tee -a $REPORT
    /bin/echo | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  fi
fi
case $ORAVER in
  "805"|"806")
     if /usr/bin/test -n "$TEMP"
     then 
       if [ $TEMP -lt 40 ]
       then
         /bin/echo "ALERT- TEMP is set in the environment and has less than the required 40 Mb.  Please point the TEMP environmental variable to a mount point with at least 40 Mb of free space" | /usr/bin/tee -a $REPORT 
         /bin/echo | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TEMPLOC"
         then
           /bin/echo "TEMP has adequate space of $TEMP Mb" | /usr/bin/tee -a $REPORT
           /bin/echo | /usr/bin/tee -a $REPORT
         else
           /bin/echo "ALERT- TEMP is set in the environment; however, $TEMPLOC does not have write permissions for this user" | /usr/bin/tee -a $REPORT
           /bin/echo | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMP"
     then
       if [ $TMP -lt 40 ]
       then
         /bin/echo "ALERT- TMP is set in the environment and has less than the required 40 Mb.  Please point the TMP environmental variable to a mount point with at least 40 Mb of free space" | /usr/bin/tee -a $REPORT
         /bin/echo | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TMPLOC"
         then
           /bin/echo "TMP has adequate space of $TMP Mb" | /usr/bin/tee -a $REPORT
           /bin/echo | /usr/bin/tee -a $REPORT
         else
           /bin/echo "ALERT- TMP is set in the environment; however, $TMPLOC does not have write permissions for this user" | /usr/bin/tee -a $REPORT
           /bin/echo | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMPMT"
     then
       if [ $TMPMT -lt 40 ]
       then
         /bin/echo "ALERT- /tmp space = $TMPMT Mb, please increase /tmp to at least 40 Mb" | /usr/bin/tee -a $REPORT
         /bin/echo | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         /bin/echo "/tmp has adequate space of $TMPMT Mb" | /usr/bin/tee -a $REPORT
         /bin/echo | /usr/bin/tee -a $REPORT
       fi
     else
       /bin/echo "ALERT-  /tmp is not specified" | /usr/bin/tee -a $REPORT
       /bin/echo | /usr/bin/tee -a $REPORT
       ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
     fi
     ;;
   "815"|"816"|"817")
     if /usr/bin/test -n "$TEMP"
     then 
       if [ $TEMP -lt 75 ]
       then
         /bin/echo "ALERT- TEMP is set in the environment and has less than the required 75 Mb.  Please point the TEMP environmental variable to a mount point with at least 75 Mb of free space" | /usr/bin/tee -a $REPORT 
         /bin/echo | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TEMPLOC"
         then
           /bin/echo "TEMP has adequate space of $TEMP Mb" | /usr/bin/tee -a $REPORT
           /bin/echo | /usr/bin/tee -a $REPORT
         else
           /bin/echo "ALERT- TEMP is set in the environment; however, $TEMPLOC does not have write permissions for this user" | /usr/bin/tee -a $REPORT
           /bin/echo | tee =a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMP"
     then
       if [ $TMP -lt 75 ]
       then
         /bin/echo "ALERT- TMP is set in the environment and has less than the required 75 Mb.  Please point the TMP environmental variable to a mount point with at least 75 Mb of free space" | /usr/bin/tee -a $REPORT
         /bin/echo | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TMPLOC"
         then
           /bin/echo "TMP has adequate space of $TMP Mb" | /usr/bin/tee -a $REPORT
           /bin/echo | /usr/bin/tee -a $REPORT
         else
           /bin/echo "ALERT- TMP is set in the environment; however, $TMPLOC does not have write permissions for this user" | /usr/bin/tee -a $REPORT
           /bin/echo | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMPMT"
     then
       if [ $TMPMT -lt 75 ]
       then
         /bin/echo "ALERT- /tmp space = $TMPMT Mb, please increase /tmp to at least 75 Mb" | /usr/bin/tee -a $REPORT
         /bin/echo | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         /bin/echo "/tmp has adequate space of $TMPMT Mb" | /usr/bin/tee -a $REPORT
         /bin/echo | /usr/bin/tee -a $REPORT
       fi
     else
       /bin/echo "ALERT-  /tmp is not specified" | /usr/bin/tee -a $REPORT
       /bin/echo | /usr/bin/tee -a $REPORT
       ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
     fi
     ;;
   "901"|"920")
     if /usr/bin/test -n "$TEMP"
     then 
       if [ $TEMP -lt 400 ]
       then
         /bin/echo "ALERT- TEMP is set in the environment and has less than the required 400 Mb.  Please point the TEMP environmental variable to a mount point with at least 400 Mb of free space" | /usr/bin/tee -a $REPORT 
         /bin/echo | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TEMPLOC"
         then
           /bin/echo "TEMP has adequate space of $TEMP Mb" | /usr/bin/tee -a $REPORT
           /bin/echo | /usr/bin/tee -a $REPORT
         else
           /bin/echo "ALERT- TEMP is set in the environment; however, $TEMPLOC does not have write permissions for this user" | /usr/bin/tee -a $REPORT
           /bin/echo | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMP"
     then
       if [ $TMP -lt 400 ]
       then
         /bin/echo "ALERT- TMP is set in the environment and has less than the required 400 Mb.  Please point the TMP environmental variable to a mount point with at least 400 Mb of free space" | /usr/bin/tee -a $REPORT
         /bin/echo | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TMPLOC"
         then
           /bin/echo "TMP has adequate space of $TMP Mb" | /usr/bin/tee -a $REPORT
           /bin/echo | /usr/bin/tee -a $REPORT
         else
           /bin/echo "ALERT- TMP is set in the environment; however, $TMPLOC does not have write permissions for this user" | /usr/bin/tee -a $REPORT
           /bin/echo | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMPMT"
     then
       if [ $TMPMT -lt 400 ]
       then
         /bin/echo "ALERT- /tmp space = $TMPMT Mb, please increase /tmp to at least 400 Mb" | /usr/bin/tee -a $REPORT
         /bin/echo | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         /bin/echo "/tmp has adequate space of $TMPMT Mb" | /usr/bin/tee -a $REPORT
         /bin/echo | /usr/bin/tee -a $REPORT
       fi
     else
       /bin/echo "ALERT-  /tmp is not specified" | /usr/bin/tee -a $REPORT
       /bin/echo | /usr/bin/tee -a $REPORT
       ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
     fi
     ;;
    *)
     /bin/echo ""
     ;;
esac


# Linux SWAP SPACE VERIFICATION

/bin/echo; /bin/echo; /bin/echo | /usr/bin/tee -a $REPORT
/bin/echo "Swap Space Verification" | /usr/bin/tee -a $REPORT
/bin/echo "_________________________" | /usr/bin/tee -a $REPORT
/bin/echo | /usr/bin/tee -a $REPORT
if /usr/bin/test -x /usr/bin/free
then
  SWAP=`/usr/bin/free | /bin/grep Swap | /bin/gawk '{print $2}'`
  SWAP=`/usr/bin/expr $SWAP / 1000`
  if /usr/bin/test -z "$SWAP"
  then 
    /bin/echo "ALERT- SWAP has not been setup or specified" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /bin/echo "Swap is $SWAP Mb" | /usr/bin/tee -a $REPORT
    /bin/echo | /usr/bin/tee -a $REPORT
  fi
else
  /bin/echo "ALERT- User $USER does not have execute permission to determine amount of swap, please have your System Administator allow execute to user $USER, or have them run '/usr/bin/free' " | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi


# Linux MEMORY VERIFICATION

/bin/echo; /bin/echo; /bin/echo | /usr/bin/tee -a $REPORT
/bin/echo "Memory Verification" | /usr/bin/tee -a $REPORT
/bin/echo "___________________" | /usr/bin/tee -a $REPORT
/bin/echo | /usr/bin/tee -a $REPORT
MEM=`/usr/bin/free | /bin/grep Mem | /bin/gawk '{print $2}'`
MEM=`/usr/bin/expr $MEM / 1024` 
TWOM=`/usr/bin/expr $MEM \* 2`
THREM=`/usr/bin/expr $MEM \* 3`

case $ORAVER in
  "805"|"806")
    if [ $MEM -lt 32 ]
    then
      /bin/echo "ALERT-  You have $MEM Mb of memory. This is not enough to install Oracle.  You must have at least 32Mb" | /usr/bin/tee -a $REPORT
      /bin/echo " " | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /bin/echo "$MEM Mb of memory is adequate to install $ORAVER" | /usr/bin/tee -a $REPORT
      /bin/echo | /usr/bin/tee -a $REPORT
    fi
    ;;
  "815"|"816"|"817")
    if [ $MEM -lt 128 ]
    then
      /bin/echo "ALERT-  You have $MEM Mb of memory. This is not enough to install Oracle.  You must have at least 128Mb" | /usr/bin/tee -a $REPORT
      /bin/echo " " | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /bin/echo "$MEM Mb of memory is adequate to install $ORAVER" | /usr/bin/tee -a $REPORT
      /bin/echo | /usr/bin/tee -a $REPORT
    fi
    ;;
  "901"|"920")
    if [ $MEM -lt 512 ]
    then
      /bin/echo "ALERT-  You have $MEM Mb of memory. This is not enough to install Oracle.  You must have at least 512Mb" | /usr/bin/tee -a $REPORT
      /bin/echo " " | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /bin/echo "$MEM Mb of memory is adequate to install Oracle $ORAVER" | /usr/bin/tee -a $REPORT
      /bin/echo " " | /usr/bin/tee -a $REPORT
    fi
    ;;
  *)
    /bin/echo ""
    ;;
esac

# Linux SWAP TO MEMORY VERIFICATION

/bin/echo; /bin/echo; /bin/echo | /usr/bin/tee -a $REPORT
/bin/echo "Swap to Memory Verification" | /usr/bin/tee -a $REPORT
/bin/echo "___________________" | /usr/bin/tee -a $REPORT
/bin/echo | /usr/bin/tee -a $REPORT

if /usr/bin/test $SWAP 
then
  case $ORAVER in
  "920")
    if [ $SWAP -lt 1000 ]
    then
      /bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least 1Gb." | /usr/bin/tee -a $REPORT
      /bin/echo " " | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $SWAP -lt $MEM ]
    then
      /bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $MEM Mb since you have $MEM Mb of RAM." | /usr/bin/tee -a $REPORT
      /bin/echo " " | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb." | /usr/bin/tee -a $REPORT
      /bin/echo " " | /usr/bin/tee -a $REPORT
    fi
    ;;
  "901")
    if [ $SWAP -lt $MEM ]
    then
      /bin/echo "ALERT-  You need to increase Swap from $SWAP Mb to $MEM Mb to have the correct ratio to Memory" | /usr/bin/tee -a $REPORT
      /bin/echo " " | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb." | /usr/bin/tee -a $REPORT
      /bin/echo " " | /usr/bin/tee -a $REPORT
    fi
    ;;
  *)
    if [ $MEM -lt 512 ]
    then
      if [ $SWAP -lt $THREM ]
      then
        /bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $THREM Mb since you have $MEM Mb of RAM." | /usr/bin/tee -a $REPORT
        /bin/echo " " | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb" | /usr/bin/tee -a $REPORT
        /bin/echo " " | /usr/bin/tee -a $REPORT
      fi
    elif [ $MEM -ge 512 -a $MEM -lt 1024 ]
    then
      if [ $SWAP -lt $TWOM ]
      then
        /bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $TWOM Mb since you have $MEM Mb of RAM." | /usr/bin/tee -a $REPORT
        /bin/echo " " | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb." | /usr/bin/tee -a $REPORT
        /bin/echo " " | /usr/bin/tee -a $REPORT
      fi
    elif [ $MEM -ge 1024 ]
    then
      if [ $SWAP -lt $MEM ]
      then
        /bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $MEM Mb since you have $MEM Mb of RAM." | /usr/bin/tee -a $REPORT
        /bin/echo " " | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb." | /usr/bin/tee -a $REPORT
        /bin/echo " " | /usr/bin/tee -a $REPORT
      fi
    fi
    ;;
  esac
else
  /bin/echo "ALERT- A Swap to Memory ratio cannot be determined because swap has not been setup or user $USER does not have execute permission to determine swap" | /usr/bin/tee -a $REPORT
  /bin/echo " " | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi


# Linux KERNEL PARAMETER VERIFICATION

/bin/echo; /bin/echo; /bin/echo | /usr/bin/tee -a $REPORT
/bin/echo "Linux Kernel Verification" | /usr/bin/tee -a $REPORT
/bin/echo "________________________" | /usr/bin/tee -a $REPORT
/bin/echo " " | /usr/bin/tee -a $REPORT
/bin/echo "Checking Required Kernel Parameters for minimum values needed."  | /usr/bin/tee -a $REPORT
/bin/echo "Note-  Changes to the Linux Kernel must be performed by the root user." | /usr/bin/tee -a $REPORT
/bin/echo "A system reboot is required for the kernel changes to take affect." | /usr/bin/tee -a $REPORT
/bin/echo | /usr/bin/tee -a $REPORT

case $ORAVER in
  "805"|"806")
    SHMMAX=`/bin/cat /proc/sys/kernel/shmmax`
    if /usr/bin/test -z "$SHMMAX"
    then
      /bin/echo "ALERT-  SHMMAX has not been defined  and needs to be set to 8388608" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $SHMMAX -lt 8388608 ]
    then
      /bin/echo "ALERT-  Increase the kernel parameter SHMMAX to 8388608 from present setting of $SHMMAX" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
        /bin/echo "SHMMAX set to $SHMMAX is adequate" | /usr/bin/tee -a $REPORT
    fi
    SHMSEG=`/usr/bin/ipcs -lm | /bin/grep "max seg size" | /bin/gawk '{print $6}'`
    if /usr/bin/test -z "$SHMSEG"
    then
      /bin/echo "ALERT- SHMSEG has not been defined and needs to be set to 10" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $SHMSEG -lt 10 ]
    then
      /bin/echo "ALERT-  Increase the kernel parameter SHMSEG to at least 10 from present setting of $SHMSEG" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /bin/echo "SHMSEG set to $SHMSEG is adequate" | /usr/bin/tee -a $REPORT
    fi
    ;;
  "815"|"816"|"817")
    SHMMAX=`/bin/cat /proc/sys/kernel/shmmax`
    if /usr/bin/test -z "$SHMMAX"
    then
      /bin/echo "ALERT-  SHMMAX has not been defined and needs to be set to 67108864" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $SHMMAX -lt 67108864 ]
    then
      /bin/echo "ALERT-  Increase the kernel parameter SHMMAX to 67108864 from present setting of $SHMMAX" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /bin/echo "SHMMAX set to $SHMMAX is adequate" | /usr/bin/tee -a $REPORT
    fi
    SHMSEG=`/usr/bin/ipcs -lm | /bin/grep "max seg size" | /bin/gawk '{print $6}'`
    if /usr/bin/test -z "$SHMSEG"
    then
      /bin/echo "ALERT- SHMSEG has not been define and needs to be set to 10" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $SHMSEG -lt 10 ]
    then
      /bin/echo "ALERT-  Increase the kernel parameter SHMSEG to at least 10 from present setting of $SHMSEG" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /bin/echo "SHMSEG set to $SHMSEG is adequate" | /usr/bin/tee -a $REPORT
    fi
    ;;
  "901"|"920")
    SHMMAX=`/bin/cat /proc/sys/kernel/shmmax`
    if /usr/bin/test -z "$SHMMAX"
    then
      /bin/echo "ALERT-  SHMMAX has not been defined and needs to be set to 2147483648" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $SHMMAX -lt 2147483648 ]
    then
      /bin/echo "ALERT-  Increase the kernel parameter SHMMAX to 2147483648 from present setting of $SHMMAX" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /bin/echo "SHMMAX set to $SHMMAX is adequate" | /usr/bin/tee -a $REPORT
    fi
    SHMSEG=`/usr/bin/ipcs -lm | /bin/grep "max seg size" | /bin/gawk '{print $6}'`
    if /usr/bin/test -z "$SHMSEG"
    then
      /bin/echo "ALERT- SHMSEG has not been defined and needs to be set to 4096" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $SHMSEG -lt 4096 ]
    then
      /bin/echo "ALERT-  Increase the kernel parameter SHMSEG to at least 4096 from present setting of $SHMSEG" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /bin/echo "SHMSEG set to $SHMSEG is adequate" | /usr/bin/tee -a $REPORT
    fi
    ;;
  *)
    /bin/echo ""
    ;;
esac

SHMMIN=`/usr/bin/ipcs -lm | /bin/grep "min seg size" | /bin/gawk '{print $6}'`
if /usr/bin/test -z "$SHMMIN"
then
  /bin/echo "ALERT- SHMMIN has not been defined and needs to be set to 1 or more" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $SHMMIN -lt 1 ]
then
  /bin/echo "ALERT- Increase the kernel parameter SHMMIN to 1 or more" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /bin/echo "SHMMIN set to $SHMMIN is adequate" | /usr/bin/tee -a $REPORT
fi

SHMMNI=`/bin/cat /proc/sys/kernel/shmmni`
if /usr/bin/test -z "$SHMMNI"
then
  /bin/echo "ALERT- SHMMNI has not been defined and needs to be set to 100 or more" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $SHMMNI -lt 100 ]
then
  /bin/echo "ALERT-  Increase the kernel parameter SHMMNI to at least 100 from present setting of $SHMMNI" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /bin/echo "SHMMNI set to $SHMMNI is adequate" | /usr/bin/tee -a $REPORT
fi

SEMMNI=`/bin/cat /proc/sys/kernel/sem | /bin/awk '{print $4}'`
if /usr/bin/test -z "$SEMMNI"
then
  /bin/echo "ALERT- SEMMNI has not been defined and needs to be set to 100" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $SEMMNI -lt 100 ]
then
  /bin/echo "ALERT- Increase the kernel parameter SEMMNI to at least 100 from present setting of $SEMMNI" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /bin/echo "SEMMNI set to $SEMMNI is adequate" | /usr/bin/tee -a $REPORT
fi

SEMMSL=`/bin/cat /proc/sys/kernel/sem | /bin/awk '{print $1}'`
if /usr/bin/test -z "$SEMMSL"
then
  /bin/echo "ALERT- SEMMSL has not been defined and needs to be set to 100" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $SEMMSL -lt 100 ]
then
  /bin/echo "ALERT-  Increase the kernel parameter SEMMSL to at least 100 from present setting of $SEMMSL" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /bin/echo "SEMMSL set to $SEMMSL is adequate" | /usr/bin/tee -a $REPORT
fi

SEMMNS=`/bin/cat /proc/sys/kernel/sem | /bin/awk '{print $2}'`
if /usr/bin/test -z "$SEMMNS"
then
  /bin/echo "ALERT- SEMMNS has not been defined and needs to be set to 256" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $SEMMNS -lt 256 ]
then
  /bin/echo "ALERT-  Increase the kernel parameter SEMMNS to at least 256 from present setting of $SEMMNS" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /bin/echo "SEMMNS set to $SEMMNS is adequate" | /usr/bin/tee -a $REPORT
fi

SEMOPM=`/bin/cat /proc/sys/kernel/sem | /bin/awk '{print $3}'`
if /usr/bin/test -z "$SEMOPM"
then
  /bin/echo "ALERT- SEMOPM has not been defined and needs to be set to 100" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $SEMOPM -lt 100 ]
then
  /bin/echo "ALERT- Increase the kernel parameter SEMOPM to at least 100 from present setting of $SEMOPM" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /bin/echo "SEMOPM set to $SEMOPM is adequate" | /usr/bin/tee -a $REPORT
fi

SEMVMX=`/usr/bin/ipcs -ls | /bin/grep "semaphore max value" | /bin/gawk '{print $5}'`
if /usr/bin/test -z "$SEMVMX"
then
  /bin/echo "ALERT- SEMVMX has not been defined and needs to be set to 32767" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $SEMVMX -lt 32767 ]
then
  /bin/echo "ALERT-  Increase the kernel parameter SEMVMX to at least 32767 from present setting of $SEMVMX" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /bin/echo "SEMVMX set to $SEMVMX is adequate" | /usr/bin/tee -a $REPORT
fi

# Linux ASSEMBLY TOOL VERIFICATION

/bin/echo; /bin/echo; /bin/echo | /usr/bin/tee -a $REPORT
/bin/echo "Assembly Tool Verification" | /usr/bin/tee -a $REPORT
/bin/echo "________________________" | /usr/bin/tee -a $REPORT
/bin/echo " " | /usr/bin/tee -a $REPORT

arvalue=`/usr/bin/which ar`
if [ "$arvalue" != "/usr/bin/ar" ]
then
  /bin/echo "WARNING-  ar not found in /usr/bin directory but was found in '$arvalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /bin/echo "ar - found correctly in /usr/bin" | /usr/bin/tee -a $REPORT
fi

ldvalue=`/usr/bin/which ld`
if [ "$ldvalue" != "/usr/bin/ld" ]
then
  /bin/echo "WARNING-  ld not found in /usr/bin directory but was found in '$ldvalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /bin/echo "ld - found correctly in /usr/bin" | /usr/bin/tee -a $REPORT
fi

nmvalue=`/usr/bin/which nm`
if [ "$nmvalue" != "/usr/bin/nm" ]
then
  /bin/echo "WARNING-  nm not found in /usr/bin directory but was found in '$nmvalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /bin/echo "nm - found correctly in /usr/bin" | /usr/bin/tee -a $REPORT
fi

makevalue=`/usr/bin/which make`
if [ "$makevalue" != "/usr/bin/make" ]
then
  /bin/echo "WARNING-  make not found in /usr/bin directory but was found in '$makevalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /bin/echo "make - found correctly in /usr/bin" | /usr/bin/tee -a $REPORT
fi

# Linux CERTIFICATION VERIFICATION

/bin/echo; /bin/echo; /bin/echo | /usr/bin/tee -a $REPORT
/bin/echo "Certification of Oracle and OS Version Verification" | /usr/bin/tee -a $REPORT
/bin/echo "________________________________________________________" | /usr/bin/tee -a $REPORT
/bin/echo | /usr/bin/tee -a $REPORT
kernelversub1=`/bin/uname -r | /bin/sed 's/[.-]/ /g' | /bin/sed 's/[a-z,A-Z]//g' | /bin/awk '{print $1}'`
kernelversub2=`/bin/uname -r | /bin/sed 's/[.-]/ /g' | /bin/sed 's/[a-z,A-Z]//g' | /bin/awk '{print $2}'`
kernelversub3=`/bin/uname -r | /bin/sed 's/[.-]/ /g' | /bin/sed 's/[a-z,A-Z]//g' | /bin/awk '{print $3}'`
kernelversub4=`/bin/uname -r | /bin/sed 's/[.-]/ /g' | /bin/sed 's/[a-z,A-Z]//g' | /bin/awk '{print $4}'`
kernelversub5=`/bin/uname -r | /bin/sed 's/[.-]/ /g' | /bin/sed 's/[a-z,A-Z]//g' | /bin/awk '{print $5}'`

if /usr/bin/test -f /etc/redhat-release 
then
  linuxtype=1
  susever=null
  if [ `/bin/cat /etc/redhat-release | /bin/grep -i pensacola | /usr/bin/wc -l` -ge 1 ]
  then
    redhatver=AS2.1
  elif [ `/bin/cat /etc/redhat-release | /bin/grep -i taroon | /usr/bin/wc -l` -ge 1 ]
  then
    redhatver=EL3
  elif [ `/bin/cat /etc/redhat-release | /bin/grep -i nahant | /usr/bin/wc -l` -ge 1 ]
  then
    redhatver=EL4
  elif [ `/bin/cat /etc/redhat-release | /bin/grep -i derry | /usr/bin/wc -l` -ge 1 ]
  then
    redhatver=AS2.1ia64
  elif [ `/bin/cat /etc/redhat-release | /bin/grep -i destin | /usr/bin/wc -l` -ge 1 ]
  then
    redhatver=ASDE2.1
  elif [ `/bin/cat /etc/redhat-release | /bin/grep -i Panama | /usr/bin/wc -l` -ge 1 ]
  then
    redhatver=ES2.1
  elif [ `/bin/cat /etc/redhat-release | /bin/grep -i shrike | /usr/bin/wc -l` -ge 1 ]
  then
    redhatver=9.0
  elif [ `/bin/cat /etc/redhat-release | /bin/grep -i psyche | /usr/bin/wc -l` -ge 1 ]
  then
    redhatver=8.0
  elif [ `/bin/cat /etc/redhat-release | /bin/grep -i valhalla | /usr/bin/wc -l` -ge 1 ]
  then
    redhatver=7.3
  elif [ `/bin/cat /etc/redhat-release | /bin/grep -i enigma | /usr/bin/wc -l` -ge 1 ]
  then
    redhatver=7.2
  elif [ `/bin/cat /etc/redhat-release | /bin/grep -i seawolf | /usr/bin/wc -l` -ge 1 ]
  then
    redhatver=7.1
  elif [ `/bin/cat /etc/redhat-release | /bin/grep -i guinness | /usr/bin/wc -l` -ge 1 ]
  then
    redhatver=7.0
  elif [ `/bin/cat /etc/redhat-release | /bin/grep -i zoot | /usr/bin/wc -l` -ge 1 ]
  then
    redhatver=6.2
  else
    redhatver=unknown
  fi
elif /usr/bin/test -f /etc/SuSE-release 
then
  linuxtype=2
  redhatver=null
  if [ `/bin/cat /etc/SuSE-release | /bin/grep -i SLES | /usr/bin/wc -l` -ge 1 ]
  then
    susever=`/bin/cat /etc/SuSE-release | /bin/grep -i SLES | /bin/awk '{print $2}'`
  else
    susever=`/bin/cat /etc/SuSE-release | /bin/sed 1d | /bin/awk '{print $3}'`
  fi
else
  linuxtype=3
  susever=null
  redhatver=null
fi

if [ $ORAVER = "920" ]
then 
  if [ $redhatver = "AS2.1" -a $kernelversub1 -ge "2" -a $kernelversub2 -ge "4" -a $kernelversub3 -ge "9" -a $kernelversub4 -ge "34" ]
  then
    /bin/echo "Red Hat $redhatver kernel $kernelversub1.$kernelversub2.$kernelversub3 is certified with 920 RDBMS"
  elif [ $redhatver = "ES2.1" -a $kernelversub1 -ge "2" -a $kernelversub2 -ge "4" -a $kernelversub3 -ge "9" -a $kernelversub4 -ge "34" ]
  then
    /bin/echo "Red Hat $redhatver kernel $kernelversub1.$kernelversub2.$kernelversub3 is certified with 920 RDBMS"
  elif [ $redhatver = "EL3" -a $kernelversub1 -ge "2" -a $kernelversub2 -ge "4" -a $kernelversub3 -ge "21" -a $kernelversub4 -ge "15" ]
  then
    /bin/echo "Red Hat $redhatver kernel $kernelversub1.$kernelversub2.$kernelversub3 is certified with 920 RDBMS"
  elif [ $redhatver = "EL4" ]
  then
    /bin/echo "Red Hat $redhatver is certified with 920 RDBMS"
  elif [ $susever = "SLES-8" -a $kernelversub1 -ge "2" -a $kernelversub2 -ge "4" -a $kernelversub3 -ge "21" -a $kernelversub4 -ge "138" ]
  then 
    /bin/echo "SuSE $susever kernel $kernelversub1.$kernelversub2.$kernelversub3 is certified with 920 RDBMS"
  elif [ $susever = "SLES-9" -a $kernelversub1 -ge "2" -a $kernelversub2 -ge "6" -a $kernelversub3 -ge "5" -a $kernelversub4 -ge "7" -a $kernelversub5 -ge "97"]
  then 
    /bin/echo "SuSE $susever kernel $kernelversub1.$kernelversub2.$kernelversub3 is certified with 920 RDBMS"
  else
    case $linuxtype in
    1)
      /bin/echo "!!SHOWSTOPPER!! Red Hat $redhatver kernel $kernelversub1.$kernelversub2.$kernelversub3 is not certified with Oracle $ORAVER, you need to install Red Hat Advanced Server 2.1 kernel 2.4.9 or later" | /usr/bin/tee -a $REPORT
      SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
      ;;
    2)
      /bin/echo "!!SHOWSTOPPER!! SuSE $susever kernel $kernelversub1.$kernelversub2.$kernelversub3 is not certified with Oracle $ORAVER, you need to install SuSE SLES8 kernel 2.4.21 or later" | /usr/bin/tee -a $REPORT
      SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
      ;;
    *)
      /bin/echo "!!SHOWSTOPPER!!  Your version of Linux is not certified with Oracle $ORAVER, please consult Metalink - Certify & Availability or Metalink Note:169706.1" | /usr/bin/tee -a $REPORT
      SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
      ;;
    esac
  fi
else
  /bin/echo "INFO- Certification verification of Oracle $ORAVER and Linux is not performed, please consult Metalink - Certify & Availability to see if your version of Linux is certified with Oracle $ORAVER or Metalink Note:169706.1" | /usr/bin/tee -a $REPORT
fi
;;

"SUNOS"|"SunOS")

OSVER=`/usr/bin/uname -r`
OSBIT=`/usr/bin/isalist | /usr/bin/awk '{print substr($1,7,1)}' | /usr/bin/sed 's/9/64/' | /usr/bin/sed 's/8/32/'`

# Sun START ECHO OF SCRIPT TO OUTPUT FILE

`/usr/bin/touch $REPORT; /usr/bin/chmod 777 $REPORT`
/usr/bin/echo "\nOutput from the Oracle InstallPrep Script run on $BOXNAME on `date`.\n \n \n" > $REPORT
/usr/bin/echo "To successfully install the Oracle Database Software you must resolve" >> $REPORT
/usr/bin/echo "each item listed in this Report. \n \n" >> $REPORT
/usr/bin/echo "\n\n\nInstallPrep now running on your $OS $OSBIT bit box....." | /usr/bin/tee -a $REPORT


# Sun ORACLE VERSION INPUT

/usr/bin/echo "\n\n\nOracle Version Input" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_______________________\n" | /usr/bin/tee -a $REPORT
/usr/bin/echo "What version of Oracle are you installing?\n (valid values:805,806,815,816,817,901,920):" | /usr/bin/tee -a $REPORT
read ORAVER
/usr/bin/echo $ORAVER >> $REPORT
case $ORAVER in
  "805"|"806"|"815"|"816"|"817"|"901"|"920")
          ;;
  "")
    /usr/bin/echo "\nALERT-  You did not enter a value" | /usr/bin/tee -a $REPORT 
    exit
    ;;
  *)
    /usr/bin/echo "\nALERT-  You have entered an invalid version - enter valid value" | /usr/bin/tee -a $REPORT
    exit
    ;;
esac

# Sun ORACLE BIT SIZE INPUT

/usr/bin/echo "\n\n\nOracle Bit Size Input" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT

/usr/bin/echo "What bit version of Oracle are you installing (32 or 64)?" | /usr/bin/tee -a $REPORT
read ORABIT
/usr/bin/echo $ORABIT >> $REPORT
case $ORABIT in
  "32"|"64")
     ;;
  "")
    /usr/bin/echo "\nALERT-  You did not enter a value" | /usr/bin/tee -a $REPORT
    exit
    ;;
  *)
    /usr/bin/echo "\nALERT:  You have entered an invalid version - enter valid value" | /usr/bin/tee -a $REPORT
    exit
    ;;
esac

# Sun CORRECT USER VERIFICATION

/usr/bin/echo "\n\n\nUser Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
USER=`/usr/bin/who -m | /usr/bin/awk '{print $1}'`
if [ $USER = "root" ]
then
  /usr/bin/echo "\nALERT-  You are logged in as user -- $USER --.  Please log in as the user that will be installing the Oracle Database Software. This user should not be root." | /usr/bin/tee -a $REPORT
  /usr/bin/echo "Exiting" | /usr/bin/tee -a $REPORT
  exit;
else
  /usr/bin/echo "\nYou are currently logged on as user -- $USER -- \n" | /usr/bin/tee -a $REPORT
fi

# Sun CONFIRMATION OF USER

/usr/bin/echo "Is user $USER the unix user that will be installing Oracle Software?  (y or n)" | /usr/bin/tee -a $REPORT
read answer
/usr/bin/echo $answer >> $REPORT
case $answer in
  "n"|"N")
    /usr/bin/echo "\nALERT-  Please log in as the user that will be installing Oracle.  Then rerun this script \n" | /usr/bin/tee -a $REPORT
    exit
    ;;
  "y"|"Y")
    /usr/bin/echo "\n \n \n Verifying User in /etc/passwd" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "______________________________________\n" | /usr/bin/tee -a $REPORT
    if /usr/bin/test -r /etc/passwd
    then
      if [ "$USER" =  "`/usr/bin/cat /etc/passwd | /usr/bin/awk -F: '{print $1}' | /usr/bin/grep -w $USER`" ]
      then
        /usr/bin/echo "-- $USER -- correctly exists in /etc/passwd \n" | /usr/bin/tee -a $REPORT
      else
        /usr/bin/echo "ALERT-  The unix user -- $USER -- is not in /etc/passwd.  You must add user $USER to the /etc/passwd file. NIS managed users are not recommended" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      fi
    else
      /usr/bin/echo " ALERT-  User $USER is not allowed read access to the /etc/passwd file, verification of user $USER in /etc/passwd can not be performed.  Please get with your System Administrator to have them verify the presence of the user $USER in the /etc/passwd file" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
    ;;
  "")
    /usr/bin/echo "\nALERT-  You did not enter a value" | /usr/bin/tee -a $REPORT
    exit
    ;;
  *)
    /usr/bin/echo "\nALERT:  You have entered an invalid value - enter valid value" | /usr/bin/tee -a $REPORT
    exit
    ;;
esac

# Sun SU VERIFICATION

/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo "Switching User (su) verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________________" | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo "Are you switching user (su) from another user to become the $USER user? (Y/N):" | /usr/bin/tee -a $REPORT
read SUORACLE
/usr/bin/echo $SUORACLE >> $REPORT
case $SUORACLE in
  "Y"|"y")
      /usr/bin/echo " " | /usr/bin/tee -a $REPORT
      /usr/bin/echo "WARNING: Switching User (su) is not suggested, you should login as $USER user directly when doing the install" | /usr/bin/tee -a $REPORT
      WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
      ;;
  "N"|"n")
      /usr/bin/echo " " | /usr/bin/tee -a $REPORT
      /usr/bin/echo "Passed switch user (su) test" | /usr/bin/tee -a $REPORT
      ;;
  *)
      /usr/bin/echo " " | /usr/bin/tee -a $REPORT
      /usr/bin/echo "You have entered an invalid answer, exiting InstallPrep, please try again" | /usr/bin/tee -a $REPORT
      exit
      ;;
esac

# Sun CONFIRMATION OF GROUP

/usr/bin/echo "\n\n\nGroup Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
/usr/bin/echo "Enter the unix group that will be used during the installation (example: dba)?" | /usr/bin/tee -a $REPORT
read GROUP
/usr/bin/echo $GROUP >> $REPORT
case $GROUP in
  "") 
    /usr/bin/echo "\nALERT- You did not enter a value" | /usr/bin/tee -a $REPORT
    exit
   ;;
  *)
    if /usr/bin/test -r /etc/group
    then
      if [ "$GROUP" = "`/usr/bin/cat /etc/group | /usr/bin/awk -F: '{print $1}' | /usr/bin/grep -w $GROUP`" ]
      then
        /usr/bin/echo "-- $GROUP -- exists in /etc/group" | /usr/bin/tee -a $REPORT
      else
        /usr/bin/echo "ALERT-  You must create the unix group -- $GROUP -- as the root user and add -- $USER -- to this group or select a different unix group that already exists in /etc/group\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      fi
    else
      /usr/bin/echo " ALERT-  User $USER is not allowed read access to the /etc/group file, verification of $GROUP in /etc/group can not be performed.  Please get with your System Administrator to have them verify the presence of the $GROUP in the /etc/group file" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
    ;;
esac

# Sun CONFIRMATION OF ORACLE_HOME

/usr/bin/echo "\n\n\nSpecify ORACLE_HOME" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
if /usr/bin/test $ORACLE_HOME
then
  /usr/bin/echo "Presently, your ORACLE_HOME is set to $ORACLE_HOME, is this the correct location that this installation will be using? (Y/N)" | /usr/bin/tee -a $REPORT
  read CFRM
  if [ $CFRM = "Y" -o $CFRM = "y" ]
  then 
    OH=$ORACLE_HOME
    /usr/bin/echo $OH >> $REPORT
  else
    /usr/bin/echo "Enter Location where you will be installing Oracle (example: /u01/app/oracle/product/8.1.7)" | /usr/bin/tee -a $REPORT
    read OH
    /usr/bin/echo $OH >> $REPORT
  fi
else
  /usr/bin/echo "Enter Location where you will be installing Oracle (example: /u01/app/oracle/product/8.1.7)" | /usr/bin/tee -a $REPORT
  read OH
  /usr/bin/echo $OH >> $REPORT
fi
if /usr/bin/test -z "$OH"
then
  /usr/bin/echo "\nALERT-  You did not provide the location that Oracle will be installed.  Setting your ORACLE_HOME to No_Location_Given" | /usr/bin/tee -a $REPORT
  OH=No_Location_Given
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi

# Sun VERIFICATION OF PERMISSIONS ON INPUT ORACLE_HOME

/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo "ORACLE_HOME permission verifications" | /usr/bin/tee -a $REPORT
/usr/bin/echo "____________________________________" | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT

ALERTCOUNTPRIOR=$ALERTCOUNT
if [ $OH != "No_Location_Given" ]
then
  if /usr/bin/test -x $OH
  then
    if /usr/bin/test -r $OH
    then
      /usr/bin/echo "User $USER has read permission to $OH" | /usr/bin/tee -a $REPORT
    else
      /usr/bin/echo "ALERT: User $USER does not have read permissions for $OH" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
    if /usr/bin/test -w $OH
    then
      /usr/bin/echo "User $USER has write permission to $OH" | /usr/bin/tee -a $REPORT
    else
      /usr/bin/echo "ALERT: User $USER does not have write permissions for $OH" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
    if /usr/bin/test -x $OH
    then
      /usr/bin/echo "User $USER has execute permission to $OH" | /usr/bin/tee -a $REPORT
    else
      /usr/bin/echo "ALERT: User $USER does not have execute permissions for $OH" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
  else
    /usr/bin/echo "ALERT: $OH does not exist, please create the $OH mount point and ensure the permissions are correctly set" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  fi
else
  /usr/bin/echo "ORACLE_HOME permissions cannot be verified since $OH" | /usr/bin/tee -a $REPORT
fi

if [ $ALERTCOUNTPRIOR = $ALERTCOUNT ]
then
  /usr/bin/echo "$OH has correct permissions for user $USER" | /usr/bin/tee -a $REPORT
else
  /usr/bin/echo "ALERT: The specified ORACLE_HOME=$OH does not have correct permissions.  Please have your System Administrator correct the permissions to "rwx" for the ORACLE_HOME mount point" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi

# Sun LIST WHAT UMASK AND UNIX ENVIRONMENT VARIABLES NEED TO BE SET

/usr/bin/echo "\n\n\nUmask Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
MASK=`/usr/bin/umask`
if [ $MASK -eq 022 ]
then
  /usr/bin/echo "umask of $MASK is set correctly \n" | /usr/bin/tee -a $REPORT
else
  /usr/bin/echo "ALERT-  umask is set to $MASK but must be set to 022 \n" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi

# Sun LIST OUT THE PATH, LD_LIBRARY_PATH, and SHLIB_PATH

/usr/bin/echo "\n\n\nEnvironmental Variables (as set in user $USER's environment)" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT

if [ $ORAVER != 920 ] || [ $ORAVER = 920 -a $ORABIT = 32 ]
then
  if /usr/bin/test $ORACLE_HOME
  then
    /usr/bin/echo "ORACLE_HOME=$ORACLE_HOME" | /usr/bin/tee -a $REPORT
  fi
  if /usr/bin/test $PATH
  then
    /usr/bin/echo "PATH=$PATH" | /usr/bin/tee -a $REPORT
  fi
  if /usr/bin/test $LD_LIBRARY_PATH
  then
    /usr/bin/echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" | /usr/bin/tee -a $REPORT
  fi
elif [ $ORAVER = 920 -a $ORABIT = 64 ]
then
  if /usr/bin/test $ORACLE_HOME
  then
    /usr/bin/echo "ORACLE_HOME=$ORACLE_HOME" | /usr/bin/tee -a $REPORT
  fi
  if /usr/bin/test $PATH
  then
    /usr/bin/echo "PATH=$PATH" | /usr/bin/tee -a $REPORT
  fi
  if /usr/bin/test $LD_LIBRARY_PATH
  then
    /usr/bin/echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" | /usr/bin/tee -a $REPORT
  fi
  if /usr/bin/test $LD_LIBRARY_PATH_64
  then
    /usr/bin/echo "LD_LIBRARY_PATH_64=$LD_LIBRARY_PATH_64" | /usr/bin/tee -a $REPORT
  fi
fi  


/usr/bin/echo "\n\n\n.cshrc or .profile Recommended Variable Settings" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
SH=`/usr/bin/cat /etc/passwd | /usr/bin/awk -F: '{print $1, $NF}' | /usr/bin/grep -w $USER | /usr/bin/awk -F/ '{print $NF}''`
/usr/bin/echo "INFO- Your shell is $SH\n" | /usr/bin/tee -a $REPORT
if [ $ORAVER != 920 ]
then
  if [ $SH = csh ]
  then
    /usr/bin/echo "The following environment variables must be set in your .cshrc file for the $USER user." | /usr/bin/tee -a $REPORT
    /usr/bin/echo "setenv ORACLE_HOME $OH" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "setenv LD_LIBRARY_PATH $OH/lib" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "setenv PATH $OH/bin:/usr/ccs/bin:$PATH" | /usr/bin/tee -a $REPORT
  else
    /usr/bin/echo "The following environment variables must be set in your .profile file for the $USER user." | /usr/bin/tee -a $REPORT
    /usr/bin/echo "ORACLE_HOME=$OH" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "LD_LIBRARY_PATH=$OH/lib" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "PATH=$OH/bin:$PATH" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "export \$ORACLE_HOME" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "export \$LD_LIBRARY_PATH" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "export \$PATH" | /usr/bin/tee -a $REPORT
  fi
elif [ $ORAVER = 920 -a $ORABIT = 64 ]
then
  if [ $SH = csh ]
  then
    /usr/bin/echo "The following environment variables must be set in your .cshrc file for the $USER user." | /usr/bin/tee -a $REPORT
    /usr/bin/echo "setenv ORACLE_HOME $OH" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "setenv LD_LIBRARY_PATH $OH/lib32" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "setenv LD_LIBRARY_PATH_64 $OH/lib" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "setenv PATH $OH/bin:/usr/ccs/bin:$PATH" | /usr/bin/tee -a $REPORT
  else
    /usr/bin/echo "The following environment variables must be set in your .profile file for the $USER user." | /usr/bin/tee -a $REPORT
    /usr/bin/echo "ORACLE_HOME=$OH" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "LD_LIBRARY_PATH=$OH/lib32" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "LD_LIBRARY_PATH_64=$OH/lib" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "PATH=$OH/bin:$PATH" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "export \$ORACLE_HOME" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "export \$LD_LIBRARY_PATH" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "export \$LD_LIBRARY_PATH_64" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "export \$PATH" | /usr/bin/tee -a $REPORT
  fi
fi

if [ "$OH" = "No_Location_Given" ]
then
  /usr/bin/echo "\nALERT- When running this script you did not provide a location where Oracle will be installed.  Change the value of No_Location_Given to the location where Oracle will be installed in." | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi


# Sun /tmp SPACE VERIFICATION

/usr/bin/echo "\n \n \nTMP space Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_______________________\n" | /usr/bin/tee -a $REPORT
/usr/bin/echo "FYI: The runInstaller (OUI) uses/checks for temporary space by checking first for the TEMP environmental variable, then the TMP environmental variable and lastly the actual '/tmp' mount point" | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo "_______________________\n" | /usr/bin/tee -a $REPORT 
TMPMT=`/usr/sbin/df -k /tmp | /usr/bin/awk '{print $4}' |  /usr/bin/sed '1d'`
TMPMT=`/usr/bin/expr $TMPMT / 1024`
if [ `/usr/bin/env | /usr/bin/grep -ic "TEMP="` -ne 0 ]
then
 TEMPLOC=`/usr/bin/env | /usr/bin/grep "TEMP=" | /usr/bin/awk -F= '{print $2}'`
 if /usr/bin/test -d $TEMPLOC
 then
   TEMP=`/usr/sbin/df -k "$TEMPLOC" | /usr/bin/awk '{print $4}' | /usr/bin/sed '1d'`
   TEMP=`/usr/bin/expr $TEMP / 1024`
   /usr/bin/echo "The TEMP variable was found set in your environment and has $TEMP Mb of free space" | /usr/bin/tee -a $REPORT
 else
   /usr/bin/echo "ALERT- The TEMP variable was found set in your environment but is either an invalid value or is not a directory.  Please set TEMP correctly or to a valid, writable directory or unset if the InstallPrep determines you have adequate space in /tmp" | /usr/bin/tee -a $REPORT
   ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
 fi
elif [ `/usr/bin/env | /usr/bin/grep -ic "TMP="` -ne 0 ]
then
  TMPLOC=`/usr/bin/env | /usr/bin/grep "TMP=" | /usr/bin/awk -F= '{print $2}'`
  if /usr/bin/test -d $TMPLOC
  then
    TMP=`/usr/sbin/df -k "$TMPLOC" | /usr/bin/awk '{print $4}' | /usr/bin/sed '1d'`
    TMP=`/usr/bin/expr $TMP / 1024`
    /usr/bin/echo "The TMP variable was found set in your environment and has $TMP Mb of free space" | /usr/bin/tee -a $REPORT
  else 
    /usr/bin/echo "ALERT- The TMP variable was found set in your environment but is either an invalid value or is not a directory.  Please set TMP correctly or to a valid, writable directory or unset if the InstallPrep determines you have adequate space in /tmp" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  fi
fi
case $ORAVER in
  "805"|"806")
     if /usr/bin/test -n "$TEMP"
     then 
       if [ $TEMP -lt 20 ]
       then
         /usr/bin/echo "ALERT- TEMP is set in the environment and has less than the required 20 Mb.  Please point the TEMP environmental variable to a mount point with at least 20 Mb of free space" | /usr/bin/tee -a $REPORT 
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TEMPLOC"
         then
           /usr/bin/echo "TEMP has adequate space of $TEMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TEMP is set in the environment; however, $TEMPLOC does not have write permissions for user $USER" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMP"
     then
       if [ $TMP -lt 20 ]
       then
         /usr/bin/echo "ALERT- TMP is set in the environment and has less than the required 20 M.  Please point the TMP environmental variable to a mount point with at least 20 Mb of free space" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TMPLOC"
         then
           /usr/bin/echo "TMP has adequate space of $TMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TMP is set in the environment; however, $TMPLOC does not have write permissions for user $USER" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMPMT"
     then
       if [ $TMPMT -lt 20 ]
       then
         /usr/bin/echo "ALERT- /tmp space = $TMPMT Mb, please increase /tmp to at least 20 Mb\n" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         /usr/bin/echo "/tmp has adequate space of $TMPMT Mb\n" | /usr/bin/tee -a $REPORT
       fi
     else
       /usr/bin/echo "ALERT-  /tmp is not specified\n" | /usr/bin/tee -a $REPORT
       ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
     fi
     ;;
   "815"|"816"|"817"|"901"|"920")
     if /usr/bin/test -n "$TEMP"
     then 
       if [ $TEMP -lt 400 ]
       then
         /usr/bin/echo "ALERT- TEMP is set in the environment and has less than the required 400 Mb.  Please point the TEMP environmental variable to a mount point with at least 400 Mb of free space" | /usr/bin/tee -a $REPORT 
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TEMPLOC"
         then
           /usr/bin/echo "TEMP has adequate space of $TEMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TEMP is set in the environment; however, $TEMPLOC does not have write permissions for user $USER" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMP"
     then
       if [ $TMP -lt 400 ]
       then
         /usr/bin/echo "ALERT- TMP is set in the environment and has less than the required 400 Mb.  Please point the TMP environmental variable to a mount point with at least 400 Mb of free space" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TMPLOC"
         then
           /usr/bin/echo "TMP has adequate space of $TMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TMP is set in the environment; however, $TMPLOC does not have write permissions for user $USER" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMPMT"
     then
       if [ $TMPMT -lt 400 ]
       then
         /usr/bin/echo "ALERT- /tmp space = $TMPMT Mb, please increase /tmp to at least 400 Mb\n" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         /usr/bin/echo "/tmp has adequate space of $TMPMT Mb\n" | /usr/bin/tee -a $REPORT
       fi
     else
       /usr/bin/echo "ALERT-  /tmp is not specified\n" | /usr/bin/tee -a $REPORT
       ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
     fi
     ;;
    *)
     /usr/bin/echo ""
     ;;
esac

# Sun VERIFY SWAP

/usr/bin/echo "\n\n\nSwap Space Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
if /usr/bin/test -x /usr/sbin/swap
then
  SWAP=`/usr/sbin/swap -s | /usr/bin/sed -n '$p' | /usr/bin/awk '{print $11}' | /usr/bin/sed 's/k/ k /' | /usr/bin/awk '{print $1}'`
  SWAP=`/usr/bin/expr $SWAP / 1024`
  SWAPG=`/usr/sbin/swap -s | /usr/bin/sed -n '$p' | /usr/bin/awk '{print $11}' | /usr/bin/sed 's/k/ k /' | /usr/bin/awk '{print $2}'`
  if /usr/bin/test -z "$SWAP"
  then 
    /usr/bin/echo "ALERT- SWAP has not been setup or specified" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "Swap is $SWAP Mb\n" | /usr/bin/tee -a $REPORT
  fi
else
  /usr/bin/echo "ALERT- Swap space verification cannot be determined because either swap has not been setup or user $USER does not have execute permission to determine swap.  Please have the System Administrator add execute on the swap command or have them do '/usr/sbin/swap -s'" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi

# Sun Verifying Memory

MEM=`/usr/sbin/prtconf | /usr/bin/grep Memory | /usr/bin/awk '{print $3}'`
TWOM=`/usr/bin/expr $MEM \* 2`
THREM=`/usr/bin/expr $MEM \* 3`
/usr/bin/echo "\n\n\nMemory Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "___________________\n" | /usr/bin/tee -a $REPORT

if [ $ORAVER = "805" -o $ORAVER = "806" -o $ORAVER = "815" -o $ORAVER = "816" -o $ORAVER = "817" ]
then
  if [ $MEM -lt 128 ]
  then
    /usr/bin/echo "ALERT-  You have $MEM Mb of memory. This is not enough to install Oracle $ORAVER $ORABIT bit.  You must have at least 128Mb\n" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "You have $MEM Mb of memory which is adequate to install Oracle $ORAVER $ORABIT bit" | /usr/bin/tee -a $REPORT
  fi
elif [ $ORAVER = "901" -a $ORABIT = 32 ]
then
  if [ $MEM -gt  128 -a $MEM -lt 256 ]
  then
    /usr/bin/echo "ALERT-  You have $MEM Mb of memory. This is not enough to install Oracle $ORAVER $ORABIT bit.  You must have at least 256Mb\n" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "You have $MEM Mb of memory which is adequate to install Oracle $ORAVER $ORABIT bit" | /usr/bin/tee -a $REPORT
  fi
elif [ $ORAVER = "901" -a $ORABIT = 64 ] || [ $ORAVER = "920" ]
then
  if [ $MEM -gt 256 -a $MEM -lt 512 ]
  then
    /usr/bin/echo "ALERT-  You have $MEM Mb of memory. This is not enough to install Oracle $ORAVER $ORABIT bit.  You must have at least 512Mb\n" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "You have $MEM Mb of memory which is adequate to install Oracle $ORAVER $ORABIT bit" | /usr/bin/tee -a $REPORT
  fi
fi

/usr/bin/echo "\n\n\nChecking Swap to Memory Ratio" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
if /usr/bin/test $SWAP
then
  if [ $ORAVER = "805" -o $ORAVER = "806" ]
  then
    if [ $MEM -le 512 ]
    then 
      if [ $SWAP -lt $THREM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $THREM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb\n" | /usr/bin/tee -a $REPORT
      fi
    elif [ $MEM -gt 512 -a $MEM -lt 1024 ]
    then
      if [ $SWAP -lt $TWOM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $TWOM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb\n" | /usr/bin/tee -a $REPORT
      fi
    elif [ $MEM -ge 1024 ]
    then
      if [ $SWAP -lt $MEM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $MEM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb\n" | /usr/bin/tee -a $REPORT
      fi
    fi
  elif [ $ORAVER = "815" -o $ORAVER = "816" -o $ORAVER = "817" ] 
  then
    if [ $MEM -lt 1024 ]
    then
      if [ $SWAP -lt $TWOM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $TWOM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb.\n" | /usr/bin/tee -a $REPORT
      fi
    elif [ $MEM -ge 1024 ]
    then
      if [ $SWAP -lt $MEM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $MEM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb.\n" | /usr/bin/tee -a $REPORT
      fi
    fi
  elif [ $ORAVER = "901" -a $ORABIT = 32 ]
  then
    if [ $MEM -lt 1024 ]
    then
      if [ $SWAP -lt $TWOM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $TWOM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb.\n" | /usr/bin/tee -a $REPORT
      fi
    elif [ $MEM -ge 1024 ]
    then
      if [ $SWAP -lt $MEM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP to at least $MEM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb.\n" | /usr/bin/tee -a $REPORT
      fi
    fi
  elif [ $ORAVER = "901" -a $ORABIT = 64 ]
  then
    if [ $MEM -lt 512 ]
    then
      if [ $SWAP -lt $TWOM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $TWOM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb.\n" | /usr/bin/tee -a $REPORT
      fi
    elif [ $MEM -ge 512 ]
    then
      if [ $SWAP -lt $MEM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $MEM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb.\n" | /usr/bin/tee -a $REPORT
      fi
    fi
  elif [ $ORAVER = "920" ] 
  then
    if [ $MEM -lt 1024 ]
    then
      if [ $SWAP -lt 1024 ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least 1Gig.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb.\n" | /usr/bin/tee -a $REPORT
      fi
    elif [ $MEM -ge 1024 ]
    then
      if [ $SWAP -lt $MEM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $MEM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb.\n" | /usr/bin/tee -a $REPORT
      fi
    fi
  fi 
else
  /usr/bin/echo "ALERT- A Swap to Memory ratio cannot be determined because swap has not been setup or user $USER does not have execute permission to determine swap" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi 


# Sun KERNEL PARAMETER VERIFICATION

/usr/bin/echo "\n \n \nUnix Kernel Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________\n" | /usr/bin/tee -a $REPORT
/usr/bin/echo "Checking Required Kernel Parameters for minimum values needed."  | /usr/bin/tee -a $REPORT
/usr/bin/echo "Note-  Changes to the Unix Kernel must be performed by the root user." | /usr/bin/tee -a $REPORT
/usr/bin/echo "A system reboot is required for the kernel changes to take affect.\n" | /usr/bin/tee -a $REPORT

SHMMAX=`/usr/sbin/sysdef | /usr/bin/grep SHMMAX | /usr/bin/awk '{print $1}'`
if /usr/bin/test -z "$SHMMAX"
then
  /usr/bin/echo "ALERT-  SHMMAX has not been defined and needs to be set to 4294967295" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $SHMMAX -lt 4294967295 ]
then
  /usr/bin/echo "ALERT-  Increase the kernel parameter SHMMAX to 4294967295 from present setting of $SHMMAX" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "SHMMAX set to $SHMMAX is adequate" | /usr/bin/tee -a $REPORT
fi

if [ $OSVER != "2.9" ] && [ $OSVER != "5.9" ]
then
  SHMMIN=`/usr/sbin/sysdef | /usr/bin/grep SHMMIN | /usr/bin/awk '{print $1}'`
  if /usr/bin/test -z "$SHMMIN"
  then
    /usr/bin/echo "ALERT- SHMMIN has not been defined and needs to be set to 1" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $SHMMIN -lt 1 ]
  then
    /usr/bin/echo "ALERT- Increase the kernel parameter SHMMIN to 1 or more" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SHMMIN set to $SHMMIN is adequate" | /usr/bin/tee -a $REPORT
  fi
fi

SHMMNI=`/usr/sbin/sysdef | /usr/bin/grep SHMMNI | /usr/bin/awk '{print $1}'`
if /usr/bin/test -z "$SHMMNI"
then
  /usr/bin/echo "ALERT- SHMMNI has not been defined and needs to be set to 100 or more" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $SHMMNI -lt 100 ]
then
  /usr/bin/echo "ALERT-  Increase the kernel parameter SHMMNI to at least 100 from present setting of $SHMMNI" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "SHMMNI set to $SHMMNI is adequate" | /usr/bin/tee -a $REPORT
fi

if [ $OSVER != "2.9" ] && [ $OSVER != "5.9" ]
then
  SHMSEG=`/usr/sbin/sysdef | /usr/bin/grep SHMSEG | /usr/bin/awk '{print $1}'`
  if /usr/bin/test -z "$SHMSEG"
  then
    /usr/bin/echo "ALERT- SHMSEG has not been defined and needs to be set to 10 or more" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  elif [ $SHMSEG -lt 10 ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter SHMSEG to at least 10 from present setting of $SHMSEG" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SHMSEG set to $SHMSEG is adequate" | /usr/bin/tee -a $REPORT
  fi
fi

SEMMNI=`/usr/sbin/sysdef | /usr/bin/grep SEMMNI | /usr/bin/awk '{print $1}'`
if /usr/bin/test -z "$SEMMNI"
then
  /usr/bin/echo "ALERT- SEMMNI has not been defined and needs to be set to 100 or more" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $SEMMNI -lt 100 ]
then
  /usr/bin/echo "ALERT- Increase the kernel parameter SEMMNI to at least 100 from present setting of $SEMMNI" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "SEMMNI set to $SEMMNI is adequate" | /usr/bin/tee -a $REPORT
fi

SEMMSL=`/usr/sbin/sysdef | /usr/bin/grep SEMMSL | /usr/bin/awk '{print $1}'`
if /usr/bin/test -z "$SEMMSL"
then
  /usr/bin/echo "ALERT- SEMMSL has not been defined and needs to be set to 100 or more" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $SEMMSL -lt 256 ]
then
  /usr/bin/echo "ALERT-  Increase the kernel parameter SEMMSL to at least 100 from present setting of $SEMMSL" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "SEMMSL set to $SEMMSL is adequate" | /usr/bin/tee -a $REPORT
fi


SEMMNS=`/usr/sbin/sysdef | /usr/bin/grep SEMMNS | /usr/bin/awk '{print $1}'`
if /usr/bin/test -z "$SEMMNS"
then
  /usr/bin/echo "ALERT- SEMMNS has not been defined and needs to be set to 256 (pre 9.2) and 1024 (9.2) or more" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $ORAVER != "920" ]
then
  if [ $SEMMNS -lt 256 ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter SEMMNS to at least 256 from present setting of $SEMMNS" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SEMMNS set to $SEMMNS is adequate" | /usr/bin/tee -a $REPORT
  fi
else
  if [ $SEMMNS -lt 1024 ]
  then
    /usr/bin/echo "ALERT-  Increase the kernel parameter SEMMNS to at least 1024 from present setting of $SEMMNS" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "SEMMNS set to $SEMMNS is adequate" | /usr/bin/tee -a $REPORT
  fi
fi

SEMOPM=`/usr/sbin/sysdef | /usr/bin/grep SEMOPM | /usr/bin/awk '{print $1}'`
if /usr/bin/test -z "$SEMOPM"
then
  /usr/bin/echo "ALERT- SEMOPM has not been defined and needs to be set to 100" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $SEMOPM -lt 100 ]
then
  /usr/bin/echo "ALERT- Increase the kernel parameter SEMOPM to at least 100 from present setting of $SEMOPM" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "SEMOPM set to $SEMOPM is adequate" | /usr/bin/tee -a $REPORT
fi

SEMVMX=`/usr/sbin/sysdef | /usr/bin/grep SEMVMX | /usr/bin/awk '{print $1}'`
if /usr/bin/test -z "$SEMVMX"
then
  /usr/bin/echo "ALERT- SEMVMX has not been defined and needs to be set to 32767" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $SEMVMX -lt 32767 ]
then
  /usr/bin/echo "ALERT-  Increase the kernel parameter SEMVMX to at least 32767 from present setting of $SEMVMX" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "SEMVMX set to $SEMVMX is adequate" | /usr/bin/tee -a $REPORT
fi

# Sun ASSEMBLY TOOL VERIFICATION

/usr/bin/echo "\n \n \nAssembly Tool Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________\n" | /usr/bin/tee -a $REPORT

arvalue=`/usr/bin/which ar`
if [ "$arvalue" != "/usr/ccs/bin/ar" ]
then
  /usr/bin/echo "WARNING-  ar not found in /usr/ccs/bin directory but was found in '$arvalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /usr/bin/echo "ar - found correctly in /usr/ccs/bin" | /usr/bin/tee -a $REPORT
fi

ldvalue=`/usr/bin/which ld`
if [ "$ldvalue" != "/usr/ccs/bin/ld" ]
then
  /usr/bin/echo "WARNING-  ld not found in /usr/ccs/bin directory but was found in '$ldvalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /usr/bin/echo "ld - found correctly in /usr/ccs/bin" | /usr/bin/tee -a $REPORT
fi

nmvalue=`/usr/bin/which nm`
if [ "$nmvalue" != "/usr/ccs/bin/nm" ]
then
  /usr/bin/echo "WARNING-  nm not found in /usr/ccs/bin directory but was found in '$nmvalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /usr/bin/echo "nm - found correctly in /usr/ccs/bin" | /usr/bin/tee -a $REPORT
fi

makevalue=`/usr/bin/which make`
if [ "$makevalue" != "/usr/ccs/bin/make" ]
then
  /usr/bin/echo "WARNING-  make not found in /usr/ccs/bin directory but was found in '$makevalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /usr/bin/echo "make - found correctly in /usr/ccs/bin" | /usr/bin/tee -a $REPORT
fi

# Sun ULIMIT VERIFICATION

/usr/bin/echo "\n \n \nVerification of ulimits" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_______________________________\n" | /usr/bin/tee -a $REPORT

TIMERAW=`/usr/bin/ulimit -t`
TIME=`/usr/bin/ulimit -t | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$TIME"
then
  /usr/bin/echo "ALERT- ulimit(TIME) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $TIME -lt 1000000000 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(TIME) to unlimited from the present $TIMERAW" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(TIME) set to $TIMERAW is adequate" | /usr/bin/tee -a $REPORT
fi

FILERAW=`/usr/bin/ulimit -f`
FILE=`/usr/bin/ulimit -f | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$FILE"
then
  /usr/bin/echo "ALERT- ulimit(FILE) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $FILE -lt 1000000000 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(FILE) to unlimited from the present $FILERAW" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(FILE) set to $FILERAW is adequate" | /usr/bin/tee -a $REPORT
fi

DATARAW=`/usr/bin/ulimit -d`
DATA=`/usr/bin/ulimit -d | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$DATA"
then
  /usr/bin/echo "ALERT- ulimit(DATA) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $DATA -lt 1000000000 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(DATA) to unlimited from the present $DATARAW" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(DATA) set to $DATARAW is adequate" | /usr/bin/tee -a $REPORT
fi

STACKRAW=`/usr/bin/ulimit -s`
STACK=`/usr/bin/ulimit -s | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$STACK"
then
  /usr/bin/echo "ALERT- ulimit(STACK) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $STACK -lt 8192 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(STACK) to at least 8192 from the present $STACKRAW" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(STACK) set to $STACKRAW is adequate" | /usr/bin/tee -a $REPORT
fi

NOFILESRAW=`/usr/bin/ulimit -n`
NOFILES=`/usr/bin/ulimit -n | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$NOFILES"
then
  /usr/bin/echo "ALERT- ulimit(NOFILES) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $NOFILES -lt 1024 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(NOFILES) to at least 1024 from the present $NOFILESRAW" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(NOFILES) set to $NOFILESRAW is adequate" | /usr/bin/tee -a $REPORT
fi

VMEMORYRAW=`/usr/bin/ulimit -v`
VMEMORY=`/usr/bin/ulimit -v | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$VMEMORY"
then
  /usr/bin/echo "ALERT- ulimit(VMEMORY) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $VMEMORY -lt 1000000000 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(VMEMORY) to unlimited from the present $VMEMORY" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(VMEMORY) set to $VMEMORYRAW is adequate" | /usr/bin/tee -a $REPORT
fi

# Sun CERTIFICATION VERIFICATION

/usr/bin/echo "\n \n \nCertification of Oracle and OS Version Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________________________________________\n" | /usr/bin/tee -a $REPORT
if [ "$ORABIT" = "64" ]
then
  case $OSVER in
    "2.5.1"|"5.5.1"|"2.6"|"5.6")
       /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER is not certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
       SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
       ;;
    "2.7"|"5.7")
       if [ $OSBIT = 64 -a $ORAVER = "815" ] || [ $OSBIT = 64 -a $ORAVER = "816" ]
       then
         /usr/bin/echo "$OS $OSVER $OSBIT bit is certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
       else
         /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER $OSBIT bit is not certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
         SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
       fi
       ;;
    "2.8"|"5.8")
       if [ $OSBIT = 64 -a $ORAVER = "815" ] || [ $OSBIT = 64 -a $ORAVER = "816" ] || [ $OSBIT = 64 -a $ORAVER = "817" ] || [ $OSBIT = 64 -a $ORAVER = "901" ] || [ $OSBIT = 64 -a $ORAVER = "920" ]
       then
         /usr/bin/echo "$OS $OSVER $OSBIT bit is certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
       else
         /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER $OSBIT bit is not certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
         SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
       fi
       ;;
    "2.9"|"5.9")
       if [ $OSBIT = 64 -a $ORAVER = "901" ] || [ $OSBIT = 64 -a $ORAVER = "920" ]
       then
         /usr/bin/echo "$OS $OSVER $OSBIT bit is certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
       else
         /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER $OSBIT bit is not certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
         SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
       fi
       ;;
    "2.10"|"5.10")
       if [ $ORAVER = "920" ]
       then
         /usr/bin/echo "$OS $OSVER $OSBIT bit is certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
       else
         /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER $OSBIT bit is not certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT
         SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
       fi
       ;;
    *)
       /usr/bin/echo "!!SHOWSTOPPER!!  The $OS OS Version was not determinable or is incorrect\n" | /usr/bin/tee -a $REPORT
       SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
       ;;
  esac
else
  if [ $OSVER = "2.9" -o $OSVER = "5.9" ]
  then
    if [ $ORAVER = "805" -o $ORAVER = "806" -o $ORAVER = "815" -o $ORAVER = "816" ]
    then
      /usr/bin/echo "!!SHOWSTOPPER!!  The $OS OS Version was not determinable or is incorrect\n" | /usr/bin/tee -a $REPORT
      SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
    else
      /usr/bin/echo "$OS $OSVER $OSBIT bit is certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT 
    fi
  else
    /usr/bin/echo "$OS $OSVER $OSBIT bit is certified to run Oracle $ORAVER $ORABIT bit configuration\n" | /usr/bin/tee -a $REPORT 
  fi
fi

# Sun Verify OS packages are installed

/usr/bin/echo "\n \n \n32bit/64bit OS Package Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________\n" | /usr/bin/tee -a $REPORT

for PACKAGE in SUNWarc SUNWbtool SUNWlibm SUNWlibms SUNWsprot SUNWtoo SUNWhea
do
  if [ `pkginfo $PACKAGE 2>>/dev/null | /usr/bin/grep -c $PACKAGE` = 0 ]
  then
    /usr/bin/echo "ALERT-  The $PACKAGE package needs to be installed" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "The $PACKAGE package is installed" | /usr/bin/tee -a $REPORT
  fi
done

for PACKAGE in SUNWi1of SUNWxwfnt
do
  if [ `pkginfo $PACKAGE 2>>/dev/null | /usr/bin/grep -c $PACKAGE` = 0 ]
  then
    /usr/bin/echo "ALERT-  The $PACKAGE package needs to be installed (For Java only)" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "The $PACKAGE package is installed" | /usr/bin/tee -a $REPORT
  fi
done

/usr/bin/echo "\n \n \n64bit specific OS Package Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________\n" | /usr/bin/tee -a $REPORT
if [ $OSBIT = 64 -a $ORAVER = "901" ]
then
    for PACKAGE in SUNWarcx SUNWtoox 
    do
      if [ `pkginfo $PACKAGE 2>>/dev/null | /usr/bin/grep -c $PACKAGE` = 0 ]
      then
        /usr/bin/echo "ALERT-  The $PACKAGE package needs to be installed" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "The $PACKAGE package is installed" | /usr/bin/tee -a $REPORT
      fi
    done
elif [ $OSBIT = 64 -a $ORAVER = "920" ] 
then
  if [ `pkginfo SUNWsprox 2>>/dev/null | /usr/bin/grep -c SUNWsprox` = 0 ]
  then
    /usr/bin/echo "ALERT-  The SUNWsprox package needs to be installed" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "The SUNWsprox package is installed" | /usr/bin/tee -a $REPORT
  fi
else
  /usr/bin/echo "Not applicable since your installing Oracle $ORAVER $ORABIT bit" | /usr/bin/tee -a $REPORT
fi

# Sun VERIFY KERNEL PATCH LEVEL

/usr/bin/echo "\n \n \nKernel Patch Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________\n" | /usr/bin/tee -a $REPORT

if [ $OSVER = "2.6" ] || [ $OSVER = "5.6" ]
then
  case $ORAVER in
    "815")
       if [ `/usr/bin/uname -v | /usr/bin/grep -c 105181` = 1 ] 
       then
         if [ `/usr/bin/uname -v | /usr/bin/sed 's/-/ /' | /usr/bin/awk '{print $2}'` -gt 6 ]
         then
           /usr/bin/echo "Kernel patch `/usr/bin/uname -v` is adequate" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT-  Kernel patch `/usr/bin/uname -v` is too low, please applied the latest Kernel patch"i | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       else
         /usr/bin/echo "ALERT-  Either the Kernel patch is too old or it is not the right patch" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       fi
       ;;
    "816"|"817"|"901")
       if [ `/usr/bin/uname -v | /usr/bin/grep -c 105181` = 1 ] 
       then
         if [ `/usr/bin/uname -v | /usr/bin/sed 's/-/ /' | /usr/bin/awk '{print $2}'` -gt 15 ]
         then    
           /usr/bin/echo "Kernel patch `/usr/bin/uname -v` is adequate" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT-  Kernel patch `/usr/bin/uname -v` is too low, please applied the latest Kernel patch" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       else
         /usr/bin/echo "ALERT-  Either the Kernel patch is too old or it is not the right patch" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       fi
       ;;
    *)
       ;;
    esac
fi
if [ $OSVER = "2.8" ] || [ $OSVER = "5.8" ]
then
  case $ORAVER in
    "901")
       if [ `/usr/bin/uname -v | /usr/bin/grep -c 108528` = 1 ]
       then
         if [ `/usr/bin/uname -v | /usr/bin/sed 's/-/ /' | /usr/bin/awk '{print $2}'` -gt 1 ] 
         then
           /usr/bin/echo "Kernel patch `/usr/bin/uname -v` is adequate" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT-  Kernel patch `/usr/bin/uname -v` is too low, please applied the latest Kernel patch" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       elif [ `/usr/bin/uname -v | /usr/bin/grep -c 117350` = 1 ]
       then
         /usr/bin/echo "Kernel patch `/usr/bin/uname -v` is adequate" | /usr/bin/tee -a $REPORT
       else
         /usr/bin/echo "ALERT-  Either the Kernel patch is too old or it is not the right patch" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       fi
       ;;
     "920")
        if [ `/usr/bin/uname -v | /usr/bin/grep -c 108528` = 1 ] 
        then
          if [ `/usr/bin/uname -v | /usr/bin/sed 's/-/ /' | /usr/bin/awk '{print $2}'` -lt 5 ]
          then   
            /usr/bin/echo "ALERT-  Kernel patch `/usr/bin/uname -v` is too low, please applied the latest Kernel patch" | /usr/bin/tee -a $REPORT 
            ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
          else
            /usr/bin/echo "Kernel patch `/usr/bin/uname -v` is adequate" | /usr/bin/tee -a $REPORT
          fi
        elif [ `/usr/bin/uname -v | /usr/bin/grep -c 117350` = 1 ]
        then
         /usr/bin/echo "Kernel patch `/usr/bin/uname -v` is adequate" | /usr/bin/tee -a $REPORT
        else
          /usr/bin/echo "ALERT-  Either the Kernel patch is too old or it is not the right patch" | /usr/bin/tee -a $REPORT
          ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
        fi
        ;;
     *)
       /usr/bin/echo "Kernel patch `/usr/bin/uname -v` is adequate" | /usr/bin/tee -a $REPORT
       ;;
   esac
fi
if [ $OSVER = "2.9" ] || [ $OSVER = "5.9" ] || [ $OSVER = "2.10" ] || [ $OSVER = "5.10" ]
then
  /usr/bin/echo "Verification is not needed since the SunOS version is $OSVER"
fi

;;

"OSF1")

OSVER=`/usr/sbin/sizer -v | /usr/bin/sed 's/Tru64//' | /usr/bin/awk '{print substr($3,2)}'`

# TRU64 START echo OF SCRIPT TO OUTPUT FILE

`/usr/bin/touch $REPORT; /usr/bin/chmod 777 $REPORT`
/usr/bin/echo "\nOutput from the Oracle InstallPrep Script run on $BOXNAME on `date`.\n \n \n" > $REPORT
/usr/bin/echo "To successfully install the Oracle Database Software you must resolve" >> $REPORT
/usr/bin/echo "each item listed in this Report. \n \n"  >> $REPORT
/usr/bin/echo "\n\n\nInstallPrep now running on your $OS box ....." | /usr/bin/tee -a $REPORT


# TRU64  ORACLE VERSION INPUT

/usr/bin/echo "\n\n\nOracle Version Input" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_______________________\n" | /usr/bin/tee -a $REPORT
/usr/bin/echo "What version of Oracle are you installing?\n (valid values:805,806,815,816,817,901,920):" | /usr/bin/tee -a $REPORT
read ORAVER
/usr/bin/echo $ORAVER >> $REPORT
case $ORAVER in
  "805"|"806"|"815"|"816"|"817"|"901"|"920")
          ;;
  "")
    /usr/bin/echo "\nALERT-  You did not enter a value" | /usr/bin/tee -a $REPORT 
    exit
    ;;
  *)
    /usr/bin/echo "\nALERT-  You have entered an invalid version - enter valid value" | /usr/bin/tee -a $REPORT
    exit
    ;;
esac

# TRU64 CORRECT USER VERIFICATION

/usr/bin/echo "\n\n\nUser Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
USER=`/usr/bin/who -m | /usr/bin/awk '{print $1}'`
if [ $USER = "root" ]
then
  /usr/bin/echo "\nALERT-  You are logged in as user -- $USER --.  Please log in as the user that will be installing the Oracle Database Software. This user should not be root." | /usr/bin/tee -a $REPORT
  /usr/bin/echo "Exiting" | /usr/bin/tee -a $REPORT
  exit;
else
  /usr/bin/echo "\nYou are currently logged on as user -- $USER -- \n" | /usr/bin/tee -a $REPORT
fi

# TRU64 CONFIRMATION OF USER

/usr/bin/echo "Is user $USER the unix user that will be installing Oracle Software?  (y or n)" | /usr/bin/tee -a $REPORT
read answer
/usr/bin/echo $answer >> $REPORT
case $answer in
  "n"|"N")
    /usr/bin/echo "\nALERT-  Please log in as the user that will be installing Oracle.  Then rerun this script \n" | /usr/bin/tee -a $REPORT
    exit
    ;;
  "y"|"Y")
    /usr/bin/echo "\n \n \n Verifying User in /etc/passwd" | /usr/bin/tee -a $REPORT
    /usr/bin/echo "______________________________________\n" | /usr/bin/tee -a $REPORT
    if /usr/bin/test -r /etc/passwd
    then
      if [ "$USER" =  `/usr/bin/cat /etc/passwd | /usr/bin/awk -F: '{print $1}' | /usr/bin/grep -e $USER` ]
      then
        /usr/bin/echo "-- $USER -- correctly exists in /etc/passwd \n" | /usr/bin/tee -a $REPORT
      else
        /usr/bin/echo "ALERT-  The unix user -- $USER -- is not in /etc/passwd.  You must add user $USER to the /etc/passwd file. NIS managed users are not recommended" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      fi
    else
      /usr/bin/echo " ALERT-  User $USER is not allowed read access to the /etc/passwd file, verification of user $USER in /etc/passwd can not be performed.  Please get with your System Administrator to have them verify the presence of the user $USER in the /etc/passwd file" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
    ;;
  "")
    /usr/bin/echo "\nALERT-  You did not enter a value" | /usr/bin/tee -a $REPORT
    exit
    ;;
  *)
    /usr/bin/echo "\nALERT-  You have entered an invalid value - enter valid value" | /usr/bin/tee -a $REPORT
    exit
    ;;
esac

# TRU64 SU VERIFICATION

/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo "Switching User (su) verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________________" | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo "Are you switching user (su) from another user to become the $USER user? (Y/N):" | /usr/bin/tee -a $REPORT
read SUORACLE
/usr/bin/echo $SUORACLE >> $REPORT
case $SUORACLE in
  "Y"|"y")
      /usr/bin/echo " " | /usr/bin/tee -a $REPORT
      /usr/bin/echo "WARNING: Switching User (su) is not suggested, you should login as $USER user directly when doing the install" | /usr/bin/tee -a $REPORT
      WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
      ;;
  "N"|"n")
      /usr/bin/echo " " | /usr/bin/tee -a $REPORT
      /usr/bin/echo "Passed switch user (su) test" | /usr/bin/tee -a $REPORT
      ;;
  *)
      /usr/bin/echo " " | /usr/bin/tee -a $REPORT
      /usr/bin/echo "You have entered an invalid answer, exiting InstallPrep, please try again" | /usr/bin/tee -a $REPORT
      exit
      ;;
esac

# TRU64 CONFIRMATION OF GROUP

/usr/bin/echo "\n\n\nGroup Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
/usr/bin/echo "Enter the unix group that will be used during the installation (example: dba)?" | /usr/bin/tee -a $REPORT
read GROUP
/usr/bin/echo $GROUP >> $REPORT
case $GROUP in
  "") 
    /usr/bin/echo "\nALERT- You did not enter a value" | /usr/bin/tee -a $REPORT
    exit
   ;;
  *)
    if /usr/bin/test -r /etc/group
    then
      if [ "$GROUP" = "`/usr/bin/cat /etc/group | /usr/bin/awk -F: '{print $1}' | /usr/bin/grep -e $GROUP`" ]
      then
        /usr/bin/echo "-- $GROUP -- exists in /etc/group" | /usr/bin/tee -a $REPORT
      else
        /usr/bin/echo "ALERT-  You must create the unix group -- $GROUP -- as the root user and add -- $USER -- to this group or select a different unix group that already exists in /etc/group\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      fi
    else
      /usr/bin/echo " ALERT-  user $USER is not allowed read access to the /etc/group file, verification of $GROUP in /etc/group can not be performed.  Please get with your System Administrator to have them verify the presence of the $GROUP in the /etc/group file" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
    ;;
esac

# TRU64 CONFIRMATION OF ORACLE_HOME

/usr/bin/echo "\n\n\nSpecify ORACLE_HOME" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
if /usr/bin/test $ORACLE_HOME
then
  /usr/bin/echo "Presently, your ORACLE_HOME is set to $ORACLE_HOME, is this the correct location that this installation will be using? (Y/N)" | /usr/bin/tee -a $REPORT
  read CFRM
  if [ $CFRM = "Y" -o $CFRM = "y" ]
  then 
    OH=$ORACLE_HOME
    /usr/bin/echo $OH >> $REPORT
  else
    /usr/bin/echo "Enter Location where you will be installing Oracle (example: /u01/app/oracle/product/8.1.7)" | /usr/bin/tee -a $REPORT
    read OH
    /usr/bin/echo $OH >> $REPORT
  fi
else
  /usr/bin/echo "Enter Location where you will be installing Oracle (example: /u01/app/oracle/product/8.1.7)" | /usr/bin/tee -a $REPORT
  read OH
  /usr/bin/echo $OH >> $REPORT
fi
if /usr/bin/test -z "$OH"
then
  /usr/bin/echo "\nALERT-  You did not provide the location that Oracle will be installed.  Setting your ORACLE_HOME to No_Location_Given" | /usr/bin/tee -a $REPORT
  OH=No_Location_Given
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi

# TRU64 VERIFICATION OF PERMISSIONS ON INPUT ORACLE_HOME

/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
/usr/bin/echo "ORACLE_HOME permission verifications" | /usr/bin/tee -a $REPORT
/usr/bin/echo "____________________________________" | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT

ALERTCOUNTPRIOR=$ALERTCOUNT
if [ $OH != "No_Location_Given" ]
then
  if /usr/bin/test -x $OH
  then
    if /usr/bin/test -r $OH
    then
      /usr/bin/echo "User $USER has read permission to $OH" | /usr/bin/tee -a $REPORT
    else
      /usr/bin/echo "ALERT: User $USER does not have read permissions for $OH" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
    if /usr/bin/test -w $OH
    then
      /usr/bin/echo "User $USER has write permission to $OH" | /usr/bin/tee -a $REPORT
    else
      /usr/bin/echo "ALERT: User $USER does not have write permissions for $OH" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
    if /usr/bin/test -x $OH
    then
      /usr/bin/echo "User $USER has execute permission to $OH" | /usr/bin/tee -a $REPORT
    else
      /usr/bin/echo "ALERT: User $USER does not have execute permissions for $OH" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    fi
  else
    /usr/bin/echo "ALERT: $OH does not exist, please create the $OH mount point and ensure the permissions are correctly set" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  fi
else
  /usr/bin/echo "ORACLE_HOME permissions cannot be verified since $OH" | /usr/bin/tee -a $REPORT
fi

if [ $ALERTCOUNTPRIOR = $ALERTCOUNT ]
then
  /usr/bin/echo "$OH has correct permissions for user $USER" | /usr/bin/tee -a $REPORT
else
  /usr/bin/echo "ALERT: The specified ORACLE_HOME=$OH does not have correct permissions.  Please have your System Administrator correct the permissions to "rwx" for the ORACLE_HOME mount point" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi

# TRU64 LIST WHAT UMASK AND UNIX ENVIRONMENT VARIABLES NEED TO BE SET

/usr/bin/echo "\n\n\nUmask Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
MASK=`/usr/bin/umask`
if [ $MASK -eq 022 ]
then
  /usr/bin/echo "umask of $MASK is set correctly \n" | /usr/bin/tee -a $REPORT
else
  /usr/bin/echo "ALERT-  umask is set to $MASK but must be set to 022 \n" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi

# TRU64 LIST OUT THE PATH, LD_LIBRARY_PATH, and SHLIB_PATH

/usr/bin/echo "\n\n\nEnvironmental Variables (as set in user $USER's environment)" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
if /usr/bin/test $ORACLE_HOME
then
  /usr/bin/echo "ORACLE_HOME=$ORACLE_HOME" | /usr/bin/tee -a $REPORT
fi
if /usr/bin/test $PATH
then
  /usr/bin/echo "PATH=$PATH" | /usr/bin/tee -a $REPORT
fi
if /usr/bin/test $LD_LIBRARY_PATH
then
  /usr/bin/echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" | /usr/bin/tee -a $REPORT
fi


/usr/bin/echo "\n\n\n.cshrc or .profile Recommended Variable Settings" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
SH=`/usr/bin/cat /etc/passwd | /usr/bin/awk -F: '{print $1, $NF}' | /usr/bin/grep -e $USER | /usr/bin/awk -F/ '{print $NF}'`
/usr/bin/echo "INFO- Your shell is $SH\n" | /usr/bin/tee -a $REPORT
if [ "$SH" = csh ]
then
  /usr/bin/echo "The following environment variables must be set in your .cshrc file for the $USER user." | /usr/bin/tee -a $REPORT
  /usr/bin/echo "setenv ORACLE_HOME $OH" | /usr/bin/tee -a $REPORT
  /usr/bin/echo "setenv LD_LIBRARY_PATH $OH/lib" | /usr/bin/tee -a $REPORT
  /usr/bin/echo "setenv PATH $OH/bin:/usr/ccs/bin:/etc:$PATH" | /usr/bin/tee -a $REPORT
else
  /usr/bin/echo "The following environment variables must be set in your .profile file for the $USER user." | /usr/bin/tee -a $REPORT
  /usr/bin/echo "ORACLE_HOME=$OH" | /usr/bin/tee -a $REPORT
  /usr/bin/echo "LD_LIBRARY_PATH=$OH/lib" | /usr/bin/tee -a $REPORT
  /usr/bin/echo "PATH=$OH/bin:$PATH" | /usr/bin/tee -a $REPORT
  /usr/bin/echo "export \$ORACLE_HOME" | /usr/bin/tee -a $REPORT
  /usr/bin/echo "export \$LD_LIBRARY_PATH" | /usr/bin/tee -a $REPORT
  /usr/bin/echo "export \$PATH" | /usr/bin/tee -a $REPORT
fi

if [ "$OH" = "No_Location_Given" ]
then
  /usr/bin/echo "\nALERT- When running this script you did not provide a location where Oracle will be installed.  Change the value of No_Location_Given to the location where Oracle will be installed in." | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi


# TRU64 /tmp SPACE VERIFICATION

/usr/bin/echo "\n \n \nTMP space Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_______________________\n" | /usr/bin/tee -a $REPORT
/usr/bin/echo "FYI: The runInstaller (OUI) uses/checks for temporary space by checking first for the TEMP environmental variable, then the TMP environmental variable and lastly the actual '/tmp' mount point" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_______________________\n" | /usr/bin/tee -a $REPORT
TMPMT=`/usr/bin/df -k /tmp | /usr/bin/awk '{print $4}' |  /usr/bin/sed '1d'`
TMPMT=`/usr/bin/expr $TMPMT / 1024`
if [ `/usr/bin/env | /usr/bin/grep -ic "TEMP="` -ne 0 ]
then
 TEMPLOC=`/usr/bin/env | /usr/bin/grep "TEMP=" | /usr/bin/awk -F= '{print $2}'`
 if /usr/bin/test -d $TEMPLOC
 then
   TEMP=`/usr/bin/df -k "$TEMPLOC" | /usr/bin/awk '{print $4}' | /usr/bin/sed '1d'`
   TEMP=`/usr/bin/expr $TEMP / 1024`
   /usr/bin/echo "The TEMP variable was found set in your environment and has $TEMP Mb of free space" | /usr/bin/tee -a $REPORT
 else
   /usr/bin/echo "ALERT- The TEMP variable was found set in your environment but is either an invalid value or is not a directory.  Please set TEMP correctly or to a valid, writable directory or unset if the InstallPrep determines you have adequate space in /tmp" | /usr/bin/tee -a $REPORT
   ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
 fi
elif [ `/usr/bin/env | /usr/bin/grep -ic "TMP="` -ne 0 ]
then
  TMPLOC=`/usr/bin/env | /usr/bin/grep "TMP=" | /usr/bin/awk -F= '{print $2}'`
  if /usr/bin/test -d "$TMPLOC"
  then
    TMP=`/usr/bin/df -k "$TMPLOC" | /usr/bin/awk '{print $4}' | /usr/bin/sed '1d'`
    TMP=`/usr/bin/expr $TMP / 1024`
    /usr/bin/echo "The TMP variable was found set in your environment and has $TMP Mb of free space" | /usr/bin/tee -a $REPORT
  else 
    /usr/bin/echo "ALERT- The TMP variable was found set in your environment but is either an invalid value or is not a directory.  Please set TMP correctly or to a valid, writable directory or unset if the InstallPrep determines you have adequate space in /tmp" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  fi
fi
case $ORAVER in
  "805"|"806")
     if /usr/bin/test -n "$TEMP"
     then 
       if [ $TEMP -lt 40 ]
       then
         /usr/bin/echo "ALERT- TEMP is set in the environment and has less than the required 40 Mb.  Please point the TEMP environmental variable to a mount point with at least 40 Mb of free space" | /usr/bin/tee -a $REPORT 
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TEMPLOC"
         then
           /usr/bin/echo "TEMP has adequate space of $TEMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TEMP is set in the environment; however, $TEMPLOC does not have write permissions for user $USER" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMP"
     then
       if [ $TMP -lt 40 ]
       then
         /usr/bin/echo "ALERT- TMP is set in the environment and has less than the required 40 Mb.  Please point the TMP environmental variable to a mount point with at least 40 Mb of free space" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TMPLOC"
         then
           /usr/bin/echo "TMP has adequate space of $TMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TMP is set in the environment; however, $TMPLOC does not have write permissions for user $USER" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMPMT"
     then
       if [ $TMPMT -lt 40 ]
       then
         /usr/bin/echo "ALERT- /tmp space = $TMPMT Mb, please increase /tmp to at least 40 Mb\n" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         /usr/bin/echo "/tmp has adequate space of $TMPMT Mb\n" | /usr/bin/tee -a $REPORT
       fi
     else
       /usr/bin/echo "ALERT-  /tmp is not specified\n" | /usr/bin/tee -a $REPORT
       ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
     fi
     ;;
   "815"|"816"|"817")
     if /usr/bin/test -n "$TEMP"
     then 
       if [ $TEMP -lt 75 ]
       then
         /usr/bin/echo "ALERT- TEMP is set in the environment and has less than the required 75 Mb.  Please point the TEMP environmental variable to a mount point with at least 75 Mb of free space" | /usr/bin/tee -a $REPORT 
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TEMPLOC"
         then
           /usr/bin/echo "TEMP has adequate space of $TEMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TEMP is set in the environment; however, $TEMPLOC does not have write permissions for user $USER" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMP"
     then
       if [ $TMP -lt 75 ]
       then
         /usr/bin/echo "ALERT- TMP is set in the environment and has less than the required 75 Mb.  Please point the TMP environmental variable to a mount point with at least 75 Mb of free space" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TMPLOC"
         then
           /usr/bin/echo "TMP has adequate space of $TMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TMP is set in the environment; however, $TMPLOC does not have write permissions for user $USER" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMPMT"
     then
       if [ $TMPMT -lt 75 ]
       then
         /usr/bin/echo "ALERT- /tmp space = $TMPMT Mb, please increase /tmp to at least 75 Mb\n" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         /usr/bin/echo "/tmp has adequate space of $TMPMT Mb\n" | /usr/bin/tee -a $REPORT
       fi
     else
       /usr/bin/echo "ALERT-  /tmp is not specified\n" | /usr/bin/tee -a $REPORT
       ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
     fi
     ;;
   "901"|"920")
     if /usr/bin/test -n "$TEMP"
     then 
       if [ $TEMP -lt 400 ]
       then
         /usr/bin/echo "ALERT- TEMP is set in the environment and has less than the required 400 Mb.  Please point the TEMP environmental variable to a mount point with at least 400 Mb of free space" | /usr/bin/tee -a $REPORT 
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TEMPLOC"
         then
           /usr/bin/echo "TEMP has adequate space of $TEMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TEMP is set in the environment; however, $TEMPLOC does not have write permissions for user $USER" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMP"
     then
       if [ $TMP -lt 400 ]
       then
         /usr/bin/echo "ALERT- TMP is set in the environment and has less than the required 400 Mb.  Please point the TMP environmental variable to a mount point with at least 400 Mb of free space" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         if /usr/bin/test -w "$TMPLOC"
         then
           /usr/bin/echo "TMP has adequate space of $TMP Mb\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "ALERT- TMP is set in the environment; however, $TMPLOC does not have write permissions for user $USER" | /usr/bin/tee -a $REPORT
           ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         fi
       fi
     elif /usr/bin/test -n "$TMPMT"
     then
       if [ $TMPMT -lt 400 ]
       then
         /usr/bin/echo "ALERT- /tmp space = $TMPMT Mb, please increase /tmp to at least 400 Mb\n" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
       else
         /usr/bin/echo "/tmp has adequate space of $TMPMT Mb\n" | /usr/bin/tee -a $REPORT
       fi
     else
       /usr/bin/echo "ALERT-  /tmp is not specified\n" | /usr/bin/tee -a $REPORT
       ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
     fi
     ;;
    *)
     /usr/bin/echo ""
     ;;
esac


# TRU64 SWAP SPACE VERIFICATION

/usr/bin/echo "\n\n\nSwap Space Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
if /usr/bin/test -x /sbin/swapon
then
  SWAP=`/sbin/swapon -s | /usr/bin/grep -w 'Allocated space:' | /usr/bin/sed -n '$p' |  /usr/bin/awk -F \( '{print $2}' |  /usr/bin/sed 's/G/ G /' | /usr/bin/sed 's/M/ M /' | /usr/bin/awk '{print $1}'` 
  SWAP=`/usr/bin/echo $SWAP | /usr/bin/awk '{print int($1)}'` 
  SWAPGIGORMEG=`/sbin/swapon -s | /usr/bin/grep -w 'Allocated space:' | /usr/bin/sed -n '$p' |  /usr/bin/awk -F \( '{print $2}' |  /usr/bin/sed 's/G/ G /' | /usr/bin/sed 's/M/ M /' | /usr/bin/awk '{print $2}'`
  if /usr/bin/test -z "$SWAP"
  then 
    /usr/bin/echo "ALERT- SWAP has not been setup or specified" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1` 
  elif [ $SWAPGIGORMEG = G ]
  then
    SWAP=`/usr/bin/expr "$SWAP" \* 1024`
    /usr/bin/echo "Swap is $SWAP Mb\n" | /usr/bin/tee -a $REPORT
  else
    /usr/bin/echo "Swap is $SWAP Mb\n" | /usr/bin/tee -a $REPORT
  fi
else 
  /usr/bin/echo "ALERT- Your Swap cannot be determined due to user $USER not having execute priviledge to run /sbin/swapon, please have your System Administrator grant execute permission on /sbin/swapon or have them do '/sbin/swapon -s | /usr/bin/grep -w 'Allocated space:' to determine the amount of Swap" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi

# TRU64 MEMORY VERIFICATION

/usr/bin/echo "\n\n\nMemory Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "___________________\n" | /usr/bin/tee -a $REPORT
MEM=`/usr/bin/vmstat -P | /usr/bin/grep -i 'Total Physical Memory = ' | /usr/bin/awk -F = '{print $NF}'| /usr/bin/awk -F. '{print $1}'`
TWOM=`/usr/bin/expr $MEM \* 2`
if [ $ORAVER = "805" -o $ORAVER = "806" -o $ORAVER = "815" -o $ORAVER = "816" -o $ORAVER = "817" ]
then
  if [ $MEM -lt 128 ]
  then
    /usr/bin/echo "ALERT-  $MEM Mb of memory is not enough to install Oracle $ORAVER.  You must have at least 128 Mb\n" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "$MEM Mb of memory is adequate to install Oracle $ORAVER\n" | /usr/bin/tee -a $REPORT
  fi
elif [ $ORAVER = "901" ]
then
  if [ $MEM -lt 255 ]
  then
    /usr/bin/echo "ALERT-  $MEM Mb of memory is not enough to install Oracle $ORAVER.  You must have at least 256 Mb\n" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "$MEM Mb of memory is adequate to install Oracle $ORAVER\n" | /usr/bin/tee -a $REPORT
  fi
elif [ $ORAVER = "920" ]
then
  if [ $MEM -lt 511 ]
  then
    /usr/bin/echo "ALERT-  $MEM Mb of memory is not enough to install Oracle $ORAVER.  You must have at least 512 Mb\n" | /usr/bin/tee -a $REPORT
    ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
  else
    /usr/bin/echo "$MEM Mb of memory is adequate to install Oracle $ORAVER\n" | /usr/bin/tee -a $REPORT
  fi
fi

/usr/bin/echo "\n\n\nChecking Swap to Memory Ratio" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_________________________\n" | /usr/bin/tee -a $REPORT
if /usr/bin/test $SWAP
then
  if [ $ORAVER = "805" -o $ORAVER = "806" -o $ORAVER = "815" -o $ORAVER = "816" -o $ORAVER = "817" ]
  then
    if [ $MEM -le 512 ]
    then 
      if [ $SWAP -lt $THREM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $THREM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb\n" | /usr/bin/tee -a $REPORT
      fi
    elif [ $MEM -gt 512 -a $MEM -lt 1024 ]
    then
      if [ $SWAP -lt $TWOM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $TWOM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb\n" | /usr/bin/tee -a $REPORT
      fi
    elif [ $MEM -ge 1024 ]
    then
      if [ $SWAP -lt $MEM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $MEM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb\n" | /usr/bin/tee -a $REPORT
      fi
    fi
  elif [ $ORAVER = "901" ] 
  then
    if [ $MEM -le 1024 ]
    then
      if [ $SWAP -lt $TWOM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $TWOM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb.\n" | /usr/bin/tee -a $REPORT
      fi
    elif [ $MEM -gt 1024 ]
    then
      if [ $SWAP -lt $MEM ]
      then
        /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $MEM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb.\n" | /usr/bin/tee -a $REPORT
      fi
    fi
  elif [ $ORAVER = "920" ] 
  then
    if [ $SWAP -lt 1024 ]
    then
      /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least 1Gb.\n" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $SWAP -lt $MEM ]
    then
      /usr/bin/echo "ALERT-  You must increase your swap space from $SWAP Mb to at least $MEM Mb since you have $MEM Mb of RAM.\n" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
        /usr/bin/echo "You have adequate Swap of $SWAP Mb for your Physical Memory of $MEM Mb.\n" | /usr/bin/tee -a $REPORT
    fi
  fi 
else
  /usr/bin/echo "ALERT- A Swap to Memory ratio cannot be determined because swap has not been setup or user $USER does not have execute permission to determine swap" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
fi 

# TRU64 ASSEMBLY TOOL VERIFICATION

/usr/bin/echo "\n \n \nAssembly Tool Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________\n" | /usr/bin/tee -a $REPORT

arvalue=`/usr/bin/which ar`
if [ "$arvalue" != "/usr/ccs/bin/ar" ]
then
  /usr/bin/echo "WARNING-  ar not found in /usr/ccs/bin directory but was found in '$arvalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /usr/bin/echo "ar - found correctly in /usr/ccs/bin" | /usr/bin/tee -a $REPORT
fi

ldvalue=`/usr/bin/which ld`
if [ "$ldvalue" != "/usr/ccs/bin/ld" ]
then
  /usr/bin/echo "WARNING-  ld not found in /usr/ccs/bin directory but was found in '$ldvalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /usr/bin/echo "ld - found correctly in /usr/ccs/bin" | /usr/bin/tee -a $REPORT
fi

nmvalue=`/usr/bin/which nm`
if [ "$nmvalue" != "/usr/ccs/bin/nm" ]
then
  /usr/bin/echo "WARNING-  nm not found in /usr/ccs/bin directory but was found in '$nmvalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /usr/bin/echo "nm - found correctly in /usr/ccs/bin" | /usr/bin/tee -a $REPORT
fi

makevalue=`/usr/bin/which make`
if [ "$makevalue" != "/usr/ccs/bin/make" ]
then
  /usr/bin/echo "WARNING-  make not found in /usr/ccs/bin directory but was found in '$makevalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /usr/bin/echo "make - found correctly in /usr/ccs/bin" | /usr/bin/tee -a $REPORT
fi

ccvalue=`/usr/bin/which cc`
if [ "$ccvalue" != "/usr/ccs/bin/cc" ]
then
  /usr/bin/echo "WARNING-  cc not found in /usr/ccs/bin directory but was found in '$ccvalue'" | /usr/bin/tee -a $REPORT
  WARNINGCOUNT=`/usr/bin/expr $WARNINGCOUNT + 1`
else
  /usr/bin/echo "cc - found correctly in /usr/ccs/bin" | /usr/bin/tee -a $REPORT
fi

# TRU64 ULIMIT VERIFICATION

/usr/bin/echo "\n \n \nVerification of ulimits" | /usr/bin/tee -a $REPORT
/usr/bin/echo "_______________________________\n" | /usr/bin/tee -a $REPORT

TIMERAW=`/usr/bin/ulimit -t`
TIME=`/usr/bin/ulimit -t | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$TIME"
then
  /usr/bin/echo "ALERT- ulimit(TIME) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $TIME -lt 1000000000 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(TIME) to unlimited from the present $TIMERAW" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(TIME) set to $TIMERAW is adequate" | /usr/bin/tee -a $REPORT
fi

FILERAW=`/usr/bin/ulimit -f`
FILE=`/usr/bin/ulimit -f | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$FILE"
then
  /usr/bin/echo "ALERT- ulimit(FILE) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $FILE -lt 1000000000 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(FILE) to unlimited from the present $FILERAW" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(FILE) set to $FILERAW is adequate" | /usr/bin/tee -a $REPORT
fi

DATARAW=`/usr/bin/ulimit -d`
DATA=`/usr/bin/ulimit -d | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$DATA"
then
  /usr/bin/echo "ALERT- ulimit(DATA) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $DATA -lt 1572864 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(DATA) to 1572864 from the present $DATARAW" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(DATA) set to $DATARAW is adequate" | /usr/bin/tee -a $REPORT
fi

STACKRAW=`/usr/bin/ulimit -s`
STACK=`/usr/bin/ulimit -s | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$STACK"
then
  /usr/bin/echo "ALERT- ulimit(STACK) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $STACK -lt 2048 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(STACK) to 2048 from the present $STACKRAW" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(STACK) set to $STACKRAW is adequate" | /usr/bin/tee -a $REPORT
fi

NOFILESRAW=`/usr/bin/ulimit -n`
NOFILES=`/usr/bin/ulimit -n | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$NOFILES"
then
  /usr/bin/echo "ALERT- ulimit(NOFILES) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $NOFILES -lt 4096 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(NOFILES) to 4096 from the present $NOFILESRAW" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(NOFILES) set to $NOFILESRAW is adequate" | /usr/bin/tee -a $REPORT
fi

MEMORYRAW=`/usr/bin/ulimit -m`
MEMORY=`/usr/bin/ulimit -m | /usr/bin/sed 's/unlimited/1000000000/'`
if /usr/bin/test -z "$MEMORY"
then
  /usr/bin/echo "ALERT- ulimit(MEMORY) has not been defined" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
elif [ $MEMORY -lt 1000000000 ]
then
  /usr/bin/echo "ALERT-  Increase the ulimit(MEMORY) to unlimited from the present $MEMORY" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
else
  /usr/bin/echo "ulimit(MEMORY) set to $MEMORYRAW is adequate" | /usr/bin/tee -a $REPORT
fi

#VMEMORYRAW=`/usr/bin/ulimit -v`
#VMEMORY=`/usr/bin/ulimit -v | /usr/bin/sed 's/unlimited/1000000000/'`
#if /usr/bin/test -z "$VMEMORY"
#  then
#    /usr/bin/echo "ALERT- ulimit(VMEMORY) has not been defined" | /usr/bin/tee -a $REPORT
#elif [ $VMEMORY -lt 1000000000 ]
#  then
#    /usr/bin/echo "ALERT-  Increase the ulimit(VMEMORY) to unlimited from the present $VMEMORY" | /usr/bin/tee -a $REPORT
#  else
#    /usr/bin/echo "ulimit(VMEMORY) set to $VMEMORYRAW is adequate" | /usr/bin/tee -a $REPORT
#fi


# TRU64 CERTIFICATION VERIFICATION

/usr/bin/echo "\n \n \nCertification of Oracle and OS Version Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________________________________________\n" | /usr/bin/tee -a $REPORT
case $OSVER in
      "4.0d"|"4.0D"|"4.0e"|"4.0E"|"4.0f"|"4.0F"|"4.0g"|"4.0G"|"5.0")
         if [ $ORAVER = "805" -o $ORAVER = "806" -o $ORAVER = "815" -o $ORAVER = "816" -o $ORAVER = "817" ]
         then
           /usr/bin/echo "$OS $OSVER is certified to run Oracle $ORAVER\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER is not certified to run Oracle $ORAVER\n" | /usr/bin/tee -a $REPORT
           SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
         fi        
         ;;
      "5.0a"|"5.0A")
         if [ $ORAVER = "805" -o $ORAVER = "806" -o $ORAVER = "815" -o $ORAVER = "816" -o $ORAVER = "817" -o $ORAVER = "901" ]
         then
           /usr/bin/echo "$OS $OSVER is certified to run Oracle $ORAVER\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "!!SHOWSTOPPER!!  $OS $OSVER is not certified to run Oracle $ORAVER\n" | /usr/bin/tee -a $REPORT
           SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
         fi
         ;;
      "5.1")
         if [ $ORAVER = "806" -o $ORAVER = "815" -o $ORAVER = "816" -o $ORAVER = "817" -o $ORAVER = "901" -o $ORAVER = "920" ]
         then
           /usr/bin/echo "$OS $OSVER is certified to run Oracle $ORAVER\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "!!SHOWSTOPPER!!  Oracle $ORAVER is not certified to run on $OS $OSVER\n" | /usr/bin/tee -a $REPORT
           SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
         fi
         ;;
      "5.1A"|"5.1a")
         if [ $ORAVER = "806" -o $ORAVER = "817" -o $ORAVER = "901" -o $ORAVER = "920" ]
         then
           /usr/bin/echo "$OS $OSVER is certified to run $ORAVER\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "!!SHOWSTOPPER!!  Oracle $ORAVER is not certified to run on $OS $OSVER\n" | /usr/bin/tee -a $REPORT
           SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
         fi
         ;;
      "5.1B"|"5.1b")
         if [ $ORAVER = "817" -o $ORAVER = "901" -o $ORAVER = "920" ]
         then
           /usr/bin/echo "$OS $OSVER is certified to run $ORAVER\n" | /usr/bin/tee -a $REPORT
         else
           /usr/bin/echo "!!SHOWSTOPPER!!  Oracle $ORAVER is not certified to run on $OS $OSVER\n" | /usr/bin/tee -a $REPORT
           SHOWSTOPPERCOUNT=`/usr/bin/expr $SHOWSTOPPERCOUNT + 1`
         fi
         ;;
      *)
         /usr/bin/echo "ALERT-  The $OS OS Version was not determinable or is incorrect\n" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         ;;
esac

# TRU64 Verify OS packages are installed

/usr/bin/echo "\n \n \nOS Package Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________\n" | /usr/bin/tee -a $REPORT
/usr/bin/echo "this may take awhile.....\n" | /usr/bin/tee -a $REPORT

case $ORAVER in
  "805"|"806"|"815"|"816"|"817")
    for PACKAGE in OSFLIBA OSFPGMR OSFCMPLRS 
    do
      if [ `/usr/sbin/setld -i | /usr/bin/grep -ic $PACKAGE` = 0 ]
      then
        /usr/bin/echo "ALERT-  The $PACKAGE package needs to be installed" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "The $PACKAGE package is installed" | /usr/bin/tee -a $REPORT
      fi
    done
    ;;
"901"|"920")
    for PACKAGE in OSFLIBA OSFPGMR OSFCMPLRS OSFX11 OSFSER
    do
      if [ `/usr/sbin/setld -i | /usr/bin/grep -ic $PACKAGE` = 0 ]
      then
        /usr/bin/echo "ALERT-  The $PACKAGE package needs to be installed" | /usr/bin/tee -a $REPORT
        ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
      else
        /usr/bin/echo "The $PACKAGE package is installed" | /usr/bin/tee -a $REPORT
      fi
    done
    ;;
*)
  /usr/bin/echo ""
 ;;
esac

# TRU64 OS PATCHKIT VERIFICATION

/usr/bin/echo "\n \n \nOS Patchkit Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________________________________________\n" | /usr/bin/tee -a $REPORT
/usr/bin/echo "this will take a bit of time..." | /usr/bin/tee -a $REPORT
/usr/bin/echo " " | /usr/bin/tee -a $REPORT
case $OSVER in
      "4.0d"|"4.0D")
         if [ $ORAVER = "816" -o $ORAVER = "817" ]
         then
           if /usr/bin/test -x /usr/sbin/dupatch
           then
             if [ `/usr/sbin/dupatch -track -type kit | /usr/bin/grep -i T64V40D | /usr/bin/awk -F- '{print substr($2,length($2)-3,4)}' | /usr/bin/sort -r | /usr/bin/sed 1q` ]
             then 
               PATCHKIT=`/usr/sbin/dupatch -track -type kit | /usr/bin/grep -i T64V40D | /usr/bin/awk -F- '{print substr($2,length($2)-3,4)}' | /usr/bin/sort -r | /usr/bin/sed 1q`
               if [ $PATCHKIT -lt 4 ]
               then
                 /usr/bin/echo "ALERT-  Oracle $ORAVER on $OSVER requires patchkit 4 or higher and you are only at patchkit $PATCHKIT\n" | /usr/bin/tee -a $REPORT
                 ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
               else
                 /usr/bin/echo "Patchkit $PATCHKIT is installed and is adequate for running Oracle $ORAVER on $OSVER\n" | /usr/bin/tee -a $REPORT
               fi
             else
               /usr/bin/echo "ALERT - $USER having issues using dupatch command to determined patchkit level, have root user run '/usr/sbin/dupatch -track -type kit' to see if it is at PK4 or higher" | /usr/bin/tee -a $REPORT
               ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
             fi
           else
             /usr/bin/echo "ALERT- $USER does not have execute permission to determine patchkit that is applied, please have your System Administator allow execute to user $USER for /usr/sbin/dupatch, or have them run '/usr/sbin/dupatch -track -type kit' " | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1` 
           fi
         else
           /usr/bin/echo "No patchkit verification performed, $ORAVER on $OSVER does not require a specific patchkit" | /usr/bin/tee -a $REPORT
         fi       
         ;;
      "4.0e"|"4.0E")
         if [ $ORAVER = "816" -o $ORAVER = "817" ]
         then
           if /usr/bin/test -x /usr/sbin/dupatch
           then
             if [ `/usr/sbin/dupatch -track -type kit | /usr/bin/grep -i T64V40E | /usr/bin/awk -F- '{print substr($2,length($2)-3,4)}' | /usr/bin/sort -r | /usr/bin/sed 1q` ]
             then 
               PATCHKIT=`/usr/sbin/dupatch -track -type kit | /usr/bin/grep -i T64V40E | /usr/bin/awk -F- '{print substr($2,length($2)-3,4)}' | /usr/bin/sort -r | /usr/bin/sed 1q`
               if [ $PATCHKIT -lt 2 ]
               then
                 /usr/bin/echo "ALERT-  Oracle $ORAVER on $OSVER requires patchkit 2 or higher and you are only at patchkit $PATCHKIT\n" | /usr/bin/tee -a $REPORT
                 ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
               else
                 /usr/bin/echo "Patchkit $PATCHKIT is installed and is adequate for running Oracle $ORAVER on $OSVER\n" | /usr/bin/tee -a $REPORT
               fi
             else
               /usr/bin/echo "ALERT - $USER having issues using dupatch command to determined patchkit level, have root user run '/usr/sbin/dupatch -track -type kit' to see if it is at PK2 or higher" | /usr/bin/tee -a $REPORT
               ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
             fi 
           else
             /usr/bin/echo "ALERT- User $USER does not have execute permission to determine patchkit that is applied, please have your System Administator allow execute to user $USER for /usr/sbin/dupatch, or have them run '/usr/sbin/dupatch -track -type kit' " | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1` 
           fi
         else
           /usr/bin/echo "No patchkit verification performed, $ORAVER on $OSVER does not require a specific patchkit" | /usr/bin/tee -a $REPORT
         fi       
         ;;
      "4.0f"|"4.0F")
         if [ $ORAVER = "816" -o $ORAVER = "817" ]
         then
           if /usr/bin/test -x /usr/sbin/dupatch
           then
             if [ `/usr/sbin/dupatch -track -type kit | /usr/bin/grep -i T64V40F | /usr/bin/awk -F- '{print substr($2,length($2)-3,4)}' | /usr/bin/sort -r | /usr/bin/sed 1q` ]
             then 
               PATCHKIT=`/usr/sbin/dupatch -track -type kit | /usr/bin/grep -i T64V40F | /usr/bin/awk -F- '{print substr($2,length($2)-3,4)}' | /usr/bin/sort -r | /usr/bin/sed 1q`
               if [ $PATCHKIT -lt 1 ]
               then
                 /usr/bin/echo "ALERT-  Oracle $ORAVER on $OSVER requires patchkit 1 or higher and you are only at patchkit $PATCHKIT\n" | /usr/bin/tee -a $REPORT
                 ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
               else
                 /usr/bin/echo "Patchkit $PATCHKIT is installed and is adequate for running Oracle $ORAVER on $OSVER\n" | /usr/bin/tee -a $REPORT
               fi 
             else
               /usr/bin/echo "ALERT - $USER having issues using dupatch command to determined patchkit level, have root user run '/usr/sbin/dupatch -track -type kit' to see if it is at PK1 or higher" | /usr/bin/tee -a $REPORT
               ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
             fi 
           else
             /usr/bin/echo "ALERT- User $USER does not have execute permission to determine patchkit that is applied, please have your System Administator allow execute to user $USER for /usr/sbin/dupatch, or have them run '/usr/sbin/dupatch -track -type kit' " | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1` 
           fi
         else
           /usr/bin/echo "No patchkit verification performed, $ORAVER on $OSVER does not require a specific patchkit" | /usr/bin/tee -a $REPORT
         fi       
         ;;

      "5.0a"|"5.0A")
         if [ $ORAVER = "901" ]
         then
           if /usr/bin/test -x /usr/sbin/dupatch
           then
             if [ `/usr/sbin/dupatch -track -type kit | /usr/bin/grep -i T64V50A | /usr/bin/awk -F- '{print substr($2,length($2)-3,4)}' | /usr/bin/sort -r | /usr/bin/sed 1q` ]
             then 
               PATCHKIT=`/usr/sbin/dupatch -track -type kit | /usr/bin/grep -i T64V50A | /usr/bin/awk -F- '{print substr($2,length($2)-3,4)}' | /usr/bin/sort -r | /usr/bin/sed 1q`
               if [ $PATCHKIT -lt 4 ]
               then
                 /usr/bin/echo "ALERT-  Oracle $ORAVER on $OSVER requires patchkit 4 or higher and you are only at patchkit $PATCHKIT\n" | /usr/bin/tee -a $REPORT
                 ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
               else
                 /usr/bin/echo "Patchkit $PATCHKIT is installed and is adequate for running Oracle $ORAVER on $OSVER\n" | /usr/bin/tee -a $REPORT
               fi 
             else
               /usr/bin/echo "ALERT - $USER having issues using dupatch command to determined patchkit level, have root user run '/usr/sbin/dupatch -track -type kit' to see if it is at PK4 or higher" | /usr/bin/tee -a $REPORT
               ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
             fi 
           else
             /usr/bin/echo "ALERT- User $USER does not have execute permission to determine patchkit that is applied, please have your System Administator allow execute to user $USER for /usr/sbin/dupatch, or have them run '/usr/sbin/dupatch -track -type kit' " | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1` 
           fi
         else
           /usr/bin/echo "No patchkit verification performed, $ORAVER on $OSVER does not require a specific patchkit" | /usr/bin/tee -a $REPORT
         fi       
         ;;

      "5.1")
         if [ $ORAVER = "901" ]
         then
           if /usr/bin/test -x /usr/sbin/dupatch
           then
             if [ `/usr/sbin/dupatch -track -type kit | /usr/bin/grep -i T64V51 | /usr/bin/awk -F- '{print substr($2,length($2)-3,4)}' | /usr/bin/sort -r | /usr/bin/sed 1q` ]
             then 
               PATCHKIT=`/usr/sbin/dupatch -track -type kit | /usr/bin/grep -i T64V51 | /usr/bin/awk -F- '{print substr($2,length($2)-3,4)}' | /usr/bin/sort -r | /usr/bin/sed 1q`
               if [ $PATCHKIT -lt 4 ]
               then
                 /usr/bin/echo "ALERT-  Oracle $ORAVER on $OSVER requires patchkit 4 or higher and you are only at patchkit $PATCHKIT\n" | /usr/bin/tee -a $REPORT
                 ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
               else
                 /usr/bin/echo "Patchkit $PATCHKIT is installed and is adequate for running Oracle $ORAVER on $OSVER\n" | /usr/bin/tee -a $REPORT
               fi 
             else
               /usr/bin/echo "ALERT - $USER having issues using dupatch command to determined patchkit level, have root user run '/usr/sbin/dupatch -track -type kit' to see if it is at PK4 or higher" | /usr/bin/tee -a $REPORT
               ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
             fi
           else
             /usr/bin/echo "ALERT- User $USER does not have execute permission to determine patchkit that is applied, please have your System Administator allow execute to user $USER for /usr/sbin/dupatch, or have them run '/usr/sbin/dupatch -track -type kit' " | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1` 
           fi
         else
           /usr/bin/echo "No patchkit verification performed, $ORAVER on $OSVER does not require a specific patchkit" | /usr/bin/tee -a $REPORT
         fi    
         ;;
     "5.1a"|"5.1A")
         if [ $ORAVER = "920" ]
         then
           if /usr/bin/test -x /usr/sbin/dupatch
           then
             if [ `/usr/sbin/dupatch -track -type kit | /usr/bin/grep -i T64V51A | /usr/bin/awk -F- '{print substr($2,length($2)-3,4)}' | /usr/bin/sort -r | /usr/bin/sed 1q` ]
             then
               PATCHKIT=`/usr/sbin/dupatch -track -type kit | /usr/bin/grep -i T64V51A | /usr/bin/awk -F- '{print substr($2,length($2)-3,4)}' | /usr/bin/sort -r | /usr/bin/sed 1q`
               if [ $PATCHKIT -lt 6 ]
               then
                 /usr/bin/echo "ALERT-  Oracle $ORAVER on $OSVER requires patchkit 6 or higher and you are only at patchkit $PATCHKIT\n" | /usr/bin/tee -a $REPORT
                 ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
               else
                 /usr/bin/echo "Patchkit $PATCHKIT is installed and is adequate for running Oracle $ORAVER on $OSVER\n" | /usr/bin/tee -a $REPORT
               fi 
             else
               /usr/bin/echo "ALERT - $USER having issues using dupatch command to determined patchkit level, have root user run '/usr/sbin/dupatch -track -type kit' to see if it is at PK1 or higher" | /usr/bin/tee -a $REPORT
               ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
             fi
           else
             /usr/bin/echo "ALERT- User $USER does not have execute permission to determine patchkit that is applied, please have your System Administator allow execute to user $USER for /usr/sbin/dupatch, or have them run '/usr/sbin/dupatch -track -type kit' " | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1` 
           fi
         else
           /usr/bin/echo "No patchkit verification performed, $ORAVER on $OSVER does not require a specific patchkit" | /usr/bin/tee -a $REPORT
         fi
         ;;
     "5.1b"|"5.1B")
         if [ $ORAVER = "817" -o $ORAVER = "901" ]
         then
           if /usr/bin/test -x /usr/sbin/dupatch
           then
             if [ `/usr/sbin/dupatch -track -type kit | /usr/bin/grep -i T64V51B | /usr/bin/awk -F- '{print substr($2,length($2)-3,4)}' | /usr/bin/sort -r | /usr/bin/sed 1q` ]
             then
               PATCHKIT=`/usr/sbin/dupatch -track -type kit | /usr/bin/grep -i T64V51B | /usr/bin/awk -F- '{print substr($2,length($2)-3,4)}' | /usr/bin/sort -r | /usr/bin/sed 1q`
               if [ $PATCHKIT -lt 2 ]
               then
                 /usr/bin/echo "ALERT-  Oracle $ORAVER on $OSVER requires patchkit 2 or higher and you are only at patchkit $PATCHKIT\n" | /usr/bin/tee -a $REPORT
                 ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
               else
                 /usr/bin/echo "Patchkit $PATCHKIT is installed and is adequate for running Oracle $ORAVER on $OSVER\n" | /usr/bin/tee -a $REPORT
               fi  
             else
               /usr/bin/echo "ALERT - $USER having issues using dupatch command to determined patchkit level, have root user run '/usr/sbin/dupatch -track -type kit' to see if it is at PK2 or higher" | /usr/bin/tee -a $REPORT
               ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
             fi
           else
             /usr/bin/echo "ALERT- User $USER does not have execute permission to determine patchkit that is applied, please have your System Administator allow execute to user $USER for /usr/sbin/dupatch, or have them run '/usr/sbin/dupatch -track -type kit' " | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1` 
           fi
         elif [ $ORAVER = "920" ]
         then
           if /usr/bin/test -x /usr/sbin/dupatch
           then
             if [ `/usr/sbin/dupatch -track -type kit | /usr/bin/grep -i T64V51B | /usr/bin/awk -F- '{print substr($2,length($2)-3,4)}' | /usr/bin/sort -r | /usr/bin/sed 1q` ]
             then
               PATCHKIT=`/usr/sbin/dupatch -track -type kit | /usr/bin/grep -i T64V51B | /usr/bin/awk -F- '{print substr($2,length($2)-3,4)}' | /usr/bin/sort -r | /usr/bin/sed 1q`
               if [ $PATCHKIT -lt 4 ]
               then
                 /usr/bin/echo "ALERT-  Oracle $ORAVER on $OSVER requires patchkit 4 or higher and you are only at patchkit $PATCHKIT\n" | /usr/bin/tee -a $REPORT
                 ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
               else
                 /usr/bin/echo "Patchkit $PATCHKIT is installed and is adequate for running Oracle $ORAVER on $OSVER\n" | /usr/bin/tee -a $REPORT
               fi  
             else
               /usr/bin/echo "ALERT - $USER having issues using dupatch command to determined patchkit level, have root user run '/usr/sbin/dupatch -track -type kit' to see if it is at PK2 or higher" | /usr/bin/tee -a $REPORT
               ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
             fi
           else
             /usr/bin/echo "ALERT- User $USER does not have execute permission to determine patchkit that is applied, please have your System Administator allow execute to user $USER for /usr/sbin/dupatch, or have them run '/usr/sbin/dupatch -track -type kit' " | /usr/bin/tee -a $REPORT
             ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1` 
           fi
         else
           /usr/bin/echo "No patchkit verification performed, $ORAVER on $OSVER does not require a specific patchkit" | /usr/bin/tee -a $REPORT
         fi
         ;;
      *)
         /usr/bin/echo "ALERT-  The $OS OS Version was not determinable or is incorrect\n" | /usr/bin/tee -a $REPORT
         ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
         ;;
    esac


# TRU64 KERNEL PARAMETER VERIFICATION

/usr/bin/echo "\n \n \nUnix Kernel Verification" | /usr/bin/tee -a $REPORT
/usr/bin/echo "________________________\n" | /usr/bin/tee -a $REPORT
/usr/bin/echo "Checking Required Kernel Parameters for minimum values needed....\n"  | /usr/bin/tee -a $REPORT
/usr/bin/echo "Note-  Changes to the Unix Kernel must be performed by the root user." | /usr/bin/tee -a $REPORT
/usr/bin/echo "A system reboot is required for the kernel changes to take affect.\n" | /usr/bin/tee -a $REPORT

case $ORAVER in
  "805"|"806"|"815"|"816"|"817")
    SHMMAX=`/sbin/sysconfig -q ipc | /usr/bin/grep shm[-_]max | /usr/bin/awk -F = '{printf $2}'`
    if /usr/bin/test -z "$SHMMAX"
    then
      /usr/bin/echo "ALERT-  SHMMAX has not been defined and needs to be set to 2139095040" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $SHMMAX -lt 2139095040 ]
    then
      /usr/bin/echo "ALERT-  Increase the kernel parameter SHM-MAX to 2139095040 from present setting of $SHMMAX" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /usr/bin/echo "SHMMAX set to $SHMMAX is adequate" | /usr/bin/tee -a $REPORT
    fi
 
    SHMMIN=`/sbin/sysconfig -q ipc | /usr/bin/grep shm[-_]min | /usr/bin/awk -F = '{printf $2}'`
    if /usr/bin/test -z "$SHMMIN"
    then
      /usr/bin/echo "ALERT- SHMMIN has not been defined and needs to be set to 1" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $SHMMIN -lt 1 ]
    then
      /usr/bin/echo "ALERT- Increase the kernel parameter SHMMIN to 1 or more" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /usr/bin/echo "SHM-MIN set to $SHMMIN is adequate" | /usr/bin/tee -a $REPORT
    fi

    SHMMNI=`/sbin/sysconfig -q ipc | /usr/bin/grep shm[-_]mni | /usr/bin/awk -F = '{printf $2}'`
    if /usr/bin/test -z "$SHMMNI"
    then
      /usr/bin/echo "ALERT-  SHMMNI has not been defined and needs to be set to 100" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $SHMMNI -lt 100 ]
    then
      /usr/bin/echo "ALERT-  Increase the kernel parameter SHM-MNI to at least 100 from present setting of $SHMMNI" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1` 
    else
      /usr/bin/echo "SHM-MNI set to $SHMMNI is adequate" | /usr/bin/tee -a $REPORT
    fi
 
    SHMSEG=`/sbin/sysconfig -q ipc | /usr/bin/grep shm[-_]seg | /usr/bin/awk -F = '{printf $2}'`
    if /usr/bin/test -z "$SHMSEG"
    then
      /usr/bin/echo "ALERT-  SHMSEG has not been defined and needs to be set to 32" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $SHMSEG -lt 32 ]
    then
      /usr/bin/echo "ALERT-  Increase the kernel parameter SHM-SEG to at least 32 from present setting of $SHMSEG" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /usr/bin/echo "SHM-SEG set to $SHMSEG is adequate" | /usr/bin/tee -a $REPORT
    fi

    case $OSVER in
      "4.0d"|"4.0D"|"4.0e"|"4.0E"|"4.0f"|"4.0F"|"4.0g"|"4.0G")
    VMMAPENTRIES=`/sbin/sysconfig -q vm | /usr/bin/grep vm[-_]mapentries | /usr/bin/awk -F = '{printf $2}'`
    if /usr/bin/test -z "$VMMAPENTRIES"
    then
      /usr/bin/echo "ALERT-  vm-mapentries has not been defined and needs to be set to 1024" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $VMMAPENTRIES -lt 1024 ]
    then
      /usr/bin/echo "ALERT-  Increase the kernel parameter vm-mapentries to at least 1024 from present setting of $VMMAPENTRIES" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /usr/bin/echo "vm-mapentries set to $VMMAPENTRIES is adequate" | /usr/bin/tee -a $REPORT
    fi
    ;;
    *)
      /usr/bin/echo "vm-mapentries not checked since your OS version is $OSVER, vm-mapentries is set automatically by kernel" | /usr/bin/tee -a $REPORT
    ;;
    esac

    MAXPERPROCADDRESSSPACE=`/sbin/sysconfig -q proc | /usr/bin/grep max[-_]per[-_]proc[-_]address[-_]space | /usr/bin/awk -F = '{printf $2}'`
    if /usr/bin/test -z "$MAXPERPROCADDRESSSPACE"
    then
      /usr/bin/echo "ALERT-  max-per-proc-address-space has not been defined and needs to be set to $MEM Mb" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $MAXPERPROCADDRESSSPACE -lt $MEM ]
    then
      /usr/bin/echo "ALERT- Increase the kernel parameter max-per-proc-address-space to at least $MEM Mb from present setting of $MAXPERPROCADDRESSSPACE" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /usr/bin/echo "max-per-proc-address-space set to $MAXPERPROCADDRESSSPACE is adequate" | /usr/bin/tee -a $REPORT
    fi

    PERPROCADDRESSSPACE=`/sbin/sysconfig -q proc | /usr/bin/grep per[-_]proc[-_]address[-_]space | /usr/bin/grep -v max | /usr/bin/awk -F = '{printf $2}'`
    if /usr/bin/test -z "$PERPROCADDRESSSPACE"
    then
      /usr/bin/echo "ALERT- per-proc-address-space has not been defined and needs to be set to $MEM Mb" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $PERPROCADDRESSSPACE -lt $MEM ]
    then
      /usr/bin/echo "ALERT- Increase the kernel parameter per-proc-address-space to at least $MEM Mb from present setting of $PERPROCADDRESSSPACE" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /usr/bin/echo "per-proc-address-space set to $PERPROCADDRESSSPACE is adequate" | /usr/bin/tee -a $REPORT
    fi
    ;;
  "901"|"920")
    SHMMAX=`/sbin/sysconfig -q ipc | /usr/bin/grep shm[-_]max | /usr/bin/awk -F = '{printf $2}'`
    if /usr/bin/test -z "$SHMMAX"
    then
      /usr/bin/echo "ALERT-  SHMMAX has not been defined and needs to be set to 4278190080" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $SHMMAX -lt 4278190080 ]
    then
      /usr/bin/echo "ALERT-  Increase the kernel parameter SHM-MAX to 4278190080 from present setting of $SHMMAX" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /usr/bin/echo "SHM-MAX set to $SHMMAX is adequate" | /usr/bin/tee -a $REPORT
    fi
 
    SHMMIN=`/sbin/sysconfig -q ipc | /usr/bin/grep shm[-_]min | /usr/bin/awk -F = '{printf $2}'`
    if /usr/bin/test -z "$SHMMIN"
    then
      /usr/bin/echo "ALERT- SHMMIN has not been defined and needs to be set to 1024" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $SHMMIN -lt 1024 ]
    then
      /usr/bin/echo "ALERT- Increase the kernel parameter SHM-MIN to 1024 from present setting of $SHMMIN" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /usr/bin/echo "SHM-MIN set to $SHMMIN is adequate" | /usr/bin/tee -a $REPORT
    fi

    SHMMNI=`/sbin/sysconfig -q ipc | /usr/bin/grep shm[-_]mni | /usr/bin/awk -F = '{printf $2}'`
    if /usr/bin/test -z "$SHMMNI"
    then
      /usr/bin/echo "ALERT-  SHMMNI has not been defined and needs to be set to 256" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $SHMMNI -lt 256 ]
    then
      /usr/bin/echo "ALERT-  Increase the kernel parameter SHM-MNI to at least 256 from present setting of $SHMMNI" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /usr/bin/echo "SHM-MNI set to $SHMMNI is adequate" | /usr/bin/tee -a $REPORT
    fi
 
    SHMSEG=`/sbin/sysconfig -q ipc | /usr/bin/grep shm[-_]seg | /usr/bin/awk -F = '{printf $2}'`
    if /usr/bin/test -z "$SHMSEG"
    then
      /usr/bin/echo "ALERT-  SHMSEG has not been defined and needs to be set to 128" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $SHMSEG -lt 128 ]
    then
      /usr/bin/echo "ALERT-  Increase the kernel parameter SHM-SEG to at least 128 from present setting of $SHMSEG" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /usr/bin/echo "SHM-SEG set to $SHMSEG is adequate" | /usr/bin/tee -a $REPORT
    fi

    MAXPERPROCSTACKSIZE=`/sbin/sysconfig -q proc | /usr/bin/grep max[-_]per[-_]proc[-_]stack[-_]size | /usr/bin/awk -F = '{printf $2}'`
    if /usr/bin/test -z "$MAXPERPROCSTACKSIZE"
    then
      /usr/bin/echo "ALERT-  max-per-proc-stack-size has not been defined and needs to be set to 33554432" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $MAXPERPROCSTACKSIZE -lt 33554432 ]
    then
      /usr/bin/echo "ALERT-  Increase the kernel parameter max-per-proc-stack-size to at least 33554432 from present setting of $MAXPERPROCSTACKSIZE" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /usr/bin/echo "max-per-proc-address-space set to $MAXPERPROCSTACKSIZE is adequate" | /usr/bin/tee -a $REPORT
    fi

    PERPROCSTACKSIZE=`/sbin/sysconfig -q proc | /usr/bin/grep per[-_]proc[-_]stack[-_]size | /usr/bin/grep -v max | /usr/bin/awk -F = '{printf $2}'`
    if /usr/bin/test -z "$PERPROCSTACKSIZE"
    then
      /usr/bin/echo "ALERT- per-proc-stack-size has not been defined and needs to be set to 33554432" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $PERPROCSTACKSIZE -lt 33554432 ]
    then
      /usr/bin/echo "ALERT- Increase the kernel parameter per-proc-stack-size to at least 33554432 from present setting of $PERPROCSTACKSIZE" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /usr/bin/echo "per-proc-address-space set to $PERPROCSTACKSIZE is adequate" | /usr/bin/tee -a $REPORT
    fi

    PERPROCDATASIZE=`/sbin/sysconfig -q proc | /usr/bin/grep per[-_]proc[-_]data[-_]size | /usr/bin/grep -v max | /usr/bin/awk -F = '{printf $2}'`
    if /usr/bin/test -z "$PERPROCDATASIZE"
    then
      /usr/bin/echo "ALERT- per-proc-data-size has not been defined and needs to be set to 201326592" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $PERPROCDATASIZE -lt 201326592 ]
    then
      /usr/bin/echo "ALERT- Increase the kernel parameter per-proc-data-size to at least 201326592 from present setting of $PERPROCDATASIZE" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /usr/bin/echo "per-proc-data-space set to $PERPROCDATASIZE is adequate" | /usr/bin/tee -a $REPORT
    fi

    NEWWIREMETHOD=`/sbin/sysconfig -q vm | /usr/bin/grep new[-_]wire[-_]method | /usr/bin/grep -v max | /usr/bin/awk -F = '{printf $2}'`
    if /usr/bin/test -z "$NEWWIREMETHOD"
    then
      /usr/bin/echo "ALERT- new-wire-method has not been defined and needs to be set to 0" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $NEWWIREMETHOD -gt 0 ]
    then
      /usr/bin/echo "ALERT- Change the kernel parameter new-wire-method to 0 from present setting of $NEWWIREMETHOD, unless you are at 5.1B with Patchkit 3 and have T64KIT0021686-V51BB24-E-20040223 installed (Refer to Metalink Note: 272697.1)" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /usr/bin/echo "new-wire-method set to $NEWWIREMETHOD is adequate unless you are at 5.1B with Patchkit 3 and have T64KIT0021686-V51BB24-E-20040223 installed (Refer to Metalink Note: 272697.1)" | /usr/bin/tee -a $REPORT
    fi

    VMBIGPGENABLED=`/sbin/sysconfig -q vm | /usr/bin/grep vm[-_]bigpg[-_]enabled | /usr/bin/awk -F = '{printf $2}'`
    if /usr/bin/test -z "$VMBIGPGENABLED"
    then
      /usr/bin/echo "ALERT- vm_bigpg_enabled has not been defined and needs to be set to 0" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    elif [ $VMBIGPGENABLED -gt 0 ]
    then
      /usr/bin/echo "ALERT- Change the kernel parameter vm_bigpg_enabled to 0 from present setting of $VMBIGPGENABLED" | /usr/bin/tee -a $REPORT
      ALERTCOUNT=`/usr/bin/expr $ALERTCOUNT + 1`
    else
      /usr/bin/echo "vm_bigpg_enabled set to 0 is adequate" | /usr/bin/tee -a $REPORT
    fi

    ;;
    *)
      /usr/bin/echo ""
    ;;
esac
;;
*)
  echo "$OS is not supported by this tool or someone has changed the system name via setuname" | /usr/bin/tee -a $REPORT
;;
esac

echo "" | /usr/bin/tee -a $REPORT
echo "" | /usr/bin/tee -a $REPORT
echo "Note:" | /usr/bin/tee -a $REPORT
echo "-----" | /usr/bin/tee -a $REPORT
echo "" | /usr/bin/tee -a $REPORT
echo "If you currently have Oracle 8.1.x or Oracle 9.x already installed on this machine" | /usr/bin/tee -a $REPORT
echo "backup your ORACLE INVENTORY directory prior to installing a new version of Oracle" | /usr/bin/tee -a $REPORT
echo "Look at the /var/opt/oracle/oraInst.loc or /etc/oraInst.loc file to see where your oraInventory is located" | /usr/bin/tee -a $REPORT
echo "This is just a precaution and will help in the event problems occur on future installations" | /usr/bin/tee -a $REPORT
echo "" | /usr/bin/tee -a $REPORT
echo "" | /usr/bin/tee -a $REPORT
echo "Note:" | /usr/bin/tee -a $REPORT
echo "-----" | /usr/bin/tee -a $REPORT
echo "" | /usr/bin/tee -a $REPORT
echo "Since Oracle version 8.1.x, an Oracle Install must be executed in" | /usr/bin/tee -a $REPORT
echo "an X-window environment. A character based install is no longer available." | /usr/bin/tee -a $REPORT
echo "Regardless if you are doing a normal install or a Silent Install," | /usr/bin/tee -a $REPORT
echo "you must run the commands from a window that is capable of starting and " | /usr/bin/tee -a $REPORT
echo "running X- Window Software. If not, when you start runInstaller the " | /usr/bin/tee -a $REPORT
echo "window will not display and your installation will not start." | /usr/bin/tee -a $REPORT
echo | /usr/bin/tee -a $REPORT
echo "As a test, set your DISPLAY env variable to where the install will be" | /usr/bin/tee -a $REPORT
echo "ran from i.e." | /usr/bin/tee -a $REPORT
echo "" | /usr/bin/tee -a $REPORT
echo "sh or ksh: DISPLAY=YourClientIPaddress:0.0; export DISPLAY " | /usr/bin/tee -a $REPORT
echo "csh: setenv DISPLAY YourClientIPaddress:0.0" | /usr/bin/tee -a $REPORT
echo "" | /usr/bin/tee -a $REPORT
echo "Then run the xclock utility to see if it successfully places a clock" | /usr/bin/tee -a $REPORT
echo "on your window. If this works, then you can start the runInstaller " | /usr/bin/tee -a $REPORT

# CHECKING FOR LISTENER UP

echo "" | /usr/bin/tee -a $REPORT
echo "Listener Check" | /usr/bin/tee -a $REPORT
echo "_____________________" | /usr/bin/tee -a $REPORT
echo "" | /usr/bin/tee -a $REPORT
if [ `ps -e | grep tnslsnr | grep -v grep | wc -l` -ge 1 ]
then
  echo "ALERT: Test for listener shows it to be up, it should be down for an install - please verify" | /usr/bin/tee -a $REPORT
  ALERTCOUNT=`expr $ALERTCOUNT + 1`
else
  echo "Test for listener shows it is down" | /usr/bin/tee -a $REPORT
fi

echo "" | /usr/bin/tee -a $REPORT
echo "" | /usr/bin/tee -a $REPORT
echo "" | /usr/bin/tee -a $REPORT
echo "##############################################################################################################" | /usr/bin/tee -a $REPORT
echo "                       NOTICE" | /usr/bin/tee -a $REPORT
echo "##############################################################################################################" | /usr/bin/tee -a $REPORT
echo "Completed pre-installation check of your box" | /usr/bin/tee -a $REPORT
echo "Please review this report and resolve all ALERTS or WARNINGs before attempting to install the Oracle Database Software" | /usr/bin/tee -a $REPORT
echo "##############################################################################################################" | /usr/bin/tee -a $REPORT
echo " " | /usr/bin/tee -a $REPORT

if [ $ALERTCOUNT -gt 0 -a $SHOWSTOPPERCOUNT -eq 0 ]
then
  if [ $ALERTCOUNT -eq 1 -a $WARNINGCOUNT -eq 0 ]
  then
    echo "##########################################################################################################" | /usr/bin/tee -a $REPORT
    echo "RESULTS = There was $ALERTCOUNT ALERT to address in running the InstallPrep" | /usr/bin/tee -a $REPORT
    echo "##########################################################################################################" | /usr/bin/tee -a $REPORT
  elif [ $ALERTCOUNT -gt 1 -a $WARNINGCOUNT -eq 0 ]
  then
    echo "##########################################################################################################" | /usr/bin/tee -a $REPORT
    echo "RESULTS = There were $ALERTCOUNT ALERTs to address in running the InstallPrep" | /usr/bin/tee -a $REPORT
    echo "##########################################################################################################" | /usr/bin/tee -a $REPORT
  elif [ $ALERTCOUNT -gt 1 -a $WARNINGCOUNT -eq 1 ]
  then
    echo "##########################################################################################################" | /usr/bin/tee -a $REPORT
    echo "RESULTS = There were $ALERTCOUNT ALERTs and $WARNINGCOUNT WARNING to address in running the InstallPrep" | /usr/bin/tee -a $REPORT
    echo "##########################################################################################################" | /usr/bin/tee -a $REPORT
  elif [ $ALERTCOUNT -gt 1 -a $WARNINGCOUNT -gt 1 ]
  then
    echo "##########################################################################################################" | /usr/bin/tee -a $REPORT
    echo "RESULTS = There were $ALERTCOUNT ALERTs and $WARNINGCOUNT WARNINGS to address in running the InstallPrep" | /usr/bin/tee -a $REPORT
    echo "##########################################################################################################" | /usr/bin/tee -a $REPORT
  fi
elif [ $ALERTCOUNT -eq 0 -a $WARNINGCOUNT -eq 0 -a $SHOWSTOPPERCOUNT -eq 0 ]
then
  echo "##########################################################################################################" | /usr/bin/tee -a $REPORT
  echo "Congratulations!!! InstallPrep ran successfully on this box.  There are no issues to address." | /usr/bin/tee -a $REPORT
  echo "##########################################################################################################" | /usr/bin/tee -a $REPORT
elif [ $SHOWSTOPPERCOUNT -ge 1 ]
then
  echo "##########################################################################################################" | /usr/bin/tee -a $REPORT
  echo "                                WARNING" | /usr/bin/tee -a $REPORT
  echo "##########################################################################################################" | /usr/bin/tee -a $REPORT
  echo "There was a SHOWSTOPPER issue with either the type of media you are using or the certification of the $ORAVER being installed on $OSVER and the installation is not supported by Oracle.  Do not proceed with the installation of Oracle on your server, contact Oracle Support if you need further clarification.  Any ALERTs or WARNINGs can be ignored due to the SHOWSTOPPER issue" | /usr/bin/tee -a $REPORT
  echo "##########################################################################################################" | /usr/bin/tee -a $REPORT
fi
 

echo "" | /usr/bin/tee -a $REPORT
echo "$REPORT has been generated" | /usr/bin/tee -a $REPORT
echo "" | /usr/bin/tee -a $REPORT

cat $REPORT | egrep "ALERT|WARNING|SHOWSTOPPER" | grep -v "IMPORTANT" > $REPORTERR

echo "Do you wish to review the /tmp/InstallPrep.out file now (via more /tmp/InstallPrep.out)? (y/n)" | /usr/bin/tee -a $REPORT
read LOOKAT
case $LOOKAT in
 "y"|"Y")
     more $REPORT
     ;;
 "n"|"N"|*)
     ;;
esac