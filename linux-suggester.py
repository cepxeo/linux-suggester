#!/usr/env python

###############################################################################################################
## [Title]: linux-suggester.py - Data gathering for Linux local infrastructure assessments
## [Author]: Sergey Egorov
## Script is based on linuxprivchecker.py created by Mike Czumak (T_v3rn1x) -- @SecuritySift
###############################################################################################################

# conditional import for older versions of python not compatible with subprocess
try:
    import subprocess as sub
    compatmode = 0 # newer version of python, no need for compatibility mode
except ImportError:
    import os # older version of python, need to use os instead
    compatmode = 1

# title / formatting
bigline = "================================================================================================="
smlline = "-------------------------------------------------------------------------------------------------"

print bigline
print "LINUX PRIVILEGE ESCALATION CHECKER"
print bigline
print

# loop through dictionary, execute the commands, store the results, return updated dict
def execCmd(cmdDict):
    for item in cmdDict:
        cmd = cmdDict[item]["cmd"]
	if compatmode == 0: # newer version of python, use preferred subprocess
            out, error = sub.Popen([cmd], stdout=sub.PIPE, stderr=sub.PIPE, shell=True).communicate()
            results = out.split('\n')
	else: # older version of python, use os.popen
	    echo_stdout = os.popen(cmd, 'r')
            results = echo_stdout.read().split('\n')
        cmdDict[item]["results"]=results
    return cmdDict

# check if any SUID file is in the list of known exploitable

def chkSuid(cmdDict):
    item = "SUIDforChk"
    print "[+] " + cmdDict[item]["msg"]
    knownBins = ['apt-get', 'apt', 'aria2c', 'ash', 'awk', 'base64', 'bash', 'binaries', 'busybox', 'cat', 'chmod', 'chown', 'cp', 'cpulimit', 'crontab', 'csh', 'curl', 'cut', 'dash', 'date', 'dd', 'diff', 'docker', 'easy_install', 'ed', 'emacs', 'env', 'expand', 'expect', 'facter', 'find', 'finger', 'flock', 'fmt', 'fold', 'ftp', 'gdb', 'git', 'grep', 'head', 'ionice', 'jjs', 'journalctl', 'jq', 'jrunscript', 'ksh', 'ld', 'less', 'ltrace', 'lua', 'mail', 'make', 'mawk', 'man', 'more', 'mount', 'mv', 'mysql', 'nano', 'nc', 'nice', 'nl', 'nmap', 'node', 'od', 'perl', 'pg', 'php', 'pico', 'pip', 'puppet', 'python', 'red', 'rlwrap', 'rpm', 'rpmquery', 'rsync', 'ruby', 'scp', 'sed', 'setarch', 'sftp', 'shuf', 'smbclient', 'socat', 'sort', 'sqlite3', 'ssh', 'stdbuf', 'strace', 'tail', 'tar', 'taskset', 'tclsh', 'tcpdump', 'tee', 'telnet', 'tftp', 'time', 'timeout', 'ul', 'unexpand', 'uniq', 'unshare', 'vi', 'vim', 'watch', 'wget', 'whois', 'wish', 'xargs', 'xxd', 'zip', 'zsh']
    print list(set(cmdDict[item]["results"]).intersection(knownBins))
    print

# print results for each previously executed command, no return value
def printResults(cmdDict):
    for item in cmdDict:
	msg = cmdDict[item]["msg"]
	results = cmdDict[item]["results"]
        print "[+] " + msg
        for result in results:
	    if result.strip() != "":
	        print "    " + result.strip()
	print
    return

def writeResults(msg, results):
    f = open("privcheckout.txt", "a");
    f.write("[+] " + str(len(results)-1) + " " + msg)
    for result in results:
        if result.strip() != "":
            f.write("    " + result.strip())
    f.close()
    return

# Basic system info
print "[*] GETTING BASIC SYSTEM INFO...\n"

results=[]

sysInfo = {"OS":{"cmd":"cat /etc/issue; cat /etc/os-release","msg":"Operating System","results":results},
	   "KERNEL":{"cmd":"cat /proc/version","msg":"Kernel","results":results},
	   "HOSTNAME":{"cmd":"hostname", "msg":"Hostname", "results":results}
	  }

sysInfo = execCmd(sysInfo)
printResults(sysInfo)

# Networking Info

print "[*] GETTING NETWORKING INFO...\n"

netInfo = {"NETINFO":{"cmd":"/sbin/ifconfig -a", "msg":"Interfaces", "results":results},
	   "ROUTE":{"cmd":"route", "msg":"Route", "results":results},
	   "NETSTAT":{"cmd":"netstat -antup | grep -v 'TIME_WAIT'", "msg":"Netstat", "results":results}
	  }

netInfo = execCmd(netInfo)
printResults(netInfo)

# File System Info
print "[*] GETTING FILESYSTEM INFO...\n"

driveInfo = {"MOUNT":{"cmd":"mount","msg":"Mount results", "results":results},
	     "FSTAB":{"cmd":"cat /etc/fstab 2>/dev/null", "msg":"fstab entries", "results":results}
	    }

driveInfo = execCmd(driveInfo)
printResults(driveInfo)

# Scheduled Cron Jobs
cronInfo = {"CRON":{"cmd":"ls -la /etc/cron* 2>/dev/null", "msg":"List cron jobs", "results":results},
	    "CRONW": {"cmd":"ls -aRl /etc/cron* 2>/dev/null | awk '$1 ~ /w.$/' 2>/dev/null", "msg":"Writable cron dirs", "results":results},
        "CRONL": {"cmd":"crontab -l 2>/dev/null", "msg":"Scheduled cron dirs for the current user", "results":results}
	   }

cronInfo = execCmd(cronInfo)
printResults(cronInfo)

# User Info
print "\n[*] ENUMERATING USER AND ENVIRONMENTAL INFO...\n"

userInfo = {"WHOAMI":{"cmd":"whoami", "msg":"Current User", "results":results},
	    "ID":{"cmd":"id","msg":"Current User ID", "results":results},
	    "ALLUSERS":{"cmd":"cat /etc/passwd  | grep -v nologin", "msg":"All users", "results":results},
	    "SUPUSERS":{"cmd":"grep -v -E '^#' /etc/passwd | awk -F: '$3 == 0{print $1}'", "msg":"Super Users Found:", "results":results},
	    "HISTORY":{"cmd":"ls -la ~/.*_history; ls -la /root/.*_history 2>/dev/null", "msg":"Root and current user history (depends on privs)", "results":results},
	    "ENV":{"cmd":"env 2>/dev/null | grep -v 'LS_COLORS'", "msg":"Environment", "results":results},
        #"SUDO":{"cmd":"sudo -l 2>/dev/null", "msg":"Sudo commands avaliable", "results":results},
	    "SUDOERS":{"cmd":"cat /etc/sudoers 2>/dev/null | grep -v '#' 2>/dev/null", "msg":"Sudoers (privileged)", "results":results},
	    "LOGGEDIN":{"cmd":"w 2>/dev/null", "msg":"Logged in User Activity", "results":results},
        "LAST20":{"cmd":"find /opt -type f -exec stat -c '%X %n' {} \; | sort -nr | awk 'NR==1,NR==20 {print $2}' | xargs ls -al {} \; 2>/dev/null", "msg":"Last 20 files accessed in /opt", "results":results},
        "UPDATEDB":{"cmd":"updatedb -o /tmp/linux-suggester.db -l 0 2>/dev/null", "msg":"Updating filesystem DB and saving to /tmp/linux-suggester.db", "results":results},
        "SUID":{"cmd":"find / -type f \( -perm -2000 -o -perm -4000 \) -exec ls -ld {} \; 2>/dev/null", "msg":"SUID/SGID Files", "results":results}
	   }

userInfo = execCmd(userInfo)
printResults(userInfo)

# File/Directory Privs
print "[*] ENUMERATING FILE AND DIRECTORY PERMISSIONS/CONTENTS...\n"

# Uncomment below if World Writable dir search required
#fdPerms = {"WWDIRSROOT":{"cmd":"find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root", "msg":"World Writeable Directories for User/Group 'Root'", "results":results},
#	   "WWDIRS":{"cmd":"find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root", "msg":"World Writeable Directories for Users other than Root", "results":results},
#	   "WWFILES":{"cmd":"find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0002 \) -exec ls -l '{}' ';' 2>/dev/null", "msg":"World Writable Files", "results":results}
#	  }

#fdPerms = execCmd(fdPerms)
#printResults(fdPerms)

fdPermChk = {"SUIDforChk":{"cmd":"find / -type f \( -perm -2000 -o -perm -4000 \) -printf '%f\n' 2>/dev/null", "msg":"SUID binaries known to be EXPLOITABLE (gtfobins.github.io)", "results":results}
            }

fdPermChk = execCmd(fdPermChk)
chkSuid(fdPermChk)


SenseFiles = {"SHADOW":{"cmd":"cat /etc/shadow 2>/dev/null", "msg":"Shadow File (Privileged)", "results":results},
        "ROOTHOME":{"cmd":"ls -la /root 2>/dev/null", "msg":"Checking if root's home folder is accessible", "results":results},
        "SSHkeys":{"cmd":"ls -ahlR /var/ssh 2>/dev/null; ls -ahlR ~/.ssh 2>/dev/null", "msg":"SSH Directories", "results":results},
        "SSHkeys":{"cmd":"cat ~/.ssh/known_hosts | cut -d ',' -f1 | cut -d ' ' -f1 | sort -u 2>/dev/null", "msg":"Known Hosts for the current user", "results":results},
        "MISCFILES":{"cmd":"locate -d /tmp/linux-suggester.db id_rsa 'initparm.cfg' '*.svn-base' 'config.php' '.git' 2>/dev/null", "msg":"Interesting files (Connect:Direct, SVN, SSH keys, php config)", "results":results},
        "UC4":{"cmd":"ls -la /var/scheduling/temp/*SMGR* 2>/dev/null", "msg":"UC4 log files at /var/scheduling/temp containing passwords", "results":results},
	    "SVNREPO":{"cmd":"locate -d /tmp/linux-suggester.db '.subversion' 2>/dev/null", "msg":"SVN property files", "results":results},
        "SOURCECODE":{"cmd":"locate -d /tmp/linux-suggester.db '*.java' '*.php' '*.c' '*.cpp' 2>/dev/null", "msg":"Source code", "results":results}
	   }

SenseFiles = execCmd(SenseFiles)
printResults(SenseFiles)

pwdFiles = {"CFGPASSWD":{"cmd":"for fil in $(locate -d /tmp/linux-suggester.db '*.pass*' *.prop*' *.sgml' '*.log' '*.conf' '*.config' '*.ini' '*.sh' | grep '/opt' 2>/dev/null); do fgrep -i passw $fil 2>/dev/null;; done", "msg":"Config files in /opt containing keyword 'password'", "results":results},
        "CONFPWDS":{"cmd":"for fil in $(locate -d /tmp/linux-suggester.db '*.pass*' *.prop*' *.sgml' '*.log' '*.c*' '*.ini' '*.sh' | grep '/etc' 2>/dev/null); do fgrep -i passw $fil 2>/dev/null;; done", "msg":"Config files in /etc containing keyword 'password'", "results":results},
        "JDBCPASSWD":{"cmd":"for fil in $(locate -d /tmp/linux-suggester.db '*.pass*' *.prop*' *.sgml' '*.log' '*.conf' '*.config' '*.ini' '*.sh' | grep '/opt' 2>/dev/null); do fgrep -i jdbc $fil 2>/dev/null; done", "msg":"Config files in /opt containing keyword 'jdbc'", "results":results},
        "JDPWDS":{"cmd":"for fil in $(locate -d /tmp/linux-suggester.db '*.pass*' *.prop*' *.sgml' '*.log' '*.c*' '*.ini' '*.sh' | grep '/etc' 2>/dev/null); do fgrep -i jdbc $fil 2>/dev/null; done", "msg":"Config files in /etc containing keyword 'jdbc'", "results":results}
	   }

pwdFiles = execCmd(pwdFiles)
printResults(pwdFiles)

# Processes and Applications
print "[*] ENUMERATING PROCESSES AND APPLICATIONS...\n"

if "debian" in sysInfo["KERNEL"]["results"][0] or "ubuntu" in sysInfo["KERNEL"]["results"][0]:
    getPkgs = "dpkg -l | awk '{$1=$4=\"\"; print $0}'" # debian
else:
    getPkgs = "rpm -qa | sort -u" # RH/other

getAppProc = {"PROCS":{"cmd":"ps aux | awk '{print $1,$2,$9,$10,$11}'", "msg":"Current processes", "results":results},
              "PKGS":{"cmd":getPkgs, "msg":"Installed Packages", "results":results}
	     }

getAppProc = execCmd(getAppProc)
# printResults(getAppProc) # comment to reduce output

otherApps = { "SUDO":{"cmd":"sudo -V | grep version 2>/dev/null", "msg":"Sudo Version (Check out http://www.exploit-db.com/search/?action=search&filter_page=1&filter_description=sudo)", "results":results},
	      "APACHE":{"cmd":"apache2 -v; apache2ctl -M; httpd -v; apachectl -l 2>/dev/null", "msg":"Apache Version and Modules", "results":results},
	      "APACHECONF":{"cmd":"cat /etc/apache2/apache2.conf 2>/dev/null", "msg":"Apache Config File", "results":results}
	    }

otherApps = execCmd(otherApps)
printResults(otherApps)

print "[*] IDENTIFYING PROCESSES AND PACKAGES RUNNING AS ROOT OR OTHER SUPERUSER...\n"

# find the package information for the processes currently running
# under root or another super user

procs = getAppProc["PROCS"]["results"]
pkgs = getAppProc["PKGS"]["results"]
supusers = userInfo["SUPUSERS"]["results"]
procdict = {} # dictionary to hold the processes running as super users

for proc in procs: # loop through each process
    relatedpkgs = [] # list to hold the packages related to a process
    try:
	for user in supusers: # loop through the known super users
	    if (user != "") and (user in proc): # if the process is being run by a super user
        	procname = proc.split(" ")[4] # grab the process name
		if "/" in procname:
			splitname = procname.split("/")
			procname = splitname[len(splitname)-1]
        	for pkg in pkgs: # loop through the packages
		    if not len(procname) < 3: # name too short to get reliable package results
	    	        if procname in pkg:
			    if procname in procdict:
			        relatedpkgs = procdict[proc] # if already in the dict, grab its pkg list
			    if pkg not in relatedpkgs:
			        relatedpkgs.append(pkg) # add pkg to the list
                procdict[proc]=relatedpkgs # add any found related packages to the process dictionary entry
    except:
	pass

for key in procdict:
    print "    " + key # print the process name
    try:
        if not procdict[key][0] == "": # only print the rest if related packages were found
            print "        Possible Related Packages: "
            for entry in procdict[key]:
                print "            " + entry # print each related package
    except:
	pass

# Discover the avaialable tools
print
print "[*] ENUMERATING INSTALLED LANGUAGES/TOOLS...\n"

devTools = {"TOOLS":{"cmd":"which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null", "msg":"Installed Tools", "results":results}}
devTools = execCmd(devTools)
printResults(devTools)

print "Don't forget to check sudo -l; /mnt; /home manually"
print "Finished"
print bigline
