<p align="center">
    <img src="https://media.slid.es/uploads/329014/images/6449038/gopher_hat.png" alt="drawing" width="200">
</p>

# Ldapper

A GoLang tool to enumerate and abuse LDAP. Made _simple_.

Ldapper was created with for use in offensive security engagements for **_targeted_** user enumeration, group enumeration, and more. Ldapper uses familiar "net" commands such as "net user" and "net group" to perform all its queries and its output follows the same conventions. Ldapper's user interface operates as a pseudo-interactive shell, where the user can input commands until exited. All traffic goes over the LDAP(S) protocol with a singular bind to help you better blend into the network.

Ldapper is proxy aware and supports NTLM authentication with a user's hash. Additionally, this tool can perform modification actions within LDAP. More functionality is planned for later releases, but for now additional supported command functions are:

- Add Domain Computers
- Add/Remove Arbitrary SPNs

This tool should be considered in its beta stages. Please report any bugs, issues, or functionality ideas for future releases.

## Table of Contents

- [Ldapper](#ldapper)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Help](#help)
- [LDAPS Support](#ldaps-support)
- [Authentication](#authentication)
  - [Password](#password)
  - [NTLM](#ntlm)
- [Query Modules](#query-modules)
  - [Net](#net)
  - [Groups](#groups)
- [Command Modules](#command-modules)
  - [Add Computer](#add-computer)
  - [Add SPN](#add-spn)
- [Logging](#logging)
- [Proxy Support](#proxy-support)

## Installation

Ldapper can be built and ran using the following commands inside of the repository folder:

```
go mod init ldapper     - initialize the Go project
go mod tidy             - pull down all necessary dependencies
go build                - build Ldapper
./ldapper               - run Ldapper
```

## Help

```
./ldapper -h
 __    ____   __   ____  ____  ____  ____
(  )  (    \ / _\ (  _ \(  _ \(  __)(  _ \
/ (_/\ ) D (/    \ ) __/ ) __/ ) _)  )   /
\____/(____/\_/\_/(__)  (__)  (____)(__\_)
                          @SpaceManMitch96
                                @Synzack21

Usage of ./ldapper:
  -H string
    	Use NTLM authentication
  -d string
    	Domain. Only needed if using NTLM authentication.
  -dc string
    	IP address or FQDN of target DC
  -h	Display help menu
  -o string
    	Log file
  -p string
    	Password
  -s	Bind using LDAPS
  -socks4 string
    	SOCKS4 Proxy Address (ip:port)
  -socks4a string
    	SOCKS4A Proxy Address (ip:port)
  -socks5 string
    	SOCKS5 Proxy Address (ip:port)
  -u string
    	Username
    	If using password auth: 'NetBIOSName\user' (Must be in quotes or use \\)
    	If using NTLM auth: 'username'
Examples:
	With Password: 	./ldapper -u '<netbios>\username' -p <password> -dc <ip/FQDN> -s
	With Hash: 	./ldapper -u <username> -H <hash> -d <domain> -dc <ip/FQDN> -s
Tips:
	NetBIOS name can be found with 'nmblookup -A dc-ip' (Linux) or 'nbtstat /a dc-ip' (Windows)
```

# LDAPS Support

Ldapper supports the ability to bind to LDAP using either unencrypted LDAP on port 389 (default) or encrypted LDAPS on port 636 with the flag `-s`. Some of the command modules, such as adding a domain computer require using LDAPS. LDAPS is always recommended for OPSEC purposes.

# Authentication

## Password

Ldapper can be used with a username and password. This is the most common method of authentication. The username format must follow one of the below coventions:

- 'NetBIOSName\username' (in single quotes)
- NetBIOSName\\\\username (double backslash)

```
> ./ldapper -u 'overwatch\hanzo' -P "Password123!" -dc 10.10.10.101 -s
```

## NTLM

Ldapper can also authenticate with a user's NTLM hash. This method can be used with the `-H` flag. When using this authentication method, the username is input alone and the domain (-d) argument must be specified.

```
> ./ldapper -u hanzo -H OOGNKVJB2TRCYLD26H4DVPF3KBP0SG03 -dc 10.10.10.101 -d overwatch.local -s
```

# Query Modules

## Net

The net module follows the same structure as the traditional Windows net module. Currently the following commands are supported:

- `net user <user>`
- `net group <group>`
- `net nestedGroups <group>`

The command `net user` will information on a specified user in the domain, minus group memberships (see "[Groups](#groups)" module). The command `net group` will return a list of users that are members of the specified group. The `net nestedGroups` query acts similarly to the "net group" query, but searches recursively for all nested users and groups.

<sub>\*Note that the output in the "group" queries will return the "(Group)" label to distinguish users and groups. This is not part of the group name. Additionally, any groups with spaces in them will be wrapped in single quotes.</sub>

```
> net user hanzo

User Information - hanzo:
-------------------------------------------------------------------------------
User Name:              hanzo
Full Name:              Hanzo Shimada
Comment:                Test Description
User Account Control:   Enabled, Password Doesn't Expire
                        (If Enabled, Check Last Lockout Time)

Last Lockout Time:
Account Expires:        Never
Password Last Set:      02/21/2021 03:33:12 PM
Home Directory:         C:\Users\Home\Hanzo
Last logon:             07/06/2022 03:40:39 PM
```

```
> net group domain admins

Primary Group Members
-------------------------------------------------------------------------------
NestedHighPriv (Group)   jkaplan                  SQLService
Key Admins (Group)       Administrator
```

```
> net nestedGroups domain admins

Primary Group Members
-------------------------------------------------------------------------------
CLAUDINE_CARSON          MERRILL_HODGES           JESSIE_MAXWELL
NestedHighPriv (Group)   jkaplan                  SQLService
Key Admins (Group)       Administrator

Nested Group Members
-------------------------------------------------------------------------------
pharah                   NestedDA                 DoubleNested (Group)
DoubleNestedDA           RANDOLPH_WISE            HORACE_MONTGOMERY
DELMAR_MERRILL           THURMAN_HENDRICKS        SILAS_PRUITT
NORMAND_MULLINS          DORIS_PICKETT            NEWTON_HALL
DEMETRIUS_BRENNAN        MADELINE_SINGLETON       SHERRY_RIVAS
```

<sub>\* Note: nested group queries will likely result in an [expensive LDAP query](http://directoryadmin.blogspot.com/2019/10/hunting-bad-ldap-queries-on-your-dc.html), these are LDAP searches that visit a large number of entries. The default threshold for an expensive search is 10,000 entries.</sub>

## Groups

The `groups` module pulls the group memberships for an individual user. The syntax is as follows:

- `groups <targetUser>`

```
> groups hanzo

Group Memberships - hanzo:
-------------------------------------------------------------------------------
GA-gor-distlist1              BE-1415ACUAT-distlist1        TestGroup2
TestGroup
```

# Command Modules

## Add Computer

This module allows a user with the appropriate permissions to add a domain computer account to LDAP with a randomized 15 character alphanumeric password. This can be paired with the default machine account quota of 10, where any user can add up to 10 machine accounts.

```
> addComputer ldapper$
Successfully created computer account "ldapper$" with password "mT4lyPn6fh3T8XH"
```

## Add SPN

This module allows the addition of an arbitrary SPN to the target user. This requires write permissions over the target user account. Syntax is as follows:

- `spn add <targetUser> <spn value>`
- `spn delete <targetUser> <spn value>`

```
> spn add hanzo blah/blah
Successfully added SPN: "blah/blah" for user "hanzo"
```

```
> spn delete hanzo blah/blah
Successfully deleted SPN: "blah/blah" for user "hanzo"
```

# Logging

Currently, Ldapper supports logging of stdout to a specified log file. This can be called using the `-o` flag. The log file will be created in the current directory. If the log file already exists, it will be appended to.

```
./ldapper -u 'overwatch\hanzo' -P "Password123!" -dc 10.10.10.101 -s -o ldapper.log
```

# Proxy Support

Ldapper supports all SOCKS4, SOCKS4A, and SOCKS5 proxies. The proxy can be specified with the `-socks4`, `-socks4a`, and `-socks5` flags respectively. Proxy functionality is compatible with C2 frameworks such as Cobalt Strike.

```
./ldapper -u hanzo -P "Password123!" -dc 10.10.10.101 -socks4 127.0.0.1:6666 -s
 __    ____   __   ____  ____  ____  ____
(  )  (    \ / _\ (  _ \(  _ \(  __)(  _ \
/ (_/\ ) D (/    \ ) __/ ) __/ ) _)  )   /
\____/(____/\_/\_/(__)  (__)  (____)(__\_)
                          @SpaceManMitch96
                                @Synzack21

Connecting with proxy: 127.0.0.1:6666

Bind successful, dropping into shell.

>
```
