module ldapper

go 1.17

require (
	github.com/LeakIX/go-smb2 v1.2.0
	github.com/LeakIX/ntlmssp v0.0.0-20220417170740-7da3d6bf7333
	github.com/go-ldap/ldap/v3 v3.4.4
	github.com/jcmturner/gokrb5/v8 v8.4.3
	github.com/mazen160/go-random v0.0.0-20210308102632-d2b501c85c03
	golang.org/x/text v0.3.7
	h12.io/socks v1.0.3
)

require (
	github.com/Azure/go-ntlmssp v0.0.0-20220621081337-cb9428e4ac1e // indirect
	github.com/geoffgarside/ber v1.1.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.4 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa // indirect
	golang.org/x/net v0.0.0-20220725212005-46097bf591d3 // indirect
)

replace github.com/go-ldap/ldap/v3 => github.com/synzack/ldap/v3 v3.0.0-20221012132208-c2f34c0638be

replace github.com/jcmturner/gokrb5/v8 => github.com/mfdooom/gokrb5/v8 v8.4.3-0.20220930223631-56e96234d4e0
