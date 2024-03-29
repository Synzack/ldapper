package SecurityDescriptor

var aceTypeMap = map[int]string{
	0x00: "ACCESS_ALLOWED_ACE_TYPE",
	0x01: "ACCESS_DENIED_ACE_TYPE",
	0x02: "SYSTEM_AUDIT_ACE_TYPE",
	0x03: "SYSTEM_ALARM_ACE_TYPE",
	0x04: "ACCESS_ALLOWED_COMPOUND_ACE_TYPE",
	0x05: "ACCESS_ALLOWED_OBJECT_ACE_TYPE",
	0x06: "ACCESS_DENIED_OBJECT_ACE_TYPE",
	0x07: "SYSTEM_AUDIT_OBJECT_ACE_TYPE",
	0x08: "SYSTEM_ALARM_OBJECT_ACE_TYPE",
	0x09: "ACCESS_ALLOWED_CALLBACK_ACE_TYPE",
	0x0A: "ACCESS_DENIED_CALLBACK_ACE_TYPE",
	0x0B: "ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE",
	0x0C: "ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE",
	0x0D: "SYSTEM_AUDIT_CALLBACK_ACE_TYPE",
	0x0E: "SYSTEM_ALARM_CALLBACK_ACE_TYPE",
	0x0F: "SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE",
	0x10: "SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE",
	0x11: "SYSTEM_MANDATORY_LABEL_ACE_TYPE",
	0x12: "SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE",
	0x13: "SYSTEM_SCOPED_POLICY_ID_ACE_TYPE",
}

var aceFlagsMap = map[int]string{
	0x02: "CONTAINER_INHERIT_ACE",
	0x80: "FAILED_ACCESS_ACE_FLAG",
	0x08: "INHERIT_ONLY_ACE",
	0x10: "INHERITED_ACE",
	0x04: "NO_PROPAGATE_INHERIT_ACE",
	0x01: "OBJECT_INHERIT_ACE",
	0x40: "SUCCESSFUL_ACCESS_ACE_FLAG",
}
var accessRightsMap = map[string]int{
	"RIGHT_DS_CREATE_CHILD":            0x00000001,
	"RIGHT_DS_DELETE_CHILD":            0x00000002,
	"RIGHT_DS_LIST_CONTENTS":           0x00000004,
	"RIGHT_DS_WRITE_PROPERTY_EXTENDED": 0x00000008,
	"RIGHT_DS_READ_PROPERTY":           0x00000010,
	"RIGHT_DS_WRITE_PROPERTY":          0x00000020,
	"RIGHT_DS_DELETE_TREE":             0x00000040,
	"RIGHT_DS_LIST_OBJECT":             0x00000080,
	"RIGHT_DS_CONTROL_ACCESS":          0x00000100,
	"RIGHT_DELETE":                     0x00010000,
	"RIGHT_READ_CONTROL":               0x00020000,
	"RIGHT_WRITE_DACL":                 0x00040000,
	"RIGHT_WRITE_OWNER":                0x00080000,
	"GENERIC_ALL":                      0x000F01FF,
	/*0x00000001: "RIGHT_DS_CREATE_CHILD",
	0x00000002: "RIGHT_DS_DELETE_CHILD",
	0x00000004: "RIGHT_DS_LIST_CONTENTS",
	0x00000008: "RIGHT_DS_WRITE_PROPERTY_EXTENDED",
	0x00000010: "RIGHT_DS_READ_PROPERTY",
	0x00000020: "RIGHT_DS_WRITE_PROPERTY",
	0x00000040: "RIGHT_DS_DELETE_TREE",
	0x00000080: "RIGHT_DS_LIST_OBJECT",
	0x00000100: "RIGHT_DS_CONTROL_ACCESS",
	0x00010000: "RIGHT_DELETE",
	0x00020000: "RIGHT_READ_CONTROL",
	0x00040000: "RIGHT_WRITE_DACL", 
	0x00080000: "RIGHT_WRITE_OWNER", 
	/*0x10000000: "RIGHT_GENERIC_ALL",
	0x20000000: "RIGHT_GENERIC_EXECUTE",
	0x40000000: "RIGHT_GENERIC_WRITE",
	0x80000000: "RIGHT_GENERIC_READ",*/
	/*0x00020094: "GENERIC_READ",
	0x00020028: "GENERIC_WRITE", 		
	0x00020004: "GENERIC_EXECUTE",
	, 	*/ //abusable
}

var objectTypeMap = map[int]string{
	0x00000100: "ADS_RIGHT_DS_CONTROL_ACCESS",
	0x00000001: "ADS_RIGHT_DS_CREATE_CHILD",
	0x00000002: "ADS_RIGHT_DS_DELETE_CHILD",
	0x00000010: "ADS_RIGHT_DS_READ_PROP",
	0x00000020: "ADS_RIGHT_DS_WRITE_PROP",
	0x00000008: "ADS_RIGHT_DS_SELF",
}

var inheritedObjectTypeMap = map[int]string{
	0x00000000: "",
	0x00000001: "ACE_OBJECT_TYPE_PRESENT",
	0x00000002: "ACE_INHERITED_OBJECT_TYPE_PRESENT",
}

var wellKnownSIDsMap = map[string]string{
	"S-1-0-0":    "Null SID",
	"S-1-1-0":    "World",
	"S-1-2-0":    "Local",
	"S-1-2-1":    "Console Logon",
	"S-1-3-0":    "Creator Owner ID",
	"S-1-3-1":    "Creator Group ID",
	"S-1-3-2":    "Creator Owner Server",
	"S-1-3-3":    "Creator Group Server",
	"S-1-3-4":    "Owner Rights",
	"S-1-4":      "Non-Unique Authority",
	"S-1-5":      "NT Authority",
	"S-1-5-80-0": "All Services",
	"S-1-5-1":    "Dialup",
	"S-1-5-113":  "Local Account",
	"S-1-5-114":  "Local account and member of Administrators group",
	"S-1-5-2":    "Network",
	"S-1-5-3":    "Batch",
	"S-1-5-4":    "Interactive",
	"S-1-5-6":    "Serivce",
	"S-1-5-7":    "Anonymous Logon",
	"S-1-5-8":    "Proxy",
	"S-1-5-9":    "Enterprise Domain Controllers",
	"S-1-5-10":   "Self",
	"S-1-5-11":   "Authenticated Users",
	"S-1-5-12":   "Restricted Code",
	"S-1-5-13":   "Terminal Server User",
	"S-1-5-14":   "Remote Interactive Logon",
	"S-1-5-15":   "This Organization",
	"S-1-5-17":   "IUSR",
	"S-1-5-18":   "System (Local System)",
	"S-1-5-19":   "NT Authority (LocalService)",
	"S-1-5-20":   "Network Service",
}

var controlAccessRightMap = map[string]string{
	"ee914b82-0a98-11d1-adbb-00c04fd8d5cd":     "Abandon-Replication",
	"440820ad-65b4-11d1-a3da-0000f875ae0d":     "Add-GUID",
	"1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd":     "Allocate-Rids",
	"68b1d179-0d15-4d4f-ab71-46152e79a7bc":     "Allowed-To-Authenticate",
	"edacfd8f-ffb3-11d1-b41d-00a0c968f939":     "Apply-Group-Policy",
	"0e10c968-78fb-11d2-90d4-00c04f79dc55":     "Certificate-Enrollment",
	"a05b8cc2-17bc-4802-a710-e7c15ab866a2":     "Certificate-AutoEnrollment",
	"014bf69c-7b3b-11d1-85f6-08002be74fab":     "Change-Domain-Master",
	"cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd":     "Change-Infrastructure-Master",
	"bae50096-4752-11d1-9052-00c04fc2d4cf":     "Change-PDC",
	"d58d5f36-0a98-11d1-adbb-00c04fd8d5cd":     "Change-Rid-Master",
	"e12b56b6-0a95-11d1-adbb-00c04fd8d5cd":     "Change-Schema-Master",
	"e2a36dc9-ae17-47c3-b58b-be34c55ba633":     "Create-Inbound-Forest-Trust",
	"fec364e0-0a98-11d1-adbb-00c04fd8d5cd":     "Do-Garbage-Collection",
	"ab721a52-1e2f-11d0-9819-00aa0040529b":     "Domain-Administer-Server",
	"69ae6200-7f46-11d2-b9ad-00c04f79f805":     "DS-Check-Stale-Phantoms",
	"2f16c4a5-b98e-432c-952a-cb388ba33f2e":     "DS-Execute-Intentions-Script",
	"9923a32a-3607-11d2-b9be-0000f87a36b2":     "DS-Install-Replica",
	"4ecc03fe-ffc0-4947-b630-eb672a8a9dbc":     "DS-Query-Self-Quota",
	"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2":     "DS-Replication-Get-Changes",
	"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2":     "DS-Replication-Get-Changes-All",
	"89e95b76-444d-4c62-991a-0facbeda640c":     "DS-Replication-Get-Changes-In-Filtered-Set",
	"1131f6ac-9c07-11d1-f79f-00c04fc2dcd2":     "DS-Replication-Manage-Topology",
	"f98340fb-7c5b-4cdb-a00b-2ebdfa115a96":     "DS-Replication-Monitor-Topology",
	"1131f6ab-9c07-11d1-f79f-00c04fc2dcd2":     "DS-Replication-Synchronize",
	"05c74c5e-4deb-43b4-bd9f-86664c2a7fd5":     "Enable-Per-User-Reversibly-Encrypted-Password",
	"b7b1b3de-ab09-4242-9e30-9980e5d322f7":     "Generate-RSoP-Logging",
	"b7b1b3dd-ab09-4242-9e30-9980e5d322f7":     "Generate-RSoP-Planning",
	"7c0e2a7c-a419-48e4-a995-10180aad54dd":     "Manage-Optional-Features",
	"ba33815a-4f93-4c76-87f3-57574bff8109":     "Migrate-SID-History",
	"b4e60130-df3f-11d1-9c86-006008764d0e":     "msmq-Open-Connector",
	"06bd3201-df3e-11d1-9c86-006008764d0e":     "msmq-Peek",
	"4b6e08c3-df3c-11d1-9c86-006008764d0e":     "msmq-Peek-computer-Journal",
	"4b6e08c1-df3c-11d1-9c86-006008764d0e":     "msmq-Peek-Dead-Letter",
	"06bd3200-df3e-11d1-9c86-006008764d0e":     "msmq-Receive",
	"4b6e08c2-df3c-11d1-9c86-006008764d0e":     "msmq-Receive-computer-Journal",
	"4b6e08c0-df3c-11d1-9c86-006008764d0e":     "msmq-Receive-Dead-Letter",
	"06bd3203-df3e-11d1-9c86-006008764d0e":     "msmq-Receive-journal",
	"06bd3202-df3e-11d1-9c86-006008764d0e":     "msmq-Send",
	"a1990816-4298-11d1-ade2-00c04fd8d5cd":     "Open-Address-Book",
	"1131f6ae-9c07-11d1-f79f-00c04fc2dcd2":     "Read-Only-Replication-Secret-Synchronization",
	"45ec5156-db7e-47bb-b53f-dbeb2d03c40f":     "Reanimate-Tombstones",
	"0bc1554e-0a99-11d1-adbb-00c04fd8d5cd":     "Recalculate-Hierarchy",
	"62dd28a8-7f46-11d2-b9ad-00c04f79f805":     "Recalculate-Security-Inheritance",
	"ab721a56-1e2f-11d0-9819-00aa0040529b":     "Receive-As",
	"9432c620-033c-4db7-8b58-14ef6d0bf477":     "Refresh-Group-Cache",
	"1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8":     "Reload-SSL-Certificate",
	"7726b9d5-a4b4-4288-a6b2-dce952e80a7f":     "Run-Protect_Admin_Groups-Task",
	"91d67418-0135-4acc-8d79-c08e857cfbec":     "SAM-Enumerate-Entire-Domain",
	"ab721a54-1e2f-11d0-9819-00aa0040529b":     "Send-As",
	"ab721a55-1e2f-11d0-9819-00aa0040529b":     "Send-To",
	"ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501":     "Unexpire-Password",
	"280f369c-67c7-438e-ae98-1d46f3c6f541":     "Update-Password-Not-Required-Bit",
	"be2bb760-7f46-11d2-b9ad-00c04f79f805":     "Update-Schema-Cache",
	"ab721a53-1e2f-11d0-9819-00aa0040529b":     "User-Change-Password",
	"00299570-246d-11d0-a768-00aa006e0529":     "User-Force-Change-Password",
	"3e0f7e18-2c7a-4c10-ba82-4d926db99a3e":     "DS-Clone-Domain-Controller",
	"084c93a2-620d-4879-a836-f0ae47de0e89":     "DS-Read-Partition-Secrets",
	"94825a8d-b171-4116-8146-1e34d8f54401":     "DS-Write-Partition-Secrets",
	"4125c71f-7fac-4ff0-bcb7-f09a41325286":     "DS-Set-Owner",
	"88a9933e-e5c8-4f2a-9dd7-2527416b8092":     "DS-Bypass-Quota",
	"9b026da6-0d3c-465c-8bee-5199d7165cba":     "DS-Validated-Write-Computer",
	"c7407360-20bf-11d0-a768-00aa006e0529":     "Domain Password & Lockout Policies",
	"59ba2f42-79a2-11d0-9020-00c04fc2d3cf":     "General Information",
	"4c164200-20c0-11d0-a768-00aa006e0529":     "Account Restrictions",
	"5f202010-79a5-11d0-9020-00c04fc2d4cf":     "Logon Information",
	"bc0ac240-79a9-11d0-9020-00c04fc2d4cf":     "Group Membership",
	"e45795b2-9455-11d1-aebd-0000f80367c1":     "Phone and Mail Options",
	"77b5b886-944a-11d1-aebd-0000f80367c1":     "Personal Information",
	"e45795b3-9455-11d1-aebd-0000f80367c1":     "Web Information",
	"e48d0154-bcf8-11d1-8702-00c04fb96050":     "Public Information",
	"037088f8-0ae1-11d2-b422-00a0c968f939":     "Remote Access Information",
	"b8119fd0-04f6-4762-ab7a-4986c76b3f9a":     "Other Domain Parameters (for use by SAM)",
	"72e39547-7b18-11d1-adef-00c04fd8d5cd":     "DNS Host Name Attributes",
	"ffa6f046-ca4b-4feb-b40d-04dfee722543":     "MS-TS-GatewayAccess",
	"91e647de-d96f-4b70-9557-d63ff4f3ccd8":     "Private Information",
	"5805bc62-bdc9-4428-a5e2-856a0f4c185e":     "Terminal Server License Server",
	"ab3a1ad1-1df5-11d3-aa5e-00c04f8eedd8":     "* objects",
	"2628a46a-a6ad-4ae0-b854-2b12d9fe6f9e":     "account objects",
	"7f561288-5301-11d1-a9c5-0000f80367c1":     "aCSPolicy objects",
	"2e899b04-2834-11d3-91d4-0000f87a57d4":     "aCSResourceLimits objects",
	"7f561289-5301-11d1-a9c5-0000f80367c1":     "aCSSubnet objects",
	"19195a5f-6da0-11d0-afd3-00c04fd930c9":     "Active Directory Service objects",
	"ee64c93a-a980-11d2-a9ff-00c04f8eedd8":     "ADC Connection Agreement objects",
	"348af8f2-a982-11d2-a9ff-00c04f8eedd8":     "ADC Schema Map Policy objects",
	"e605672c-a980-11d2-a9ff-00dc04f8eedd8":    "ADC Service objects",
	"3e74f60f-3e73-11d1-a9c0-0000f80367c1":     "Address List objects",
	"5f04250a-1262-11d0-a060-00aa006c33ed":     "Address Template objects",
	"a8df74ab-c5ea-11d1-bbcb-0080c76670c0":     "Address Type objects",
	"e7211f02-a980-11d2-a9ff-00dMf8eedd8":      "Addressing Policy objects",
	"e768a58e-a980-11d2-a9ff-00c04f8eedd8":     "Administrative Group objects",
	"e7a44058-a980-11d2-a9ff-00c04f8eedd8":     "Administrative Groups objects",
	"e7f2edf2-a980-11d2-a9ff-00c04f8eedd8":     "Administrative Role objects",
	"8cc8fb0e-b09e-11d2-aa06-00c04f8eedd8":     "Advanced Security objects",
	"3fdfee4f-47f4-11d1-a9c3-0000f80367c1":     "applicationEntity objects",
	"5fd4250b-1262-11d0-a060-00aa006c33ed":     "applicationProcess objects",
	"f80acc1-56fD-11d1-a9c6-0000f80367c1":      "applicationSettings objects",
	"19195a5c-6da0-11d0-afd3-00c04fd930c9":     "applicationSiteSettings objects",
	"ddc790ac-af4d-442a-8f0f-a1d4caa7dd92":     "applicationVersion objects",
	"bf967a81-0de6-11d0-a285-00aa003049e2":     "builtinDomain objects",
	"7d6c0e9d-7e20-11d0-afd6-00c04fd930c9":     "categoryRegistration objects",
	"e85710b6-a980-11d2-a9ff-00c04f8eedd8":     "cc:Mail Connector objects",
	"e5209ca2-3bba-11d2-90cc-00c04fd91ab1":     "Certificate Template objects",
	"3fdfee50-47f4-11d1-a9c3-0000f80367c1":     "Certification Authority objects",
	"e934cb68-a980-11d2-a9ff-00c04f8eedd8":     "Chat Network objects",
	"e9621816-a980-11d2-a9ff-00c04f8eedd8":     "Chat Protocol objects",
	"bf967a82-0de6-11d0-a285-00aa003049e2":     "classRegistration objects",
	"bf967a84-0de6-11d0-a285-00aa003049e2":     "classStore objects",
	"bf967a85-0de6-11d0-a285-00aa003049e2":     "comConnectionPoint objects",
	"bf967a86-0de6-11d0-a285-00aa003049e2":     "Computer objects",
	"ed2c752c-a980-11d2-a9ff-00c04f8eedd8":     "Computer Policy objects",
	"eddce330-a980-11d2-a9ff-00c04f8eedd8":     "Conference Site objects",
	"ed7fe77a-a980-11d2-a9ff-00c04f8eedd8":     "Conference Sites objects",
	"bf967a87-0de6-11d0-a285-00aa003049e2":     "configuration objects",
	"19195a60-6da0-11d0-afd3-00c04fd930c9":     "Connection objects",
	"5cb41ecf-0e4c-11d0-a286-00aa003049e2":     "connectionPoint objects",
	"eee325dc-a980-11d2-a9ff-00c04f8eedd8":     "Connections objects",
	"5cb41ed0-0e4c-11d0-a286-00aa003049e2":     "Contact objects",
	"bf967a8b-0de6-11d0-a285-00aa003049e2":     "Container objects",
	"bf967a8c-0de6-11d0-a285-00aa003049e2":     "country objects",
	"167758ca-470-11d1-a9c3-0000f80367c1":      "cRLDistributionPoint objects",
	"{bf967a8d-0de6-11d0-a285-00aa003049e2":    "crossRef objects",
	"ef9e60e0-56f7-11d1-a9c6-0000f80367c1":     "crossRefContainer objects",
	"038680ec-a981-11d2-a9ff-00c04f8eedd8":     "Data Conference Server (T.120 MCU) objects",
	"03aa4432-a981-11d2-a9ff-00c04f8eedd8":     "Data Conference Technology Provider (T.120 MCU) objects",
	"bf967a8e-0de6-11d0-a285-00aa003049e2":     "device objects",
	"8447f9f2-1027-11d0-a05f-00aa006c33ed":     "dfsConfiguration objects",
	"963d2756-48be-11d1-a9c3-0000f80367c1":     "dHCPCIass objects",
	"3fdfee52-47f4-11d1-a9c3-0000f80367c1":     "Directory objects",
	"99f58682-12e8-11d3-aa58-00c04f8eedd8":     "Directory Replication Connector objects",
	"a8df74b5-c5ea-11d1-bbcb-0080c76670c0":     "Directory Synchronization objects",
	"a8df74ae-c5ea-11d1-bbcb-0080c76670c0":     "Directory Synchronization Requestor objects",
	"a8df74af-c5ea-11d1-bbcb-0080c76670c0":     "Directory Synchronization Server Connector objects",
	"a8df74b0-c5ea-11d1-bbcb-0080c76670c0":     "Directory Synchronization Site Server objects",
	"5fd4250c-1262-11d0-a060-00aa006c33ed":     "Display Template objects",
	"e0fa1e8a-9b45-11d0-afdd-00c04fd930c9":     "displaySpecifier objects",
	"e0fa1e8c-9b45-11d0-afad-00c04fd930c9":     "dnsNode objects",
	"e0fe1e8b-9b45-11d0-afdd-00c04fd930c9":     "dnsZone objects",
	"39bad96d-c2d6-4baf-88ab-7e4207600117":     "document objects",
	"7a2be07c-302f-4b96-bc90-0795d66885f8":     "documentSeries objects",
	"f0f8ffab-1191-11d0-a060-00aa006c33ed":     "Domain Controller Settings objects",
	"19195a5a-6da0-11d0-afd3-00c04fd930c9":     "domain objects",
	"19195a5b-6da0-11d0-afd3-00c04fd930c9":     "Domain objects",
	"bf967a99-0de6-11d0-a285-00aa003049e2":     "Domain Policy objects",
	"8bfd2d3d-efda-4549-852c-f85e137aedc6":     "domainRelatedObject objects",
	"09b10f14-6f93-11d2-9905-0000f87a57d4":     "dSUISettings objects",
	"a8df74d4-c5ea-11d1-bbcb-0080c76670c0":     "Dynamic RAS Connector objects",
	"66d51249-3355-4c1f-b24e-81f252aca23b":     "dynamicObject objects",
	"a8df74b1-c5ea-11d1-bbcb-0080c76670c0":     "Encryption Configuration objects",
	"{a8df74aa-c5ea-11d1-bbcb-0080c76670c0":    "Exchange Add-In objects",
	"a8df74ac-c5ea-11d1-bbcb-0080c76670c0":     "Exchange Admin Extension objects",
	"d03d6858-06f4-11d2-aa53-00c04fd7d83a":     "Exchange Configuration Container objects",
	"006c91da-a981-11d2-a9ff-00c04f8eedd8":     "Exchange Container objects",
	"366a319c-a982-11d2-a9ff-00c04f8eedd8":     "Exchange Organization objects",
	"3630f92c-a982-11d2-a9ff-00c04f8eedd8":     "Exchange Policies objects",
	"90f2b634-b09e-11d2-aa06-00c04f8eedd8":     "Exchange Protocols objects",
	"01a9aa9c-a981-11d2-a9ff-00c04f8eedd8":     "Exchange Server objects",
	"e497942f-1d42-11d3-aa5e-00c04f8eedd8":     "Exchange Server Policy objects",
	"346e5cba-a982-11d2-a9ff-00c04f8eedd8":     "Exchange Servers objects",
	"8297931e-86d3-11d0-afda-00c04fd930c9":     "Extended Right objects",
	"dd712229-10e4-11d0-a05f-00aa006c33ed":     "fileLinkTracking objects",
	"8e4eb2ed-4712-11d0-a1a0-00c04fd930c9":     "fileLinkTrackingEntry objects",
	"89e31c12-8530-11d0-afda-00c04fd930c9":     "Foreign Security Principal objects",
	"c498f152-dc6b-474a-9f52-7cdba3d7d351":     "friendlyCountry objects",
	"2a132586-9373-11d1-aebc-0000f80367c1":     "FRS Member objects",
	"5245803a-ca6a-11d0-afff-0000f80367c1":     "FRS Replica Set objects",
	"f780acc2-56f0-11d1-a9c6-0000f80367c1":     "FRS Settings objects",
	"2a132588-9373-11d1-aebc-0000f80367c1":     "FRS Subscriber objects",
	"2a132587-9373-11d1-aebc-0000f80367c1":     "FRS Subscriptions objects",
	"8447f9f3-1027-11d0-a05f-00aa006c33ed":     "fTDfs objects",
	"a8df74b7-c5ea-11d1-bbcb-0080c76670c0":     "Gateway objects",
	"bf967a9c-0de6-11d0-a285-00aa003049e2":     "Group objects",
	"bf967a9d-0de6-11d0-a285-00aa003049e2":     "groupOfNames objects",
	"0310a911-93a3-4e21-a7a3-55d85ab2c48b":     "groupOfUniqueNames objects",
	"f30e3bc2-9ff0-11d1-b603-0000f80367c1":     "groupPoticyContainer objects",
	"91eaaac4-b09e-11d2-aa06-00c04f8eedd8":     "GroupWise Connector objects",
	"9432cae6-b09e-11d2-aa06-00c04f8eedd8":     "HTTP Protocol objects",
	"8c3c5050-b09e-11d2-aa06-00c04f8eedd8":     "HTTP Virtual Directory objects",
	"a8df74c2-c5ea-11d1-bbcb-0080c76670c0":     "HTTP Virtual Server objects",
	"35f7c0bc-a982-11d2-a9ff-00c04f8eedd8":     "IMAP Policy objects",
	"93da93e4-b09e-11d2-aa06-00c04f8eedd8":     "IMAP Protocol objects",
	"99f58672-12e8-11d3-aa58-00c04f8eedd8":     "IMAP Sessions objects",
	"a8df74c5-c5ea-11d1-bbcb-0080c76670c0":     "IMAP Virtual Server objects",
	"7bfdcb8a-4807-11d1-a9c3-0000f80367c1":     "indexServerCatalog objects",
	"4828cc14-1437-45bc-9b07-ad6f015e5f28":     "InetOrqPerson objects",
	"031b371a-a981-11d2-a9ff-00c04f8eedd8":     "Information Store objects",
	"2df90d89-009f-11d2-aa4c-00c04fd7d83a":     "infrastrudureUpdate objects",
	"9f116eb8-284e-11d3-aa68-00c04f8eedd8":     "Instant Messaging Global Settings objects",
	"9f116ea3-284e-11d3-aa68-00c04f8eedd8":     "Instant Messaging Protocol objects",
	"9f116eb4-284e-11d3-aa68-00c04f8eedd8":     "Instant Messaging Virtual Server objects",
	"07383086-91df-11d1-aebc-0000f80367c1":     "IntelliMirror Group objects",
	"07383085-91df-11d1-aebc-0000f80367c1":     "IntelliMirror Service objects",
	"ab3a1ace-1df5-11d3-aa5e-00c04f8eedd8":     "Internet Message Formats objects",
	"26d97376-6070-11d1-a9c6-0000f80367c1":     "Inter-Site Transport objects",
	"26d97375-6070-11d1-a9c6-0000f80367c1":     "Inter-Site Transports Container objects",
	"b40ff825-427a-11d1-a9c2-0000f80367c1":     "ipsecBase objects",
	"b40ff826-427a-11d1-a9c2-0000f80367c1":     "ipsecFilter objects",
	"b40ff828-427a-11d1-a9c2-0000f80367c1":     "ipsecISAKMPPolicy objects",
	"b40ff827-427a-11d1-a9c2-0000f80367c1":     "ipsecNegotiationPolicy objects",
	"b40ff829-427a-11d1-a9c2-0000f80367c1":     "ipsecNFA objects",
	"b7b13121-b82e-11d0-afee-0000f80367c1":     "ipsecPolicy objects",
	"8ce334ec-b09e-11d2-aa06-00c04f8eedd8":     "Key Management Server objects",
	"bf967a9e-0de6-11d0-a285-00aa003049e2":     "leaf objects",
	"1be8f17d-a9ff-11d0-afe2-00c04fd930c9":     "Licensing Site Settings objects",
	"ddac0cf5-af8f-11d0-afeb-00c04fd930c9":     "linkTrackObjectMoveTable objects",
	"ddac0cf7-af8f-11d0-afeb-00c04fd930c9":     "linkTrackOMTEntry objects",
	"ddac0cf6-af8f-11d0-afeb-00c04fd930c9":     "linkTrackVolEntry objects",
	"ddac0cf4-af8f-11d0-afeb-00c04fd930c9":     "linkTrackVolumeTable objects",
	"bf967aa0-0de6-11d0-a285-00aa003049e2":     "locality objects",
	"52ab8671-5709-11d1-a9c6-0000f80367c1":     "lostAndFound objects",
	"bf967aa1-0de6-11d0-a285-00aa003049e2":     "Mail Recipient objects",
	"11b6cc94-48c4-11d1-a9c3-0000f80367c1":     "meeting objects",
	"ab3a1ad7-1df5-11d3-aa5e-00c04f8eedd8":     "Message Delivery Configuration objects",
	"a8df74b6-c5ea-11d1-bbcb-0080c76670c0":     "Message Gateway for cc:Mail objects",
	"a8df74a7-c5ea-11d1-bbcb-0080c76670c0":     "Message Transfer Agent objects",
	"a8df74bb-c5ea-11d1-bbcb-0080c76670c0":     "mHSMonitoringConfig objects",
	"0bffa04c-7d8e-44cd-968a-b2cac11d17e1":     "Microsoft Exchange System Objects objects",
	"a8df74b9-c5ea-11d1-bbcb-0080c76670c0":     "Monitoring Link Configuration objects",
	"a8df74bd-c5ea-11d1-bbcD-0080c76670c0":     "Monitoring Server Configuration objects",
	"c9010e74-4e58-4917-8a89-5e3e2340fcf8":     "msCOM-Partition objects",
	"250464ab-c417-497a-975a-9e0d459a7ca1":     "msCOM-PartitionSet objects",
	"90df3c3e-1854-4455-a5d7-cad40d56657a":     "msDS-App-Configuration objects",
	"f9e67d761-e327-4d55-bc95-682f875e2f8e":    "msDS-AppData objects",
	"cfee1051-5f28-4bae-a863-5d0cc18a8ed1":     "msDS-AzAdminManager objects",
	"ddf8de9b-cba5-4e12-842e-28d8b66f75ec":     "msDS-AzApplication objects",
	"860abe37-9a9b-4fa4-b3d2-b8ace5df9ec5":     "msDS-AzOperation objects",
	"8213eac9-9d55-44dc-925c-e9a52b927644":     "msDS-AzRole objects",
	"4feae054-ce55-47bb-860e-5b12063a51de":     "msDS-AzScope objects",
	"1ed3a473-9b1b-418a-bfa0-3a37b95a5306":     "msDS-AzTask objects",
	"b1fce95a-1d44-11d3-aa5e-00c04f8eedd8":     "msExchAddressListServiceContainer objects",
	"d8782c34-46ca-11d3-aa72-00c04f8eedd8":     "msExchBaseClass objects",
	"922180da-b09e-11d2-aa06-00c04f8eedd8":     "msExchCalendarConnector objects",
	"e8977034-a980-11d2-a9ff-00c04f8eedd8":     "msExchCertificateInformation objects",
	"e8d0a8a4-a980-11d2-a9ff-00c04f8eedd8":     "msExchChatBan objects",
	"e902ba06-a980-11d2-a9ff-00c04f8eedd8":     "msExchChatChannel objects",
	"e9a0153a-a980-11d2-a9ff-00c04f8eedd8":     "msExchChatUserClass objects",
	"89652316-b09e-11d2-aa06-00c04f8eedd8":     "msExchConnector objects",
	"00aa8efe-a981-11d2-a9ff-00c04f8eedd8":     "msExchCTP objects",
	"00e629c8-a981-11d2-a9ff-00c04f8eedd8":     "msExchCustomAttributes objects",
	"018849b0-a981-11d2-a9ff-00c04f8eedd8":     "msExchDynamicDistributionList objects",
	"e32977cd-1d31-11d3-aa5e-00c04f8eedd8":     "msExchGenericPolicy objects",
	"e32977c3-1d31-11d3-aa5e-00c04f8eedd8":     "msExchGenericPolicyContainer objects",
	"9f116ebe-284e-11d3-aa68-00c04f8eedd8":     "msExchIMFirewall objects",
	"028502f4-a981-11d2-a9ff-00c04f8eedd8":     "msExchIMRecipient objects",
	"36f94fcc-ebbb-4a32-b721-1cae42b2dbab":     "msExchMailboxManagerPolicy objects",
	"03652000-a981-11d2-a9ff-00c04f8eedd8":     "msExchMailStorage objects",
	"03d069d2-a981-11d2-a9ff-00c04f8eedd8":     "msExchMDB objects",
	"03f68f72-a981-11d2-a9ff-00c04f8eedd8":     "msExchMonitorsContainer objects",
	"1529cf7a-2fdb-11d3-aa6d-00c04f8eedd8":     "msExchMultiMediaUser objects",
	"91ce0e8c-b09e-11d2-aa06-00c04f8eedd8":     "msExchOVVMConnector objects",
	"b8d47e54-4b78-11d3-aa75-00c04f8eedd8":     "msExchPrivateMDBProxy objects",
	"8c7588c0-b09e-11d2-aa06-00c04f8eedd8":     "msExchProtocolCfgHTTPFilter objects",
	"8c58ec88-b09e-11d2-aa06-00c04f8eedd8":     "msExchProtocolCfgHTTPFilters objects",
	"9f116ea7-284e-11d3-aa68-00c04f8eedd8":     "msExchProtocolCfgIM objects",
	"939ef91a-b09e-11d2-aa06-00c04f8eedd8":     "msExchProtocolCfgSharedContainer objects",
	"8b7b31d6-b09e-11d2-aa06-00c04f8eedd8":     "msExchProtocolCfgSMTPIPAddress objects",
	"8b2c843c-b09e-11d2-aa06-00c04f8eedd8":     "msExchProtocolCfgSMTPPAddressContainer objects",
	"cec4472b-22ae-11d3-aa62-00c04f8eedd8":     "msExchPseudoPF objects",
	"9ae2fa1b-22b0-11d3-aa62-00c04f8eedd8":     "msExchPseudoPFAdmin objects",
	"3582ed82-a982-11d2-a9ff-00c04f8eedd8":     "msExchPublicFolderTreeContainer objects",
	"91b17254-b09e-11d2-aa06-00c04f8eedd8":     "msExchSNADSConnector objects",
	"7b9a2d92-b7eb-4382-9772-c3e0f9baaf94":     "msieee80211-Policy objects",
	"a8df74be-c5ea-11d1-bbcb-0080c76670c0":     "MSMail Connector objects",
	"9a0dc344-c100-11d1-bbc5-0080c75670c0":     "MSMQ Configuration objects",
	"9a0dc345-c100-11d1-bbc5-0080c76670c0":     "MSMQ Enterprise objects",
	"46b27aac-aafa-4ffb-b773-e5bf621ee87b":     "MSMQ Group objects",
	"876d6817-35cc-436c-acea-5ef7174dd9be":     "MSMQ Queue Alias objects",
	"9a0dc343-c100-11d1-bbc5-0080c76670c0":     "MSMQ Queue objects",
	"9a0dc346-c100-11d1-bbc5-0080c76670c0":     "MSMQ Routing Link objects",
	"9a0dc347-c100-11d1-bbc5-0080c76670c0":     "MSMQ Settings objects",
	"50776997-3c3d-11d2-90cc-00c04fd91ab1":     "MSMQ Upgraded User objects",
	"37cfd85c-6719-4ad8-8f9e-8678ba627563":     "msPKI-Enterprise-Oid objects",
	"26ccf238-a08e-4b86-9a82-a8c9ac7ee5cb":     "msPKI-Key-Recovery-Agent objects",
	"1562a632-44b9-4a7e-a2d3-e426c96a3acc":     "msPKI-PrivateKeyRecoveryAgent objects",
	"09f0506a-cd28-11d2-9993-0000f87a57d4":     "mS-SQL-OLAPCube objects",
	"20af031a-ccef-11d2-9993-0000f87a57d4":     "mS-SQL-OLAPDatabase objects",
	"0c7e18ea-ccef-11d2-9993-0000f87a57d4":     "mS-SQL-OLAPServer objects",
	"1d08694a-ccef-11d2-9993-0000f87a57d4":     "mS-SQL-SQLDatabase objects",
	"17c2f64e-ccef-11d2-9993-0000f87a57d4":     "mS-SQL-SQLPublication objects",
	"11d43c5c-ccef-11d2-9993-0000f87a57d4":     "mS-SQL-SQLRepository objects",
	"05f6c878-ccef-11d2-9993-0000f87a57d4":     "mS-SQL-SQLServer objects",
	"ca7b9735-4b2a-4e49-89c3-99025334dc94":     "msTAPI-RtConference objects",
	"53ea1cb5-b704-4df9-818f-5cb4ec86cac1":     "msTAPI-RtPerson objects",
	"50ca5d7d-5c8b-4ef3-b9df-5b66d491e526":     "msWMI-IntRangeParam objects",
	"292f0d9a-cf76-42b0-841f-b650f331df62":     "msWMI-IntSetParam objects",
	"07502414-fdca-4851-b04a-13645b11d226":     "msWMI-MergeablePolicyTemplate objects",
	"55dd81c9-c312-41f9-a84d-c6adbdf1e8e1":     "msWMI-ObjectEncoding objects",
	"e2bc80f1-244a-4d59-acc6-ca5c4f82e6e1":     "msWMI-PolicyTemplate objects",
	"595b2613-4109-4e77-9013-a3bb4ef277c7":     "msWMI-PolicyType objects",
	"45fb5a57-5018-4d0f-9056-997c8c9122d9":     "msWMI-RangeParam objects",
	"6afe8fe2-70bc-4cce-b166-a96f7359c514":     "msWMI-RealRangeParam objects",
	"3c7e6f83-dd0e-481b-a0c2-74cd96ef2a66":     "msWMI-Rule objects",
	"f1e44bdf-8dd3-4235-9c86-f91f31f5b569":     "msWMI-ShadowObject objects",
	"6cc8b2b5-12df-44f6-8307-e74f5cdee369":     "msWMI-SimplePolicyTemplate objects",
	"ab857078-0142-4406-945b-34c9b6b13372":     "msWMI-Som objects",
	"0bc579a2-1da7-4cea-b699-807f3b9d63a4":     "msWMI-StringSetParam objects",
	"d9a799b2-cef3-48b3-b5ad-fb85f8dd3214":     "msWMI-UintRangeParam objects",
	"8f4beb31-4e19-46f5-932e-5fa03c339b1d":     "msWMI-UintSetParam objects",
	"b82ac26b-c6db-4098-92c6-49c18a3336e1":     "msWMI-UnknownRangeParam objects",
	"05630000-3927-4ede-bf27-ca91f275c26f":     "msWMI-WMIGPO objects",
	"94162eae-b09e-11d2-aa06-00c04f8eedd8":     "NNTP Protocol objects",
	"a8df74cb-c5ea-11d1-bbcb-0080c76670c0":     "NNTP Virtual Server objects",
	"04c85e62-a981-11d2-a9ff-00c04f8eedd8":     "Notes Connector objects",
	"3686cdd4-a982-11d2-a9ff-00c04f8eedd8":     "Offline Address List objects",
	"bf967aa3-0de6-11d0-a285-00aa003049e2":     "organization objects",
	"bf967aa5-0de6-11d0-a285-00aa003049e2":     "Organizational Unit objects",
	"bf967aa4-0de6-11d0-a285-00aa003049e2":     "organizationalPerson objects",
	"a8df74bf-c5ea-11d1-bbcb-0080c76670c0":     "organizationalRole objects",
	"bf967aa6-0de6-11d0-a285-00aa003049e2":     "packageRegistration objects",
	"bf967aa7-0de6-11d0-a285-00aa003049e2":     "person objects",
	"b7b13122-b82e-11d0-afee-0000f80367c1":     "physicalLocation objects",
	"ee4aa692-3bba-11d2-90cc-00c04fd91ab1":     "pKIEnrollmentService objects",
	"35be884c-a982-11d2-a9ff-00c04f8eedd8":     "POP Policy objects",
	"93f99276-b09e-11d2-aa06-00c04f8eedd8":     "POP Protocol objects",
	"99f58676-12e8-11d3-aa58-00c04f8eedd8":     "POP Sessions objects",
	"a8df74ce-c5ea-11d1-bbcb-0080c76670c0":     "POP Virtual Server objects",
	"bf967aa8-0de6-11d0-a285-00aa003049e2":     "Printer objects",
	"36145cf4-a982-11d2-a9ff-00c04f8eedd8":     "Private Information Store objects",
	"35db2484-a982-11d2-a9ff-00c04f8eedd8":     "Private Information Store Policy objects",
	"a8df74c0-c5ea-11d1-bbcb-0080c76670c0":     "protocolCfg objects",
	"a8df74c1-c5ea-11d1-bbcb-0080c76670c0":     "protocolCfgKTTP objects",
	"a8df74c4-c5ea-11d1-bbcb-0080c76670c0":     "protocolCfgIMAP objects",
	"a8df74c7-c5ea-11d1-bbcb-0080c76670c0":     "protocolCfgLDAP objects",
	"a8df74ca-c5ea-11d1-bbcb-0080c76670c0":     "protocolCfgNNTP objects",
	"a8df74cd-c5ea-11d1-bbcb-0080c76670c0":     "protocolCfgPOP objects",
	"a8df74d0-c5ea-11d1-bbcb-0080c76670c0":     "protocolCfgShared objects",
	"33f98980-a982-11d2-a9ff-00c04f8eedd8":     "protocolCfgSMTP objects",
	"f0f8ffac-1191-11d0-a060-00aa006c33ed":     "Public Folder objects",
	"364d9564-a982-11d2-a9ff-00c04f8eedd8":     "Public Folder Top Level Hierarchy objects",
	"3568b3a4-a982-11d2-a9ff-00c04f8eedd8":     "Public Information Store objects",
	"354c176c-a982-11d2-a9ff-00c04f8eedd8":     "Public Information Store Policy objects",
	"83cc7075-cca7-11d0-afff-0000f80367c1":     "Query Policy objects",
	"a8df74d3-c5ea-11d1-bbcb-0080c76670c0":     "RAS MTA Transport Stack objects",
	"e32977d2-1d31-11d3-aa5e-00c04f8eedd8":     "Recipient Policies objects",
	"e32977d8-1d31-11d3-aa5e-00c04f8eedd8":     "Recipient Policy objects",
	"e6a2c260-a980-11d2-a9ff-00c04f8eedd8":     "Recipient Update Service objects",
	"2a39c5bd-8960-11d1-aebc-0000f80367c1":     "Remote Storage Service objects",
	"a8df74d5-c5ea-11d1-bbcb-0080c76670c0":     "remoteDXA objects",
	"bf967aa9-0de6-11d0-a285-00aa003049e2":     "remoteMailRecipient objects",
	"99f5867e-12e8-11d3-aa58-00c04f8eedd8":     "Replication Connectors objects",
	"a8df74d6-c5ea-11d1-bbcb-0080c76670c0":     "residentialPerson objects",
	"b93e3a78-cbae-485e-a07b-5ef4ae505686":     "rFC822LocalPart objects",
	"6617188d-8f3c-11d0-afda-00c04fd930c9":     "rIDManager objects",
	"7bfdcb89-4807-11d1-a9c3-0000f80367c1":     "rIDSet objects",
	"7860e5d2-c8b0-4cbb-bd45-d9455beb9206":     "room objects",
	"899e5b86-b09e-11d2-aa06-00c04f8eedd8":     "Routing Group Connector objects",
	"35154156-a982-11d2-a9ff-00c04f8eedd8":     "Routing Group objects",
	"34de6b40-a982-11d2-a9ff-00c04f8eedd8":     "Routing Groups objects",
	"80212842-4bdc-11d1-a9c4-0000f80367c1":     "RPC Services objects",
	"bf967aac-0de6-11d0-a285-00aa003049e2":     "rpcEntry objects",
	"88611bdf-8cf4-11d0-afda-00c04fd930c9":     "rpcGroup objects",
	"88611be1-8cf4-11d0-afda-00c04fd930c9":     "rpcProfile objects",
	"f29653cf-7ad0-11d0-afd6-00c04fd930c9":     "rpcProfileElement objects",
	"88611be0-8cM-11d0-afda-00c04fd930c9":      "rpcServer objects",
	"f29653d0-7ad0-11d0-afd6-00c04fd930c9":     "rpcServerElement objects",
	"2a39c5be-8960-11d1-aebc-0000f80367c1":     "rRASAdministrationConnectionPoint objects",
	"f39b98ae-938d-11d1-aebd-0000f80367c1":     "rRASAdministrationDictionary objects",
	"bf967a90-0de6-11d0-a285-00aa003049e2":     "samDomain objects",
	"bf967a91-0de6-11d0-a285-00aa003049e2":     "samDomainBase objects",
	"bf967aad-0de6-11d0-a285-00aa003049e2":     "samServer objects",
	"fb1fce946-1d44-11d3-aa5e-00c04f8eedd8":    "Schedule+ Free/Busy Connector objects",
	"bf967a80-0de6-11d0-a285-00aa003049e2":     "Schema Attribute objects",
	"bf967a8f-0de6-11d0-a285-00aa003049e2":     "Schema Container objects",
	"bf967a83-0de&amp;-11d0-a285-00aa003049e2": "Schema Object objects",
	"bf967aae-0de6-11d0-a285-00aa003049e2":     "secret objects",
	"bf967aaf-0de6-11d0-a285-00aa003049e2":     "securityObject objects",
	"fbf967ab0-0de6-11d0-a285-00aa003049e2":    "securityPrincipal objects",
	"a8df74c8-c5ea-11d1-bbcb-0080c76670c0":     "Server LDAP Protocol objects",
	"bf967a92-0de6-11d0-a285-00aa003049e2":     "Server objects",
	"a8df74d1-c5ea-11d1-bbcb-0080c76670c0":     "Server Protocols objects",
	"f780acc0-56f0-11d1-a9c6-0000f80367c1":     "Servers Container objects",
	"b7b13123-b82e-11d0-afee-0000f80367c1":     "Service objects",
	"bf967ab1-0de6-11d0-a285-00aa003049e2":     "serviceClass objects",
	"28630ec1-41d5-11d1-a9c1-0000f80367c1":     "serviceConnectionPoint objects",
	"bf967ab2-0de6-11d0-a285-00aa003049e2":     "serviceInstance objects",
	"bf967abb-0de6-11d0-a285-00aa003049e2":     "Shared Folder objects",
	"5fe69b0b-e146-4f15-b0ab-c1e5d488e094":     "simpleSecurityObject objects",
	"a8df74d9-c5ea-11d1-bbcb-0080c76670c0":     "Site Addressing objects",
	"a8df74da-c5ea-11d1-bbcb-0080c76670c0":     "Site Connector objects",
	"fa8df74c3-c5ea-11d1-bbcb-0080c76670c0":    "Site HTTP Protocol objects",
	"a8df74c6-c5ea-11d1-bbcb-0080c76670c0":     "Site IMAP Protocol objects",
	"a8df74c9-c5ea-11d1-bbcb-0080c76670c0":     "Site LDAP Protocol objects",
	"d50c2cdf-8951-11d1-aebc-0000f80367c1":     "Site Link Bridge objects",
	"d50c2cde-8951-11d1-aebc-0000f80367c1":     "Site Link objects",
	"a8df74a8-c5ea-11d1-bbcb-0080c76670c0":     "Site MTA Configuration objects",
	"a8df74cc-c5ea-11d1-bbcb-0080c76670c0":     "Site NNTP Protocol objects",
	"bf967ab3-0de6-11d0-a285-00aa003049e2":     "Site objects",
	"a8df74cf-c5ea-11d1-bbcb-0080c76670c0":     "Site POP Protocol objects",
	"a8df74d2-c5ea-11d1-bbcb-0080c76670c0":     "Site Protocols objects",
	"99f5867b-12e8-11d3-aa58-00c04f8eedd8":     "Site Replication Service objects",
	"19195a5d-6da0-11d0-afd3-00c04fd930c9":     "Site Settings objects",
	"32f0e47a-a982-11d2-a9ff-00c04f8eedd8":     "Site SMTP Protocol objects",
	"7a4117da-cd67-11d0-afff-0000f80367c1":     "Sites Container objects",
	"89baf7be-b09e-11d2-aa06-00c04f8eedd8":     "SMTP Connector objects",
	"33d82894-a982-11d2-a9ff-00c04f8eedd8":     "SMTP Domain objects",
	"33bb8c5c-a982-11d2-a9ff-00c04f8eedd8":     "SMTP Domains objects",
	"359f89ba-a982-11d2-a9ff-00c04f8eedd8":     "SMTP Policy objects",
	"93bb9552-b09e-11d2-aa06-00c04f8eedd8":     "SMTP Protocol objects",
	"3397c916-a982-11d2-a9ff-00c04f8eedd8":     "SMTP Routing Sources objects",
	"8ef628c6-b093-11d2-aa06-00c04f8eedd8":     "SMTP Sessions objects",
	"0b836da5-3b20-11d3-aa6f-00c04f8eedd8":     "SMTP Turf List objects",
	"3378ca84-a982-11d2-a9ff-00c04f8eedd8":     "SMTP Virtual Server objects",
	"3435244a-a982-11d2-a9ff-00c04f8eedd8":     "Storage Group objects",
	"bf967ab5-0de6-11d0-a285-00aa003049e2":     "storage objects",
	"b7b13124-b82e-11d0-afee-0000f80367c1":     "Subnet objects",
	"b7b13125-b82e-11d0-afee-0000f80367c1":     "Subnets Container objects",
	"5a8b3261-c38d-11d1-bbc9-0080c76670c0":     "subschema objects",
	"a8df74b2-c5ea-11d1-bbcb-0080c76670c0":     "System Attendant objects",
	"32412a7a-22af-479c-a444-624c0137122e":     "System Policies objects",
	"ba085a33-8807-4c6c-9522-2cf5a2a5e9c2":     "System Policy objects",
	"a8df74d7-c5ea-11d1-bbcb-0080c76670c0":     "TCP (RFC1006) MTA Transport Stack objects",
	"a8df74d8-c5ea-11d1-bbcb-0080c76670c0":     "TCP (RFC1006) X.400 Connector objects",
	"bf967ab7-0de6-11d0-a285-00aa003049e2":     "top objects",
	"a8df74db-c5ea-11d1-bbcb-0080c76670c0":     "TP4 MTA Transport Stack objects",
	"a8df74dc-c5ea-11d1-bbcb-0080c76670c0":     "TP4 X.400 Connector objects",
	"a8df74dd-c5ea-11d1-bbcb-0080c76670c0":     "transportStack objects",
	"bf967ab8-0de6-11d0-a285-00aa003049e2":     "Trusted Domain objects",
	"281416e2-1968-11d0-a28f-00aa003049e2":     "typeLibrary objects",
	"bf967aba-0de6-11d0-a285-00aa003049e2":     "User objects",
	"99f5866d-12e8-11d3-aa58-00c04f8eedd8":     "Video Conference Technology Provider objects",
	"ea5ed15a-a980-11d2-a9ff-00c04f8eedd8":     "Virtual Chat Network objects",
	"a8df74de-c5ea-11d1-bbcb-0080c76670c0":     "X.25 MTA Transport Stack objects",
	"a8df74df-c5ea-11d1-bbcb-0080c76670c0":     "X.25 X.400 Connector objects",
	"a8df74e0-c5ea-11d1-bbcb-0080c76670c0":     "x400Link objects",
}
