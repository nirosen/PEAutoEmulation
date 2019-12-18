//////////////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (C) 2000 Microsoft Corporation
//
// Module Name:
// WmiApRpl
//
// Abstract:
//
// Include file for object and counters definitions.
//
//////////////////////////////////////////////////////////////////////////////////////////////


#define	WMI_Objects	0
#define	HiPerf_Classes	2
#define	HiPerf_Validity	4

#define	MSiSCSI_ConnectionStatistics_00000	6

#define	BytesReceived_00000	8
#define	BytesSent_00000	10
#define	PDUCommandsSent_00000	12
#define	PDUResponsesReceived_00000	14

#define	MSiSCSI_InitiatorInstanceStatistics_00001	16

#define	SessionConnectionTimeoutErrorCount_00001	18
#define	SessionDigestErrorCount_00001	20
#define	SessionFailureCount_00001	22
#define	SessionFormatErrorCount_00001	24

#define	MSiSCSI_InitiatorLoginStatistics_00002	26

#define	LoginAcceptRsps_00002	28
#define	LoginAuthenticateFails_00002	30
#define	LoginAuthFailRsps_00002	32
#define	LoginFailures_00002	34
#define	LoginNegotiateFails_00002	36
#define	LoginOtherFailRsps_00002	38
#define	LoginRedirectRsps_00002	40
#define	LogoutNormals_00002	42
#define	LogoutOtherCodes_00002	44

#define	MSiSCSI_MMIPSECStats_00003	46

#define	AcquireFailures_00003	48
#define	AcquireHeapSize_00003	50
#define	ActiveAcquire_00003	52
#define	ActiveReceive_00003	54
#define	AuthenticationFailures_00003	56
#define	ConnectionListSize_00003	58
#define	GetSPIFailures_00003	60
#define	InvalidCookiesReceived_00003	62
#define	InvalidPackets_00003	64
#define	KeyAdditionFailures_00003	66
#define	KeyAdditions_00003	68
#define	KeyUpdateFailures_00003	70
#define	KeyUpdates_00003	72
#define	NegotiationFailures_00003	74
#define	OakleyMainMode_00003	76
#define	OakleyQuickMode_00003	78
#define	ReceiveFailures_00003	80
#define	ReceiveHeapSize_00003	82
#define	SendFailures_00003	84
#define	SoftAssociations_00003	86
#define	TotalGetSPI_00003	88

#define	MSiSCSI_NICPerformance_00004	90

#define	BytesReceived_00004	92
#define	BytesTransmitted_00004	94
#define	PDUReceived_00004	96
#define	PDUTransmitted_00004	98

#define	MSiSCSI_QMIPSECStats_00005	100

#define	ActiveSA_00005	102
#define	ActiveTunnels_00005	104
#define	AuthenticatedBytesReceived_00005	106
#define	AuthenticatedBytesSent_00005	108
#define	BadSPIPackets_00005	110
#define	ConfidentialBytesReceived_00005	112
#define	ConfidentialBytesSent_00005	114
#define	KeyAdditions_00005	116
#define	KeyDeletions_00005	118
#define	PacketsNotAuthenticated_00005	120
#define	PacketsNotDecrypted_00005	122
#define	PacketsWithReplayDetection_00005	124
#define	PendingKeyOperations_00005	126
#define	ReKeys_00005	128
#define	TransportBytesReceived_00005	130
#define	TransportBytesSent_00005	132
#define	TunnelBytesReceived_00005	134
#define	TunnelBytesSent_00005	136

#define	MSiSCSI_RequestTimeStatistics_00006	138

#define	AverageProcessingTime_00006	140
#define	MaximumProcessingTime_00006	142

#define	MSiSCSI_SessionStatistics_00007	144

#define	BytesReceived_00007	146
#define	BytesSent_00007	148
#define	ConnectionTimeoutErrors_00007	150
#define	DigestErrors_00007	152
#define	FormatErrors_00007	154
#define	PDUCommandsSent_00007	156
#define	PDUResponsesReceived_00007	158

#define	ProcessorPerformance_00008	160

#define	frequency_00008	162
#define	percentage_00008	164
#define	power_00008	166
