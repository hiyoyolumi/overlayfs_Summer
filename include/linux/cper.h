/*
 * UEFI Common Platform Error Record
 *
 * Copyright (C) 2010, Intel Corp.
 *	Author: Huang Ying <ying.huang@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef LINUX_CPER_H
#define LINUX_CPER_H

#include <linux/uuid.h>
#include <linux/trace_seq.h>

/* CPER record signature and the size */
#define CPER_SIG_RECORD				"CPER"
#define CPER_SIG_SIZE				4
/* Used in signature_end field in struct cper_record_header */
#define CPER_SIG_END				0xffffffff

/*
 * CPER record header revision, used in revision field in struct
 * cper_record_header
 */
#define CPER_RECORD_REV				0x0100

/*
 * CPER record length contains the CPER fields which are relevant for further
 * handling of a memory error in userspace (we don't carry all the fields
 * defined in the UEFI spec because some of them don't make any sense.)
 * Currently, a length of 256 should be more than enough.
 */
#define CPER_REC_LEN					256
/*
 * Severity difinition for error_severity in struct cper_record_header
 * and section_severity in struct cper_section_descriptor
 */
enum {
	CPER_SEV_RECOVERABLE,
	CPER_SEV_FATAL,
	CPER_SEV_CORRECTED,
	CPER_SEV_INFORMATIONAL,
};

/*
 * Validation bits difinition for validation_bits in struct
 * cper_record_header. If set, corresponding fields in struct
 * cper_record_header contain valid information.
 *
 * corresponds platform_id
 */
#define CPER_VALID_PLATFORM_ID			0x0001
/* corresponds timestamp */
#define CPER_VALID_TIMESTAMP			0x0002
/* corresponds partition_id */
#define CPER_VALID_PARTITION_ID			0x0004

/*
 * Notification type used to generate error record, used in
 * notification_type in struct cper_record_header
 *
 * Corrected Machine Check
 */
#define CPER_NOTIFY_CMC							\
	GUID_INIT(0x2DCE8BB1, 0xBDD7, 0x450e, 0xB9, 0xAD, 0x9C, 0xF4,	\
		  0xEB, 0xD4, 0xF8, 0x90)
/* Corrected Platform Error */
#define CPER_NOTIFY_CPE							\
	GUID_INIT(0x4E292F96, 0xD843, 0x4a55, 0xA8, 0xC2, 0xD4, 0x81,	\
		  0xF2, 0x7E, 0xBE, 0xEE)
/* Machine Check Exception */
#define CPER_NOTIFY_MCE							\
	GUID_INIT(0xE8F56FFE, 0x919C, 0x4cc5, 0xBA, 0x88, 0x65, 0xAB,	\
		  0xE1, 0x49, 0x13, 0xBB)
/* PCI Express Error */
#define CPER_NOTIFY_PCIE						\
	GUID_INIT(0xCF93C01F, 0x1A16, 0x4dfc, 0xB8, 0xBC, 0x9C, 0x4D,	\
		  0xAF, 0x67, 0xC1, 0x04)
/* INIT Record (for IPF) */
#define CPER_NOTIFY_INIT						\
	GUID_INIT(0xCC5263E8, 0x9308, 0x454a, 0x89, 0xD0, 0x34, 0x0B,	\
		  0xD3, 0x9B, 0xC9, 0x8E)
/* Non-Maskable Interrupt */
#define CPER_NOTIFY_NMI							\
	GUID_INIT(0x5BAD89FF, 0xB7E6, 0x42c9, 0x81, 0x4A, 0xCF, 0x24,	\
		  0x85, 0xD6, 0xE9, 0x8A)
/* BOOT Error Record */
#define CPER_NOTIFY_BOOT						\
	GUID_INIT(0x3D61A466, 0xAB40, 0x409a, 0xA6, 0x98, 0xF3, 0x62,	\
		  0xD4, 0x64, 0xB3, 0x8F)
/* DMA Remapping Error */
#define CPER_NOTIFY_DMAR						\
	GUID_INIT(0x667DD791, 0xC6B3, 0x4c27, 0x8A, 0x6B, 0x0F, 0x8E,	\
		  0x72, 0x2D, 0xEB, 0x41)

/*
 * Flags bits definitions for flags in struct cper_record_header
 * If set, the error has been recovered
 */
#define CPER_HW_ERROR_FLAGS_RECOVERED		0x1
/* If set, the error is for previous boot */
#define CPER_HW_ERROR_FLAGS_PREVERR		0x2
/* If set, the error is injected for testing */
#define CPER_HW_ERROR_FLAGS_SIMULATED		0x4

/*
 * CPER section header revision, used in revision field in struct
 * cper_section_descriptor
 */
#define CPER_SEC_REV				0x0100

/*
 * Validation bits difinition for validation_bits in struct
 * cper_section_descriptor. If set, corresponding fields in struct
 * cper_section_descriptor contain valid information.
 *
 * corresponds fru_id
 */
#define CPER_SEC_VALID_FRU_ID			0x1
/* corresponds fru_text */
#define CPER_SEC_VALID_FRU_TEXT			0x2

/*
 * Flags bits definitions for flags in struct cper_section_descriptor
 *
 * If set, the section is associated with the error condition
 * directly, and should be focused on
 */
#define CPER_SEC_PRIMARY			0x0001
/*
 * If set, the error was not contained within the processor or memory
 * hierarchy and the error may have propagated to persistent storage
 * or network
 */
#define CPER_SEC_CONTAINMENT_WARNING		0x0002
/* If set, the component must be re-initialized or re-enabled prior to use */
#define CPER_SEC_RESET				0x0004
/* If set, Linux may choose to discontinue use of the resource */
#define CPER_SEC_ERROR_THRESHOLD_EXCEEDED	0x0008
/*
 * If set, resource could not be queried for error information due to
 * conflicts with other system software or resources. Some fields of
 * the section will be invalid
 */
#define CPER_SEC_RESOURCE_NOT_ACCESSIBLE	0x0010
/*
 * If set, action has been taken to ensure error containment (such as
 * poisoning data), but the error has not been fully corrected and the
 * data has not been consumed. Linux may choose to take further
 * corrective action before the data is consumed
 */
#define CPER_SEC_LATENT_ERROR			0x0020

/*
 * Section type definitions, used in section_type field in struct
 * cper_section_descriptor
 *
 * Processor Generic
 */
#define CPER_SEC_PROC_GENERIC						\
	GUID_INIT(0x9876CCAD, 0x47B4, 0x4bdb, 0xB6, 0x5E, 0x16, 0xF1,	\
		  0x93, 0xC4, 0xF3, 0xDB)
/* Processor Specific: X86/X86_64 */
#define CPER_SEC_PROC_IA						\
	GUID_INIT(0xDC3EA0B0, 0xA144, 0x4797, 0xB9, 0x5B, 0x53, 0xFA,	\
		  0x24, 0x2B, 0x6E, 0x1D)
/* Processor Specific: IA64 */
#define CPER_SEC_PROC_IPF						\
	GUID_INIT(0xE429FAF1, 0x3CB7, 0x11D4, 0x0B, 0xCA, 0x07, 0x00,	\
		  0x80, 0xC7, 0x3C, 0x88, 0x81)
/* Processor Specific: ARM */
#define CPER_SEC_PROC_ARM						\
	GUID_INIT(0xE19E3D16, 0xBC11, 0x11E4, 0x9C, 0xAA, 0xC2, 0x05,	\
		  0x1D, 0x5D, 0x46, 0xB0)
/* Platform Memory */
#define CPER_SEC_PLATFORM_MEM						\
	GUID_INIT(0xA5BC1114, 0x6F64, 0x4EDE, 0xB8, 0x63, 0x3E, 0x83,	\
		  0xED, 0x7C, 0x83, 0xB1)
#define CPER_SEC_PCIE							\
	GUID_INIT(0xD995E954, 0xBBC1, 0x430F, 0xAD, 0x91, 0xB4, 0x4D,	\
		  0xCB, 0x3C, 0x6F, 0x35)
/* Firmware Error Record Reference */
#define CPER_SEC_FW_ERR_REC_REF						\
	GUID_INIT(0x81212A96, 0x09ED, 0x4996, 0x94, 0x71, 0x8D, 0x72,	\
		  0x9C, 0x8E, 0x69, 0xED)
/* PCI/PCI-X Bus */
#define CPER_SEC_PCI_X_BUS						\
	GUID_INIT(0xC5753963, 0x3B84, 0x4095, 0xBF, 0x78, 0xED, 0xDA,	\
		  0xD3, 0xF9, 0xC9, 0xDD)
/* PCI Component/Device */
#define CPER_SEC_PCI_DEV						\
	GUID_INIT(0xEB5E4685, 0xCA66, 0x4769, 0xB6, 0xA2, 0x26, 0x06,	\
		  0x8B, 0x00, 0x13, 0x26)
#define CPER_SEC_DMAR_GENERIC						\
	GUID_INIT(0x5B51FEF7, 0xC79D, 0x4434, 0x8F, 0x1B, 0xAA, 0x62,	\
		  0xDE, 0x3E, 0x2C, 0x64)
/* Intel VT for Directed I/O specific DMAr */
#define CPER_SEC_DMAR_VT						\
	GUID_INIT(0x71761D37, 0x32B2, 0x45cd, 0xA7, 0xD0, 0xB0, 0xFE,	\
		  0xDD, 0x93, 0xE8, 0xCF)
/* IOMMU specific DMAr */
#define CPER_SEC_DMAR_IOMMU						\
	GUID_INIT(0x036F84E1, 0x7F37, 0x428c, 0xA7, 0x9E, 0x57, 0x5F,	\
		  0xDF, 0xAA, 0x84, 0xEC)
/* HISI ts core */
#define CPER_SEC_TS_CORE						\
	GUID_INIT(0xeb4c71f8, 0xbc76, 0x4c46, 0xbd, 0x9, 0xd0, 0xd3,	\
		  0x45, 0x0, 0x5a, 0x92)

#define CPER_PROC_VALID_TYPE			0x0001
#define CPER_PROC_VALID_ISA			0x0002
#define CPER_PROC_VALID_ERROR_TYPE		0x0004
#define CPER_PROC_VALID_OPERATION		0x0008
#define CPER_PROC_VALID_FLAGS			0x0010
#define CPER_PROC_VALID_LEVEL			0x0020
#define CPER_PROC_VALID_VERSION			0x0040
#define CPER_PROC_VALID_BRAND_INFO		0x0080
#define CPER_PROC_VALID_ID			0x0100
#define CPER_PROC_VALID_TARGET_ADDRESS		0x0200
#define CPER_PROC_VALID_REQUESTOR_ID		0x0400
#define CPER_PROC_VALID_RESPONDER_ID		0x0800
#define CPER_PROC_VALID_IP			0x1000

#define CPER_MEM_VALID_ERROR_STATUS		0x0001
#define CPER_MEM_VALID_PA			0x0002
#define CPER_MEM_VALID_PA_MASK			0x0004
#define CPER_MEM_VALID_NODE			0x0008
#define CPER_MEM_VALID_CARD			0x0010
#define CPER_MEM_VALID_MODULE			0x0020
#define CPER_MEM_VALID_BANK			0x0040
#define CPER_MEM_VALID_DEVICE			0x0080
#define CPER_MEM_VALID_ROW			0x0100
#define CPER_MEM_VALID_COLUMN			0x0200
#define CPER_MEM_VALID_BIT_POSITION		0x0400
#define CPER_MEM_VALID_REQUESTOR_ID		0x0800
#define CPER_MEM_VALID_RESPONDER_ID		0x1000
#define CPER_MEM_VALID_TARGET_ID		0x2000
#define CPER_MEM_VALID_ERROR_TYPE		0x4000
#define CPER_MEM_VALID_RANK_NUMBER		0x8000
#define CPER_MEM_VALID_CARD_HANDLE		0x10000
#define CPER_MEM_VALID_MODULE_HANDLE		0x20000

#define CPER_PCIE_VALID_PORT_TYPE		0x0001
#define CPER_PCIE_VALID_VERSION			0x0002
#define CPER_PCIE_VALID_COMMAND_STATUS		0x0004
#define CPER_PCIE_VALID_DEVICE_ID		0x0008
#define CPER_PCIE_VALID_SERIAL_NUMBER		0x0010
#define CPER_PCIE_VALID_BRIDGE_CONTROL_STATUS	0x0020
#define CPER_PCIE_VALID_CAPABILITY		0x0040
#define CPER_PCIE_VALID_AER_INFO		0x0080

#define CPER_PCIE_SLOT_SHIFT			3

#define CPER_ARM_VALID_MPIDR			BIT(0)
#define CPER_ARM_VALID_AFFINITY_LEVEL		BIT(1)
#define CPER_ARM_VALID_RUNNING_STATE		BIT(2)
#define CPER_ARM_VALID_VENDOR_INFO		BIT(3)

#define CPER_ARM_INFO_VALID_MULTI_ERR		BIT(0)
#define CPER_ARM_INFO_VALID_FLAGS		BIT(1)
#define CPER_ARM_INFO_VALID_ERR_INFO		BIT(2)
#define CPER_ARM_INFO_VALID_VIRT_ADDR		BIT(3)
#define CPER_ARM_INFO_VALID_PHYSICAL_ADDR	BIT(4)

#define CPER_ARM_INFO_FLAGS_FIRST		BIT(0)
#define CPER_ARM_INFO_FLAGS_LAST		BIT(1)
#define CPER_ARM_INFO_FLAGS_PROPAGATED		BIT(2)
#define CPER_ARM_INFO_FLAGS_OVERFLOW		BIT(3)

#define CPER_ARM_CACHE_ERROR			0
#define CPER_ARM_TLB_ERROR			1
#define CPER_ARM_BUS_ERROR			2
#define CPER_ARM_VENDOR_ERROR			3
#define CPER_ARM_MAX_TYPE			CPER_ARM_VENDOR_ERROR

#define CPER_ARM_ERR_VALID_TRANSACTION_TYPE	BIT(0)
#define CPER_ARM_ERR_VALID_OPERATION_TYPE	BIT(1)
#define CPER_ARM_ERR_VALID_LEVEL		BIT(2)
#define CPER_ARM_ERR_VALID_PROC_CONTEXT_CORRUPT	BIT(3)
#define CPER_ARM_ERR_VALID_CORRECTED		BIT(4)
#define CPER_ARM_ERR_VALID_PRECISE_PC		BIT(5)
#define CPER_ARM_ERR_VALID_RESTARTABLE_PC	BIT(6)
#define CPER_ARM_ERR_VALID_PARTICIPATION_TYPE	BIT(7)
#define CPER_ARM_ERR_VALID_TIME_OUT		BIT(8)
#define CPER_ARM_ERR_VALID_ADDRESS_SPACE	BIT(9)
#define CPER_ARM_ERR_VALID_MEM_ATTRIBUTES	BIT(10)
#define CPER_ARM_ERR_VALID_ACCESS_MODE		BIT(11)

#define CPER_ARM_ERR_TRANSACTION_SHIFT		16
#define CPER_ARM_ERR_TRANSACTION_MASK		GENMASK(1,0)
#define CPER_ARM_ERR_OPERATION_SHIFT		18
#define CPER_ARM_ERR_OPERATION_MASK		GENMASK(3,0)
#define CPER_ARM_ERR_LEVEL_SHIFT		22
#define CPER_ARM_ERR_LEVEL_MASK			GENMASK(2,0)
#define CPER_ARM_ERR_PC_CORRUPT_SHIFT		25
#define CPER_ARM_ERR_PC_CORRUPT_MASK		GENMASK(0,0)
#define CPER_ARM_ERR_CORRECTED_SHIFT		26
#define CPER_ARM_ERR_CORRECTED_MASK		GENMASK(0,0)
#define CPER_ARM_ERR_PRECISE_PC_SHIFT		27
#define CPER_ARM_ERR_PRECISE_PC_MASK		GENMASK(0,0)
#define CPER_ARM_ERR_RESTARTABLE_PC_SHIFT	28
#define CPER_ARM_ERR_RESTARTABLE_PC_MASK	GENMASK(0,0)
#define CPER_ARM_ERR_PARTICIPATION_TYPE_SHIFT	29
#define CPER_ARM_ERR_PARTICIPATION_TYPE_MASK	GENMASK(1,0)
#define CPER_ARM_ERR_TIME_OUT_SHIFT		31
#define CPER_ARM_ERR_TIME_OUT_MASK		GENMASK(0,0)
#define CPER_ARM_ERR_ADDRESS_SPACE_SHIFT	32
#define CPER_ARM_ERR_ADDRESS_SPACE_MASK		GENMASK(1,0)
#define CPER_ARM_ERR_MEM_ATTRIBUTES_SHIFT	34
#define CPER_ARM_ERR_MEM_ATTRIBUTES_MASK	GENMASK(8,0)
#define CPER_ARM_ERR_ACCESS_MODE_SHIFT		43
#define CPER_ARM_ERR_ACCESS_MODE_MASK		GENMASK(0,0)

/*
 * All tables and structs must be byte-packed to match CPER
 * specification, since the tables are provided by the system BIOS
 */
#pragma pack(1)

struct cper_record_header {
	char	signature[CPER_SIG_SIZE];	/* must be CPER_SIG_RECORD */
	__u16	revision;			/* must be CPER_RECORD_REV */
	__u32	signature_end;			/* must be CPER_SIG_END */
	__u16	section_count;
	__u32	error_severity;
	__u32	validation_bits;
	__u32	record_length;
	__u64	timestamp;
	guid_t	platform_id;
	guid_t	partition_id;
	guid_t	creator_id;
	guid_t	notification_type;
	__u64	record_id;
	__u32	flags;
	__u64	persistence_information;
	__u8	reserved[12];			/* must be zero */
};

struct cper_section_descriptor {
	__u32	section_offset;		/* Offset in bytes of the
					 *  section body from the base
					 *  of the record header */
	__u32	section_length;
	__u16	revision;		/* must be CPER_RECORD_REV */
	__u8	validation_bits;
	__u8	reserved;		/* must be zero */
	__u32	flags;
	guid_t	section_type;
	guid_t	fru_id;
	__u32	section_severity;
	__u8	fru_text[20];
};

/* Generic Processor Error Section */
struct cper_sec_proc_generic {
	__u64	validation_bits;
	__u8	proc_type;
	__u8	proc_isa;
	__u8	proc_error_type;
	__u8	operation;
	__u8	flags;
	__u8	level;
	__u16	reserved;
	__u64	cpu_version;
	char	cpu_brand[128];
	__u64	proc_id;
	__u64	target_addr;
	__u64	requestor_id;
	__u64	responder_id;
	__u64	ip;
};

/* IA32/X64 Processor Error Section */
struct cper_sec_proc_ia {
	__u64	validation_bits;
	__u64	lapic_id;
	__u8	cpuid[48];
};

/* IA32/X64 Processor Error Information Structure */
struct cper_ia_err_info {
	guid_t	err_type;
	__u64	validation_bits;
	__u64	check_info;
	__u64	target_id;
	__u64	requestor_id;
	__u64	responder_id;
	__u64	ip;
};

/* IA32/X64 Processor Context Information Structure */
struct cper_ia_proc_ctx {
	__u16	reg_ctx_type;
	__u16	reg_arr_size;
	__u32	msr_addr;
	__u64	mm_reg_addr;
};

/* ARM Processor Error Section */
struct cper_sec_proc_arm {
	__u32	validation_bits;
	__u16	err_info_num;		/* Number of Processor Error Info */
	__u16	context_info_num;	/* Number of Processor Context Info Records*/
	__u32	section_length;
	__u8	affinity_level;
	__u8	reserved[3];		/* must be zero */
	__u64	mpidr;
	__u64	midr;
	__u32	running_state;		/* Bit 0 set - Processor running. PSCI = 0 */
	__u32	psci_state;
};

/* ARM Processor Error Information Structure */
struct cper_arm_err_info {
	__u8	version;
	__u8	length;
	__u16	validation_bits;
	__u8	type;
	__u16	multiple_error;
	__u8	flags;
	__u64	error_info;
	__u64	virt_fault_addr;
	__u64	physical_fault_addr;
};

/* ARM Processor Context Information Structure */
struct cper_arm_ctx_info {
	__u16	version;
	__u16	type;
	__u32	size;
};

/* Old Memory Error Section UEFI 2.1, 2.2 */
struct cper_sec_mem_err_old {
	__u64	validation_bits;
	__u64	error_status;
	__u64	physical_addr;
	__u64	physical_addr_mask;
	__u16	node;
	__u16	card;
	__u16	module;
	__u16	bank;
	__u16	device;
	__u16	row;
	__u16	column;
	__u16	bit_pos;
	__u64	requestor_id;
	__u64	responder_id;
	__u64	target_id;
	__u8	error_type;
};

/* Memory Error Section UEFI >= 2.3 */
struct cper_sec_mem_err {
	__u64	validation_bits;
	__u64	error_status;
	__u64	physical_addr;
	__u64	physical_addr_mask;
	__u16	node;
	__u16	card;
	__u16	module;
	__u16	bank;
	__u16	device;
	__u16	row;
	__u16	column;
	__u16	bit_pos;
	__u64	requestor_id;
	__u64	responder_id;
	__u64	target_id;
	__u8	error_type;
	__u8	reserved;
	__u16	rank;
	__u16	mem_array_handle;	/* card handle in UEFI 2.4 */
	__u16	mem_dev_handle;		/* module handle in UEFI 2.4 */
};

struct cper_mem_err_compact {
	__u64	validation_bits;
	__u16	node;
	__u16	card;
	__u16	module;
	__u16	bank;
	__u16	device;
	__u16	row;
	__u16	column;
	__u16	bit_pos;
	__u64	requestor_id;
	__u64	responder_id;
	__u64	target_id;
	__u16	rank;
	__u16	mem_array_handle;
	__u16	mem_dev_handle;
};

struct cper_sec_pcie {
	__u64		validation_bits;
	__u32		port_type;
	struct {
		__u8	minor;
		__u8	major;
		__u8	reserved[2];
	}		version;
	__u16		command;
	__u16		status;
	__u32		reserved;
	struct {
		__u16	vendor_id;
		__u16	device_id;
		__u8	class_code[3];
		__u8	function;
		__u8	device;
		__u16	segment;
		__u8	bus;
		__u8	secondary_bus;
		__u16	slot;
		__u8	reserved;
	}		device_id;
	struct {
		__u32	lower;
		__u32	upper;
	}		serial_number;
	struct {
		__u16	secondary_status;
		__u16	control;
	}		bridge;
	__u8	capability[60];
	__u8	aer_info[96];
};

/* Reset to default packing */
#pragma pack()

extern const char * const cper_proc_error_type_strs[4];

u64 cper_next_record_id(void);
const char *cper_severity_str(unsigned int);
const char *cper_mem_err_type_str(unsigned int);
void cper_print_bits(const char *prefix, unsigned int bits,
		     const char * const strs[], unsigned int strs_size);
void cper_mem_err_pack(const struct cper_sec_mem_err *,
		       struct cper_mem_err_compact *);
const char *cper_mem_err_unpack(struct trace_seq *,
				struct cper_mem_err_compact *);
void cper_print_proc_arm(const char *pfx,
			 const struct cper_sec_proc_arm *proc);
void cper_print_proc_ia(const char *pfx,
			const struct cper_sec_proc_ia *proc);

#endif
