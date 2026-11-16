// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE-GO file.

// Adapted from Go's crypto/internal/fips140/sha3/sha3_arm64.s (go1.25.5): the
// same rounds, whose instructions all work on both 64-bit halves of a register,
// over two states at once. Lane i of both states is loaded into Vi.

//go:build arm64 && !purego

#include "textflag.h"

// ROUND is one round of Keccak-f[1600] over V0-V24, V25-V31 its scratch, R1 the
// address of its round constant, which it advances.
#define ROUND \
	VEOR3	 V20.B16, V15.B16, V10.B16, V25.B16; \
	VEOR3	 V21.B16, V16.B16, V11.B16, V26.B16; \
	VEOR3	 V22.B16, V17.B16, V12.B16, V27.B16; \
	VEOR3	 V23.B16, V18.B16, V13.B16, V28.B16; \
	VEOR3	 V24.B16, V19.B16, V14.B16, V29.B16; \
	VEOR3	 V25.B16, V5.B16, V0.B16, V25.B16; \
	VEOR3	 V26.B16, V6.B16, V1.B16, V26.B16; \
	VEOR3	 V27.B16, V7.B16, V2.B16, V27.B16; \
	VEOR3	 V28.B16, V8.B16, V3.B16, V28.B16; \
	VEOR3	 V29.B16, V9.B16, V4.B16, V29.B16; \
	VRAX1	V27.D2, V25.D2, V30.D2; \
	VRAX1	V28.D2, V26.D2, V31.D2; \
	VRAX1	V29.D2, V27.D2, V27.D2; \
	VRAX1	V25.D2, V28.D2, V28.D2; \
	VRAX1	V26.D2, V29.D2, V29.D2; \
	VEOR	V29.B16, V0.B16, V0.B16; \
	VXAR	$63, V30.D2, V1.D2, V25.D2; \
	VXAR	$20, V30.D2, V6.D2, V1.D2; \
	VXAR	$44, V28.D2, V9.D2, V6.D2; \
	VXAR	$3, V31.D2, V22.D2, V9.D2; \
	VXAR	$25, V28.D2, V14.D2, V22.D2; \
	VXAR	$46, V29.D2, V20.D2, V14.D2; \
	VXAR	$2, V31.D2, V2.D2, V26.D2; \
	VXAR	$21, V31.D2, V12.D2, V2.D2; \
	VXAR	$39, V27.D2, V13.D2, V12.D2; \
	VXAR	$56, V28.D2, V19.D2, V13.D2; \
	VXAR	$8, V27.D2, V23.D2, V19.D2; \
	VXAR	$23, V29.D2, V15.D2, V23.D2; \
	VXAR	$37, V28.D2, V4.D2, V15.D2; \
	VXAR	$50, V28.D2, V24.D2, V28.D2; \
	VXAR	$62, V30.D2, V21.D2, V24.D2; \
	VXAR	$9, V27.D2, V8.D2, V8.D2; \
	VXAR	$19, V30.D2, V16.D2, V4.D2; \
	VXAR	$28, V29.D2, V5.D2, V16.D2; \
	VXAR	$36, V27.D2, V3.D2, V5.D2; \
	VXAR	$43, V27.D2, V18.D2, V27.D2; \
	VXAR	$49, V31.D2, V17.D2, V3.D2; \
	VXAR	$54, V30.D2, V11.D2, V30.D2; \
	VXAR	$58, V31.D2, V7.D2, V31.D2; \
	VXAR	$61, V29.D2, V10.D2, V29.D2; \
	VBCAX	V8.B16, V22.B16, V26.B16, V20.B16; \
	VBCAX	V22.B16, V23.B16, V8.B16, V21.B16; \
	VBCAX	V23.B16, V24.B16, V22.B16, V22.B16; \
	VBCAX	V24.B16, V26.B16, V23.B16, V23.B16; \
	VBCAX	V26.B16, V8.B16, V24.B16, V24.B16; \
	VLD1R.P	8(R1), [V26.D2]; \
	VBCAX	V3.B16, V19.B16, V30.B16, V17.B16; \
	VBCAX	V19.B16, V15.B16, V3.B16, V18.B16; \
	VBCAX	V15.B16, V16.B16, V19.B16, V19.B16; \
	VBCAX	V16.B16, V30.B16, V15.B16, V15.B16; \
	VBCAX	V30.B16, V3.B16, V16.B16, V16.B16; \
	VBCAX	V31.B16, V12.B16, V25.B16, V10.B16; \
	VBCAX	V12.B16, V13.B16, V31.B16, V11.B16; \
	VBCAX	V13.B16, V14.B16, V12.B16, V12.B16; \
	VBCAX	V14.B16, V25.B16, V13.B16, V13.B16; \
	VBCAX	V25.B16, V31.B16, V14.B16, V14.B16; \
	VBCAX	V4.B16, V9.B16, V29.B16, V7.B16; \
	VBCAX	V9.B16, V5.B16, V4.B16, V8.B16; \
	VBCAX	V5.B16, V6.B16, V9.B16, V9.B16; \
	VBCAX	V6.B16, V29.B16, V5.B16, V5.B16; \
	VBCAX	V29.B16, V4.B16, V6.B16, V6.B16; \
	VBCAX	V28.B16, V0.B16, V27.B16, V3.B16; \
	VBCAX	V0.B16, V1.B16, V28.B16, V4.B16; \
	VBCAX	V1.B16, V2.B16, V0.B16, V0.B16; \
	VBCAX	V2.B16, V27.B16, V1.B16, V1.B16; \
	VBCAX	V27.B16, V28.B16, V2.B16, V2.B16; \
	VEOR	V26.B16, V0.B16, V0.B16;


// func keccakF1600x2NEON(s *[50]uint64)
TEXT ·keccakF1600x2NEON(SB), NOSPLIT, $0-8
	MOVD	s+0(FP), R0
	MOVD	$round_consts<>(SB), R1
	MOVD	$24, R2 // counter for loop

	VLD1.P	64(R0), [V0.D2, V1.D2, V2.D2, V3.D2]
	VLD1.P	64(R0), [V4.D2, V5.D2, V6.D2, V7.D2]
	VLD1.P	64(R0), [V8.D2, V9.D2, V10.D2, V11.D2]
	VLD1.P	64(R0), [V12.D2, V13.D2, V14.D2, V15.D2]
	VLD1.P	64(R0), [V16.D2, V17.D2, V18.D2, V19.D2]
	VLD1.P	64(R0), [V20.D2, V21.D2, V22.D2, V23.D2]
	VLD1	(R0), [V24.D2]

	SUB	$384, R0, R0

loop:
	ROUND

	SUB		$1, R2, R2
	CBNZ	R2, loop

	VST1.P	[V0.D2, V1.D2, V2.D2, V3.D2], 64(R0)
	VST1.P	[V4.D2, V5.D2, V6.D2, V7.D2], 64(R0)
	VST1.P	[V8.D2, V9.D2, V10.D2, V11.D2], 64(R0)
	VST1.P	[V12.D2, V13.D2, V14.D2, V15.D2], 64(R0)
	VST1.P	[V16.D2, V17.D2, V18.D2, V19.D2], 64(R0)
	VST1.P	[V20.D2, V21.D2, V22.D2, V23.D2], 64(R0)
	VST1	[V24.D2], (R0)

	RET

// func searchNEON(base *[25]uint64, at int, r *[2]uint64, from, to uint64, out *[4]uint64) uint64
//
// For each even c in [from, to), it permutes two copies of base, the first with
// r + c and the second with r + c + 1 XORed into lanes at and at + 1, at 6 or 8.
// The last round computes lanes 0 and 1 only. It stops at the first c for which
// either state's lane 1 has its top 12 bits zero, which every codeword's has,
// writes lanes 0 and 1 of both states to out, and returns c. Otherwise, it
// returns -1.
TEXT ·searchNEON(SB), NOSPLIT, $0-56
	MOVD	base+0(FP), R0
	MOVD	at+8(FP), R3
	MOVD	r+16(FP), R9
	MOVD	0(R9), R4
	MOVD	8(R9), R5
	MOVD	from+24(FP), R6
	MOVD	to+32(FP), R7
	MOVD	out+40(FP), R8

trial:
	CMP	R7, R6
	BHS	none

	MOVD	R0, R9
	VLD1R.P	8(R9), [V0.D2]
	VLD1R.P	8(R9), [V1.D2]
	VLD1R.P	8(R9), [V2.D2]
	VLD1R.P	8(R9), [V3.D2]
	VLD1R.P	8(R9), [V4.D2]
	VLD1R.P	8(R9), [V5.D2]
	VLD1R.P	8(R9), [V6.D2]
	VLD1R.P	8(R9), [V7.D2]
	VLD1R.P	8(R9), [V8.D2]
	VLD1R.P	8(R9), [V9.D2]
	VLD1R.P	8(R9), [V10.D2]
	VLD1R.P	8(R9), [V11.D2]
	VLD1R.P	8(R9), [V12.D2]
	VLD1R.P	8(R9), [V13.D2]
	VLD1R.P	8(R9), [V14.D2]
	VLD1R.P	8(R9), [V15.D2]
	VLD1R.P	8(R9), [V16.D2]
	VLD1R.P	8(R9), [V17.D2]
	VLD1R.P	8(R9), [V18.D2]
	VLD1R.P	8(R9), [V19.D2]
	VLD1R.P	8(R9), [V20.D2]
	VLD1R.P	8(R9), [V21.D2]
	VLD1R.P	8(R9), [V22.D2]
	VLD1R.P	8(R9), [V23.D2]
	VLD1R	(R9), [V24.D2]

	// The two randomizers, r + c and r + c + 1, into V30 (low halves) and V31.
	ADDS	R6, R4, R10
	ADC	ZR, R5, R11
	ADD	$1, R6, R12
	ADDS	R12, R4, R12
	ADC	ZR, R5, R13
	VMOV	R10, V30.D[0]
	VMOV	R12, V30.D[1]
	VMOV	R11, V31.D[0]
	VMOV	R13, V31.D[1]

	CMP	$6, R3
	BEQ	at6
	VEOR	V30.B16, V8.B16, V8.B16
	VEOR	V31.B16, V9.B16, V9.B16
	B	permute

at6:
	VEOR	V30.B16, V6.B16, V6.B16
	VEOR	V31.B16, V7.B16, V7.B16

permute:
	MOVD	$round_consts<>(SB), R1
	MOVD	$23, R2

rounds:
	ROUND
	SUB	$1, R2, R2
	CBNZ	R2, rounds

	// The last round, for lanes 0 and 1: theta's column parities,
	VEOR3	V20.B16, V15.B16, V10.B16, V25.B16
	VEOR3	V21.B16, V16.B16, V11.B16, V26.B16
	VEOR3	V22.B16, V17.B16, V12.B16, V27.B16
	VEOR3	V23.B16, V18.B16, V13.B16, V28.B16
	VEOR3	V24.B16, V19.B16, V14.B16, V29.B16
	VEOR3	V25.B16, V5.B16, V0.B16, V25.B16
	VEOR3	V26.B16, V6.B16, V1.B16, V26.B16
	VEOR3	V27.B16, V7.B16, V2.B16, V27.B16
	VEOR3	V28.B16, V8.B16, V3.B16, V28.B16
	VEOR3	V29.B16, V9.B16, V4.B16, V29.B16

	// D1 into V30, D2 into V31, D3 into V27 and D0 into V29: D4 is not needed,
	VRAX1	V27.D2, V25.D2, V30.D2
	VRAX1	V28.D2, V26.D2, V31.D2
	VRAX1	V29.D2, V27.D2, V27.D2
	VRAX1	V26.D2, V29.D2, V29.D2

	// lanes (0, 0), (1, 1), (2, 2) and (3, 3), rho'd into the first row,
	VEOR	V29.B16, V0.B16, V0.B16
	VXAR	$20, V30.D2, V6.D2, V1.D2
	VXAR	$21, V31.D2, V12.D2, V2.D2
	VXAR	$43, V27.D2, V18.D2, V3.D2

	// then chi and iota of lanes 0 and 1.
	VLD1R	(R1), [V26.D2]
	VBCAX	V1.B16, V2.B16, V0.B16, V0.B16
	VBCAX	V2.B16, V3.B16, V1.B16, V1.B16
	VEOR	V26.B16, V0.B16, V0.B16

	VMOV	V1.D[0], R10
	VMOV	V1.D[1], R11
	LSR	$52, R10, R10
	LSR	$52, R11, R11
	CBZ	R10, found
	CBZ	R11, found
	ADD	$2, R6, R6
	B	trial

found:
	VST1	[V0.D2, V1.D2], (R8)
	MOVD	R6, ret+48(FP)
	RET

none:
	MOVD	$-1, R6
	MOVD	R6, ret+48(FP)
	RET

DATA	round_consts<>+0x00(SB)/8, $0x0000000000000001
DATA	round_consts<>+0x08(SB)/8, $0x0000000000008082
DATA	round_consts<>+0x10(SB)/8, $0x800000000000808a
DATA	round_consts<>+0x18(SB)/8, $0x8000000080008000
DATA	round_consts<>+0x20(SB)/8, $0x000000000000808b
DATA	round_consts<>+0x28(SB)/8, $0x0000000080000001
DATA	round_consts<>+0x30(SB)/8, $0x8000000080008081
DATA	round_consts<>+0x38(SB)/8, $0x8000000000008009
DATA	round_consts<>+0x40(SB)/8, $0x000000000000008a
DATA	round_consts<>+0x48(SB)/8, $0x0000000000000088
DATA	round_consts<>+0x50(SB)/8, $0x0000000080008009
DATA	round_consts<>+0x58(SB)/8, $0x000000008000000a
DATA	round_consts<>+0x60(SB)/8, $0x000000008000808b
DATA	round_consts<>+0x68(SB)/8, $0x800000000000008b
DATA	round_consts<>+0x70(SB)/8, $0x8000000000008089
DATA	round_consts<>+0x78(SB)/8, $0x8000000000008003
DATA	round_consts<>+0x80(SB)/8, $0x8000000000008002
DATA	round_consts<>+0x88(SB)/8, $0x8000000000000080
DATA	round_consts<>+0x90(SB)/8, $0x000000000000800a
DATA	round_consts<>+0x98(SB)/8, $0x800000008000000a
DATA	round_consts<>+0xA0(SB)/8, $0x8000000080008081
DATA	round_consts<>+0xA8(SB)/8, $0x8000000000008080
DATA	round_consts<>+0xB0(SB)/8, $0x0000000080000001
DATA	round_consts<>+0xB8(SB)/8, $0x8000000080008008
GLOBL	round_consts<>(SB), NOPTR|RODATA, $192
