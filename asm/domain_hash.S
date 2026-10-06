/* AArch64 DJB2, identical to the unsigned-long C fallback */

.text
.p2align 2
.globl domain_hash
.type domain_hash, %function

domain_hash:
	mov	x1, #5381
1:
	ldrb	w2, [x0], #1
	cbz	w2, 2f
	add	x1, x1, x1, lsl, #5
	add	x1, x1, x2
	b	1b
2:
	mov	x0, x1
	ret

.size domain_hash, .-domain_hash
.section .note.GNU-stack,"",%progbits