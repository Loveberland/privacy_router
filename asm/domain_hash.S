/*
 * Assembly AArch64
 * calculating hash of domain name with DJB2
 */

.text
.align 2
.globl domain_hash
.type domain_hash, %function

domain_hash:
	mov	x1, #5381
1:
	ldrb	w2, [x0], #1
	cbz	w2, 2f
	lsl	x3, x1, #5
	add	x1, x3, x1
	add	x1, x1, x2
	b	1b
2:
	mov	x0, x1
	ret

.size	domain_hash, .-domain_hash