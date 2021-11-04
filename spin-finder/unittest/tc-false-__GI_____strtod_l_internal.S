// TC_OUT
000000000003fb90 <__GI_____strtod_l_internal>:
   3fb90:	push   %r15
   3fb92:	push   %r14
   3fb94:	xor    %r15d,%r15d
   3fb97:	push   %r13
   3fb99:	push   %r12
   3fb9b:	mov    %rdi,%r14
   3fb9e:	push   %rbp
   3fb9f:	push   %rbx
   3fba0:	mov    %rcx,%r9
   3fba3:	sub    $0x448,%rsp
   3fbaa:	test   %edx,%edx
   3fbac:	mov    0x8(%rcx),%rax
   3fbb0:	mov    %rsi,(%rsp)
   3fbb4:	movq   $0x0,0x10(%rsp)
   3fbbd:	jne    40ad0 <__GI_____strtod_l_internal+0xf40>
   3fbc3:	mov    0x40(%rax),%r13
   3fbc7:	mov    %r9,0x8(%rsp)
   3fbcc:	mov    %r13,%rdi
   3fbcf:	callq  8d020 <strlen>
   3fbd4:	test   %rax,%rax
   3fbd7:	mov    %rax,0x18(%rsp)
   3fbdc:	mov    0x8(%rsp),%r9
   3fbe1:	je     4214b <__GI_____strtod_l_internal+0x25bb>
   3fbe7:	movq   $0x0,0x78(%rsp)
   3fbf0:	lea    -0x1(%r14),%rax
   3fbf4:	mov    0x68(%r9),%rcx
   3fbf8:	jmp    3fc03 <__GI_____strtod_l_internal+0x73>
   3fbfa:	nopw   0x0(%rax,%rax,1)
   3fc00:	mov    %rbx,%rax
   3fc03:	movsbq 0x1(%rax),%rdx
   3fc08:	lea    0x1(%rax),%rbx
   3fc0c:	testb  $0x20,0x1(%rcx,%rdx,2)
   3fc11:	mov    %rdx,%rbp
   3fc14:	jne    3fc00 <__GI_____strtod_l_internal+0x70>
   3fc16:	cmp    $0x2d,%dl
   3fc19:	je     40910 <__GI_____strtod_l_internal+0xd80>
   3fc1f:	cmp    $0x2b,%dl
   3fc22:	movl   $0x0,0x8(%rsp)
   3fc2a:	je     40940 <__GI_____strtod_l_internal+0xdb0>
   3fc30:	movzbl 0x0(%r13),%esi
   3fc35:	test   %sil,%sil
   3fc38:	je     41550 <__GI_____strtod_l_internal+0x19c0>
   3fc3e:	cmp    %sil,%bpl
   3fc41:	jne    3fd08 <__GI_____strtod_l_internal+0x178>
   3fc47:	mov    $0x1,%eax
   3fc4c:	jmp    3fc5e <__GI_____strtod_l_internal+0xce>
   3fc4e:	xchg   %ax,%ax
   3fc50:	add    $0x1,%rax
   3fc54:	cmp    -0x1(%rbx,%rax,1),%dl
   3fc58:	jne    3fd08 <__GI_____strtod_l_internal+0x178>
   3fc5e:	movzbl 0x0(%r13,%rax,1),%edx
   3fc64:	test   %dl,%dl
   3fc66:	jne    3fc50 <__GI_____strtod_l_internal+0xc0>
   3fc68:	movzbl (%rbx,%rax,1),%eax
   3fc6c:	sub    $0x30,%eax
   3fc6f:	cmp    $0x9,%al
   3fc71:	ja     3fd08 <__GI_____strtod_l_internal+0x178>
   3fc77:	cmp    $0x30,%bpl
   3fc7b:	mov    0x70(%r9),%rdi
   3fc7f:	je     3fd50 <__GI_____strtod_l_internal+0x1c0>
   3fc85:	test   %r15,%r15
   3fc88:	je     41557 <__GI_____strtod_l_internal+0x19c7>
   3fc8e:	mov    %rbx,%r10
   3fc91:	mov    $0xa,%r11d
   3fc97:	cmp    $0x30,%bpl
   3fc9b:	movzbl (%r15),%r8d
   3fc9f:	mov    %r10,%rbx
   3fca2:	mov    $0xffffffffffffffff,%r12
   3fca9:	je     3fcfd <__GI_____strtod_l_internal+0x16d>
   3fcab:	nopl   0x0(%rax,%rax,1)
   3fcb0:	test   %r8b,%r8b
   3fcb3:	je     41940 <__GI_____strtod_l_internal+0x1db0>
   3fcb9:	movzbl (%rbx),%ecx
   3fcbc:	cmp    %r8b,%cl
   3fcbf:	jne    3fd88 <__GI_____strtod_l_internal+0x1f8>
   3fcc5:	mov    $0x1,%eax
   3fcca:	jmp    3fcde <__GI_____strtod_l_internal+0x14e>
   3fccc:	nopl   0x0(%rax)
   3fcd0:	add    $0x1,%rax
   3fcd4:	cmp    -0x1(%rbx,%rax,1),%dl
   3fcd8:	jne    3fd88 <__GI_____strtod_l_internal+0x1f8>
   3fcde:	movzbl (%r15,%rax,1),%edx
   3fce3:	test   %dl,%dl
   3fce5:	jne    3fcd0 <__GI_____strtod_l_internal+0x140>
   3fce7:	sub    $0x1,%rax
   3fceb:	add    %rbx,%rax
   3fcee:	movsbq 0x1(%rax),%rbp
   3fcf3:	lea    0x1(%rax),%rbx
   3fcf7:	cmp    $0x30,%bpl
   3fcfb:	jne    3fcb0 <__GI_____strtod_l_internal+0x120>
   3fcfd:	mov    %rbx,%rax
   3fd00:	jmp    3fcee <__GI_____strtod_l_internal+0x15e>
   3fd02:	nopw   0x0(%rax,%rax,1)
   3fd08:	lea    -0x30(%rbp),%eax
   3fd0b:	cmp    $0x9,%al
   3fd0d:	jbe    3fc77 <__GI_____strtod_l_internal+0xe7>
   3fd13:	mov    0x37fb36(%rip),%rax        # 3bf850 <_nl_C_locobj+0x70>
   3fd1a:	mov    (%rax,%rbp,4),%eax
   3fd1d:	cmp    $0x69,%al
   3fd1f:	je     41064 <__GI_____strtod_l_internal+0x14d4>
   3fd25:	cmp    $0x6e,%al
   3fd27:	je     410dd <__GI_____strtod_l_internal+0x154d>
   3fd2d:	cmpq   $0x0,(%rsp)
   3fd32:	jne    408ff <__GI_____strtod_l_internal+0xd6f>
   3fd38:	pxor   %xmm0,%xmm0
   3fd3c:	add    $0x448,%rsp
   3fd43:	pop    %rbx
   3fd44:	pop    %rbp
   3fd45:	pop    %r12
   3fd47:	pop    %r13
   3fd49:	pop    %r14
   3fd4b:	pop    %r15
   3fd4d:	retq   
   3fd4e:	xchg   %ax,%ax
   3fd50:	movsbq 0x1(%rbx),%rax
   3fd55:	cmpl   $0x78,(%rdi,%rax,4)
   3fd59:	je     41567 <__GI_____strtod_l_internal+0x19d7>
   3fd5f:	test   %r15,%r15
   3fd62:	mov    %rbx,%r10
   3fd65:	mov    $0xa,%r11d
   3fd6b:	jne    3fc97 <__GI_____strtod_l_internal+0x107>
   3fd71:	mov    %r10,%rbx
   3fd74:	nopl   0x0(%rax)
   3fd78:	add    $0x1,%rbx
   3fd7c:	movsbq (%rbx),%rbp
   3fd80:	cmp    $0x30,%bpl
   3fd84:	je     3fd78 <__GI_____strtod_l_internal+0x1e8>
   3fd86:	mov    %ebp,%ecx
   3fd88:	lea    -0x30(%rbp),%eax
   3fd8b:	cmp    $0x9,%al
   3fd8d:	jbe    40638 <__GI_____strtod_l_internal+0xaa8>
   3fd93:	movsbq %bpl,%rax
   3fd97:	mov    (%rdi,%rax,4),%eax
   3fd9a:	mov    %eax,0x20(%rsp)
   3fd9e:	sub    $0x61,%eax
   3fda1:	cmp    $0x5,%al
   3fda3:	ja     40950 <__GI_____strtod_l_internal+0xdc0>
   3fda9:	xor    %r8d,%r8d
   3fdac:	cmp    $0x10,%r11d
   3fdb0:	mov    %rbx,%r12
   3fdb3:	jne    40950 <__GI_____strtod_l_internal+0xdc0>
   3fdb9:	mov    $0xffffffffffffffff,%rdx
   3fdc0:	lea    -0x30(%rbp),%eax
   3fdc3:	cmp    $0x9,%al
   3fdc5:	jbe    40608 <__GI_____strtod_l_internal+0xa78>
   3fdcb:	cmp    $0x10,%r11d
   3fdcf:	je     405f0 <__GI_____strtod_l_internal+0xa60>
   3fdd5:	test   %r15,%r15
   3fdd8:	jne    4101e <__GI_____strtod_l_internal+0x148e>
   3fdde:	mov    0x10(%rsp),%rax
   3fde3:	test   %rax,%rax
   3fde6:	je     403b5 <__GI_____strtod_l_internal+0x825>
   3fdec:	cmp    %r10,%r12
   3fdef:	jbe    403b5 <__GI_____strtod_l_internal+0x825>
   3fdf5:	mov    %r10,%rdi
   3fdf8:	mov    %rax,%rcx
   3fdfb:	mov    %r15,%rdx
   3fdfe:	mov    %r12,%rsi
   3fe01:	mov    %r9,0x30(%rsp)
   3fe06:	mov    %r11d,0x28(%rsp)
   3fe0b:	mov    %r8,0x20(%rsp)
   3fe10:	mov    %r10,0x10(%rsp)
   3fe15:	callq  4a820 <__correctly_grouped_prefixmb>
   3fe1a:	cmp    %rax,%r12
   3fe1d:	mov    %rax,%rdi
   3fe20:	mov    0x10(%rsp),%r10
   3fe25:	mov    0x20(%rsp),%r8
   3fe2a:	mov    0x28(%rsp),%r11d
   3fe2f:	mov    0x30(%rsp),%r9
   3fe34:	je     403b0 <__GI_____strtod_l_internal+0x820>
   3fe3a:	cmp    %r10,%rax
   3fe3d:	je     3fd2d <__GI_____strtod_l_internal+0x19d>
   3fe43:	cmp    %rax,%rbx
   3fe46:	ja     41e12 <__GI_____strtod_l_internal+0x2282>
   3fe4c:	jae    4205e <__GI_____strtod_l_internal+0x24ce>
   3fe52:	lea    0x1(%rbx),%rax
   3fe56:	mov    $0x1,%edx
   3fe5b:	sub    %rax,%rdx
   3fe5e:	mov    %rax,%r8
   3fe61:	lea    (%rdx,%rdi,1),%rcx
   3fe65:	and    $0xf,%edx
   3fe68:	cmp    %rcx,%rdx
   3fe6b:	cmova  %rcx,%rdx
   3fe6f:	cmp    $0x11,%rcx
   3fe73:	cmovbe %rcx,%rdx
   3fe77:	test   %rdx,%rdx
   3fe7a:	je     41e96 <__GI_____strtod_l_internal+0x2306>
   3fe80:	movzbl (%rbx),%esi
   3fe83:	xor    %r14d,%r14d
   3fe86:	sub    $0x30,%esi
   3fe89:	cmp    $0xa,%sil
   3fe8d:	setb   %r14b
   3fe91:	cmp    $0x1,%rdx
   3fe95:	je     40081 <__GI_____strtod_l_internal+0x4f1>
   3fe9b:	movzbl 0x1(%rbx),%eax
   3fe9f:	sub    $0x30,%eax
   3fea2:	cmp    $0xa,%al
   3fea4:	setb   %al
   3fea7:	movzbl %al,%eax
   3feaa:	add    %rax,%r14
   3fead:	cmp    $0x2,%rdx
   3feb1:	lea    0x2(%rbx),%rax
   3feb5:	je     40081 <__GI_____strtod_l_internal+0x4f1>
   3febb:	movzbl 0x2(%rbx),%eax
   3febf:	sub    $0x30,%eax
   3fec2:	cmp    $0xa,%al
   3fec4:	setb   %al
   3fec7:	movzbl %al,%eax
   3feca:	add    %rax,%r14
   3fecd:	cmp    $0x3,%rdx
   3fed1:	lea    0x3(%rbx),%rax
   3fed5:	je     40081 <__GI_____strtod_l_internal+0x4f1>
   3fedb:	movzbl 0x3(%rbx),%eax
   3fedf:	sub    $0x30,%eax
   3fee2:	cmp    $0xa,%al
   3fee4:	setb   %al
   3fee7:	movzbl %al,%eax
   3feea:	add    %rax,%r14
   3feed:	cmp    $0x4,%rdx
   3fef1:	lea    0x4(%rbx),%rax
   3fef5:	je     40081 <__GI_____strtod_l_internal+0x4f1>
   3fefb:	movzbl 0x4(%rbx),%eax
   3feff:	sub    $0x30,%eax
   3ff02:	cmp    $0xa,%al
   3ff04:	setb   %al
   3ff07:	movzbl %al,%eax
   3ff0a:	add    %rax,%r14
   3ff0d:	cmp    $0x5,%rdx
   3ff11:	lea    0x5(%rbx),%rax
   3ff15:	je     40081 <__GI_____strtod_l_internal+0x4f1>
   3ff1b:	movzbl 0x5(%rbx),%eax
   3ff1f:	sub    $0x30,%eax
   3ff22:	cmp    $0xa,%al
   3ff24:	setb   %al
   3ff27:	movzbl %al,%eax
   3ff2a:	add    %rax,%r14
   3ff2d:	cmp    $0x6,%rdx
   3ff31:	lea    0x6(%rbx),%rax
   3ff35:	je     40081 <__GI_____strtod_l_internal+0x4f1>
   3ff3b:	movzbl 0x6(%rbx),%eax
   3ff3f:	sub    $0x30,%eax
   3ff42:	cmp    $0xa,%al
   3ff44:	setb   %al
   3ff47:	movzbl %al,%eax
   3ff4a:	add    %rax,%r14
   3ff4d:	cmp    $0x7,%rdx
   3ff51:	lea    0x7(%rbx),%rax
   3ff55:	je     40081 <__GI_____strtod_l_internal+0x4f1>
   3ff5b:	movzbl 0x7(%rbx),%eax
   3ff5f:	sub    $0x30,%eax
   3ff62:	cmp    $0xa,%al
   3ff64:	setb   %al
   3ff67:	movzbl %al,%eax
   3ff6a:	add    %rax,%r14
   3ff6d:	cmp    $0x8,%rdx
   3ff71:	lea    0x8(%rbx),%rax
   3ff75:	je     40081 <__GI_____strtod_l_internal+0x4f1>
   3ff7b:	movzbl 0x8(%rbx),%eax
   3ff7f:	sub    $0x30,%eax
   3ff82:	cmp    $0xa,%al
   3ff84:	setb   %al
   3ff87:	movzbl %al,%eax
   3ff8a:	add    %rax,%r14
   3ff8d:	cmp    $0x9,%rdx
   3ff91:	lea    0x9(%rbx),%rax
   3ff95:	je     40081 <__GI_____strtod_l_internal+0x4f1>
   3ff9b:	movzbl 0x9(%rbx),%eax
   3ff9f:	sub    $0x30,%eax
   3ffa2:	cmp    $0xa,%al
   3ffa4:	setb   %al
   3ffa7:	movzbl %al,%eax
   3ffaa:	add    %rax,%r14
   3ffad:	cmp    $0xa,%rdx
   3ffb1:	lea    0xa(%rbx),%rax
   3ffb5:	je     40081 <__GI_____strtod_l_internal+0x4f1>
   3ffbb:	movzbl 0xa(%rbx),%eax
   3ffbf:	sub    $0x30,%eax
   3ffc2:	cmp    $0xa,%al
   3ffc4:	setb   %al
   3ffc7:	movzbl %al,%eax
   3ffca:	add    %rax,%r14
   3ffcd:	cmp    $0xb,%rdx
   3ffd1:	lea    0xb(%rbx),%rax
   3ffd5:	je     40081 <__GI_____strtod_l_internal+0x4f1>
   3ffdb:	movzbl 0xb(%rbx),%eax
   3ffdf:	sub    $0x30,%eax
   3ffe2:	cmp    $0xa,%al
   3ffe4:	setb   %al
   3ffe7:	movzbl %al,%eax
   3ffea:	add    %rax,%r14
   3ffed:	cmp    $0xc,%rdx
   3fff1:	lea    0xc(%rbx),%rax
   3fff5:	je     40081 <__GI_____strtod_l_internal+0x4f1>
   3fffb:	movzbl 0xc(%rbx),%eax
   3ffff:	sub    $0x30,%eax
   40002:	cmp    $0xa,%al
   40004:	setb   %al
   40007:	movzbl %al,%eax
   4000a:	add    %rax,%r14
   4000d:	cmp    $0xd,%rdx
   40011:	lea    0xd(%rbx),%rax
   40015:	je     40081 <__GI_____strtod_l_internal+0x4f1>
   40017:	movzbl 0xd(%rbx),%eax
   4001b:	sub    $0x30,%eax
   4001e:	cmp    $0xa,%al
   40020:	setb   %al
   40023:	movzbl %al,%eax
   40026:	add    %rax,%r14
   40029:	cmp    $0xe,%rdx
   4002d:	lea    0xe(%rbx),%rax
   40031:	je     40081 <__GI_____strtod_l_internal+0x4f1>
   40033:	movzbl 0xe(%rbx),%eax
   40037:	sub    $0x30,%eax
   4003a:	cmp    $0xa,%al
   4003c:	setb   %al
   4003f:	movzbl %al,%eax
   40042:	add    %rax,%r14
   40045:	cmp    $0xf,%rdx
   40049:	lea    0xf(%rbx),%rax
   4004d:	je     40081 <__GI_____strtod_l_internal+0x4f1>
   4004f:	movzbl 0xf(%rbx),%eax
   40053:	sub    $0x30,%eax
   40056:	cmp    $0xa,%al
   40058:	setb   %al
   4005b:	movzbl %al,%eax
   4005e:	add    %rax,%r14
   40061:	cmp    $0x11,%rdx
   40065:	lea    0x10(%rbx),%rax
   40069:	jne    40081 <__GI_____strtod_l_internal+0x4f1>
   4006b:	movzbl 0x10(%rbx),%eax
   4006f:	sub    $0x30,%eax
   40072:	cmp    $0xa,%al
   40074:	setb   %al
   40077:	movzbl %al,%eax
   4007a:	add    %rax,%r14
   4007d:	lea    0x11(%rbx),%rax
   40081:	cmp    %rcx,%rdx
   40084:	je     4037b <__GI_____strtod_l_internal+0x7eb>
   4008a:	sub    %rdx,%rcx
   4008d:	mov    %rdi,%rbp
   40090:	lea    -0x10(%rcx),%rsi
   40094:	sub    %r8,%rbp
   40097:	mov    %rbp,%r8
   4009a:	shr    $0x4,%rsi
   4009e:	sub    %rdx,%r8
   400a1:	add    $0x1,%rsi
   400a5:	mov    %rsi,%r10
   400a8:	shl    $0x4,%r10
   400ac:	cmp    $0xe,%r8
   400b0:	jbe    401ba <__GI_____strtod_l_internal+0x62a>
   400b6:	pxor   %xmm3,%xmm3
   400ba:	movdqa 0x1512bd(%rip),%xmm9        # 191380 <othermask+0xa0>
   400c3:	pxor   %xmm6,%xmm6
   400c7:	add    %rbx,%rdx
   400ca:	pxor   %xmm5,%xmm5
   400ce:	xor    %r8d,%r8d
   400d1:	pxor   %xmm4,%xmm4
   400d5:	movdqa 0x1512b2(%rip),%xmm8        # 191390 <othermask+0xb0>
   400de:	movdqa 0x1512ba(%rip),%xmm7        # 1913a0 <othermask+0xc0>
   400e6:	add    $0x1,%r8
   400ea:	add    $0x10,%rdx
   400ee:	movdqa -0x10(%rdx),%xmm0
   400f3:	cmp    %rsi,%r8
   400f6:	paddb  %xmm9,%xmm0
   400fb:	psubusb %xmm8,%xmm0
   40100:	pcmpeqb %xmm6,%xmm0
   40104:	pand   %xmm7,%xmm0
   40108:	movdqa %xmm0,%xmm12
   4010d:	punpckhbw %xmm6,%xmm0
   40111:	punpcklbw %xmm6,%xmm12
   40116:	movdqa %xmm0,%xmm1
   4011a:	movdqa %xmm12,%xmm2
   4011f:	punpckhwd %xmm5,%xmm12
   40124:	punpcklwd %xmm5,%xmm1
   40128:	punpcklwd %xmm5,%xmm2
   4012c:	punpckhwd %xmm5,%xmm0
   40130:	movdqa %xmm2,%xmm11
   40135:	movdqa %xmm2,%xmm10
   4013a:	movdqa %xmm12,%xmm2
   4013f:	punpckhdq %xmm4,%xmm11
   40144:	punpckldq %xmm4,%xmm10
   40149:	punpckhdq %xmm4,%xmm2
   4014d:	paddq  %xmm11,%xmm10
   40152:	movdqa %xmm12,%xmm11
   40157:	punpckldq %xmm4,%xmm11
   4015c:	paddq  %xmm11,%xmm10
   40161:	paddq  %xmm2,%xmm10
   40166:	movdqa %xmm1,%xmm2
   4016a:	punpckhdq %xmm4,%xmm1
   4016e:	punpckldq %xmm4,%xmm2
   40172:	paddq  %xmm10,%xmm2
   40177:	paddq  %xmm1,%xmm2
   4017b:	movdqa %xmm0,%xmm1
   4017f:	punpckhdq %xmm4,%xmm0
   40183:	punpckldq %xmm4,%xmm1
   40187:	paddq  %xmm2,%xmm1
   4018b:	paddq  %xmm1,%xmm0
   4018f:	paddq  %xmm0,%xmm3
   40193:	jb     400e6 <__GI_____strtod_l_internal+0x556>
   40199:	movdqa %xmm3,%xmm0
   4019d:	add    %r10,%rax
   401a0:	psrldq $0x8,%xmm0
   401a5:	paddq  %xmm0,%xmm3
   401a9:	movq   %xmm3,%rdx
   401ae:	add    %rdx,%r14
   401b1:	cmp    %rcx,%r10
   401b4:	je     4037b <__GI_____strtod_l_internal+0x7eb>
   401ba:	movzbl (%rax),%esi
   401bd:	lea    -0x30(%rsi),%edx
   401c0:	cmp    $0xa,%dl
   401c3:	setb   %dl
   401c6:	movzbl %dl,%edx
   401c9:	add    %rdx,%r14
   401cc:	lea    0x1(%rax),%rdx
   401d0:	cmp    %rdx,%rdi
   401d3:	jbe    4037b <__GI_____strtod_l_internal+0x7eb>
   401d9:	movzbl 0x1(%rax),%esi
   401dd:	lea    -0x30(%rsi),%edx
   401e0:	cmp    $0xa,%dl
   401e3:	setb   %dl
   401e6:	movzbl %dl,%edx
   401e9:	add    %rdx,%r14
   401ec:	lea    0x2(%rax),%rdx
   401f0:	cmp    %rdx,%rdi
   401f3:	jbe    4037b <__GI_____strtod_l_internal+0x7eb>
   401f9:	movzbl 0x2(%rax),%esi
   401fd:	lea    -0x30(%rsi),%edx
   40200:	cmp    $0xa,%dl
   40203:	setb   %dl
   40206:	movzbl %dl,%edx
   40209:	add    %rdx,%r14
   4020c:	lea    0x3(%rax),%rdx
   40210:	cmp    %rdx,%rdi
   40213:	jbe    4037b <__GI_____strtod_l_internal+0x7eb>
   40219:	movzbl 0x3(%rax),%esi
   4021d:	lea    -0x30(%rsi),%edx
   40220:	cmp    $0xa,%dl
   40223:	setb   %dl
   40226:	movzbl %dl,%edx
   40229:	add    %rdx,%r14
   4022c:	lea    0x4(%rax),%rdx
   40230:	cmp    %rdx,%rdi
   40233:	jbe    4037b <__GI_____strtod_l_internal+0x7eb>
   40239:	movzbl 0x4(%rax),%esi
   4023d:	lea    -0x30(%rsi),%edx
   40240:	cmp    $0xa,%dl
   40243:	setb   %dl
   40246:	movzbl %dl,%edx
   40249:	add    %rdx,%r14
   4024c:	lea    0x5(%rax),%rdx
   40250:	cmp    %rdx,%rdi
   40253:	jbe    4037b <__GI_____strtod_l_internal+0x7eb>
   40259:	movzbl 0x5(%rax),%esi
   4025d:	lea    -0x30(%rsi),%edx
   40260:	cmp    $0xa,%dl
   40263:	setb   %dl
   40266:	movzbl %dl,%edx
   40269:	add    %rdx,%r14
   4026c:	lea    0x6(%rax),%rdx
   40270:	cmp    %rdx,%rdi
   40273:	jbe    4037b <__GI_____strtod_l_internal+0x7eb>
   40279:	movzbl 0x6(%rax),%esi
   4027d:	lea    -0x30(%rsi),%edx
   40280:	cmp    $0xa,%dl
   40283:	setb   %dl
   40286:	movzbl %dl,%edx
   40289:	add    %rdx,%r14
   4028c:	lea    0x7(%rax),%rdx
   40290:	cmp    %rdx,%rdi
   40293:	jbe    4037b <__GI_____strtod_l_internal+0x7eb>
   40299:	movzbl 0x7(%rax),%esi
   4029d:	lea    -0x30(%rsi),%edx
   402a0:	cmp    $0xa,%dl
   402a3:	setb   %dl
   402a6:	movzbl %dl,%edx
   402a9:	add    %rdx,%r14
   402ac:	lea    0x8(%rax),%rdx
   402b0:	cmp    %rdx,%rdi
   402b3:	jbe    4037b <__GI_____strtod_l_internal+0x7eb>
   402b9:	movzbl 0x8(%rax),%esi
   402bd:	lea    -0x30(%rsi),%edx
   402c0:	cmp    $0xa,%dl
   402c3:	setb   %dl
   402c6:	movzbl %dl,%edx
   402c9:	add    %rdx,%r14
   402cc:	lea    0x9(%rax),%rdx
   402d0:	cmp    %rdx,%rdi
   402d3:	jbe    4037b <__GI_____strtod_l_internal+0x7eb>
   402d9:	movzbl 0x9(%rax),%esi
   402dd:	lea    -0x30(%rsi),%edx
   402e0:	cmp    $0xa,%dl
   402e3:	setb   %dl
   402e6:	movzbl %dl,%edx
   402e9:	add    %rdx,%r14
   402ec:	lea    0xa(%rax),%rdx
   402f0:	cmp    %rdx,%rdi
   402f3:	jbe    4037b <__GI_____strtod_l_internal+0x7eb>
   402f9:	movzbl 0xa(%rax),%esi
   402fd:	lea    -0x30(%rsi),%edx
   40300:	cmp    $0xa,%dl
   40303:	setb   %dl
   40306:	movzbl %dl,%edx
   40309:	add    %rdx,%r14
   4030c:	lea    0xb(%rax),%rdx
   40310:	cmp    %rdx,%rdi
   40313:	jbe    4037b <__GI_____strtod_l_internal+0x7eb>
   40315:	movzbl 0xb(%rax),%esi
   40319:	lea    -0x30(%rsi),%edx
   4031c:	cmp    $0xa,%dl
   4031f:	setb   %dl
   40322:	movzbl %dl,%edx
   40325:	add    %rdx,%r14
   40328:	lea    0xc(%rax),%rdx
   4032c:	cmp    %rdx,%rdi
   4032f:	jbe    4037b <__GI_____strtod_l_internal+0x7eb>
   40331:	movzbl 0xc(%rax),%esi
   40335:	lea    -0x30(%rsi),%edx
   40338:	cmp    $0xa,%dl
   4033b:	setb   %dl
   4033e:	movzbl %dl,%edx
   40341:	add    %rdx,%r14
   40344:	lea    0xd(%rax),%rdx
   40348:	cmp    %rdx,%rdi
   4034b:	jbe    4037b <__GI_____strtod_l_internal+0x7eb>
   4034d:	movzbl 0xd(%rax),%esi
   40351:	lea    -0x30(%rsi),%edx
   40354:	cmp    $0xa,%dl
   40357:	setb   %dl
   4035a:	movzbl %dl,%edx
   4035d:	add    %rdx,%r14
   40360:	lea    0xe(%rax),%rdx
   40364:	cmp    %rdx,%rdi
   40367:	jbe    4037b <__GI_____strtod_l_internal+0x7eb>
   40369:	movzbl 0xe(%rax),%eax
   4036d:	sub    $0x30,%eax
   40370:	cmp    $0xa,%al
   40372:	setb   %al
   40375:	movzbl %al,%eax
   40378:	add    %rax,%r14
   4037b:	mov    %r14,%r8
   4037e:	xor    %ecx,%ecx
   40380:	cmpq   $0x0,(%rsp)
   40385:	je     4038e <__GI_____strtod_l_internal+0x7fe>
   40387:	mov    (%rsp),%rax
   4038b:	mov    %rdi,(%rax)
   4038e:	test   %r14,%r14
   40391:	jne    406c0 <__GI_____strtod_l_internal+0xb30>
   40397:	mov    0x8(%rsp),%eax
   4039b:	movsd  0x1513cd(%rip),%xmm0        # 191770 <conversion_rate+0x58>
   403a3:	test   %eax,%eax
   403a5:	jne    3fd3c <__GI_____strtod_l_internal+0x1ac>
   403ab:	jmpq   3fd38 <__GI_____strtod_l_internal+0x1a8>
   403b0:	movzbl 0x0(%r13),%esi
   403b5:	xor    %ecx,%ecx
   403b7:	test   %r8,%r8
   403ba:	sete   %cl
   403bd:	neg    %rcx
   403c0:	test   %sil,%sil
   403c3:	je     403f9 <__GI_____strtod_l_internal+0x869>
   403c5:	cmp    %sil,(%r12)
   403c9:	jne    40930 <__GI_____strtod_l_internal+0xda0>
   403cf:	mov    $0x1,%eax
   403d4:	jmp    403ef <__GI_____strtod_l_internal+0x85f>
   403d6:	nopw   %cs:0x0(%rax,%rax,1)
   403e0:	add    $0x1,%rax
   403e4:	cmp    -0x1(%r12,%rax,1),%dl
   403e9:	jne    40930 <__GI_____strtod_l_internal+0xda0>
   403ef:	movzbl 0x0(%r13,%rax,1),%edx
   403f5:	test   %dl,%dl
   403f7:	jne    403e0 <__GI_____strtod_l_internal+0x850>
   403f9:	mov    0x18(%rsp),%rax
   403fe:	cmp    $0x10,%r11d
   40402:	lea    (%r12,%rax,1),%rsi
   40406:	movsbq (%rsi),%rbp
   4040a:	mov    %rsi,%r12
   4040d:	jne    41d65 <__GI_____strtod_l_internal+0x21d5>
   40413:	mov    %r8,%rdx
   40416:	mov    0x70(%r9),%rdi
   4041a:	sub    %rsi,%rdx
   4041d:	jmp    40444 <__GI_____strtod_l_internal+0x8b4>
   4041f:	nop
   40420:	cmp    $0x30,%bpl
   40424:	je     4043b <__GI_____strtod_l_internal+0x8ab>
   40426:	cmp    $0xffffffffffffffff,%rcx
   4042a:	mov    %r12,%rax
   4042d:	sete   %r10b
   40431:	sub    %rsi,%rax
   40434:	test   %r10b,%r10b
   40437:	cmovne %rax,%rcx
   4043b:	add    $0x1,%r12
   4043f:	movsbq (%r12),%rbp
   40444:	lea    -0x30(%rbp),%eax
   40447:	lea    (%r12,%rdx,1),%r14
   4044b:	cmp    $0x9,%al
   4044d:	jbe    40420 <__GI_____strtod_l_internal+0x890>
   4044f:	movsbq %bpl,%rax
   40453:	mov    (%rdi,%rax,4),%eax
   40456:	sub    $0x61,%eax
   40459:	cmp    $0x5,%al
   4045b:	jbe    40420 <__GI_____strtod_l_internal+0x890>
   4045d:	test   %r14,%r14
   40460:	js     4216a <__GI_____strtod_l_internal+0x25da>
   40466:	mov    0x70(%r9),%rax
   4046a:	cmp    $0x10,%r11d
   4046e:	mov    (%rax,%rbp,4),%eax
   40471:	jne    40648 <__GI_____strtod_l_internal+0xab8>
   40477:	cmp    $0x70,%al
   40479:	jne    40648 <__GI_____strtod_l_internal+0xab8>
   4047f:	movzbl 0x1(%r12),%esi
   40485:	cmp    $0x2d,%sil
   40489:	je     40a50 <__GI_____strtod_l_internal+0xec0>
   4048f:	cmp    $0x2b,%sil
   40493:	je     40fa9 <__GI_____strtod_l_internal+0x1419>
   40499:	lea    0x1(%r12),%rdi
   4049e:	movl   $0x0,0x10(%rsp)
   404a6:	lea    -0x30(%rsi),%eax
   404a9:	cmp    $0x9,%al
   404ab:	ja     40656 <__GI_____strtod_l_internal+0xac6>
   404b1:	cmp    $0x10,%r11d
   404b5:	je     409bc <__GI_____strtod_l_internal+0xe2c>
   404bb:	mov    0x10(%rsp),%ebp
   404bf:	test   %ebp,%ebp
   404c1:	je     40fc1 <__GI_____strtod_l_internal+0x1431>
   404c7:	movabs $0x7ffffffffffffe97,%rax
   404d1:	cmp    %rax,%r8
   404d4:	ja     421b6 <__GI_____strtod_l_internal+0x2626>
   404da:	lea    0x168(%r8),%rbp
   404e1:	mov    %rbp,%rax
   404e4:	movabs $0x6666666666666667,%rdx
   404ee:	imul   %rdx
   404f1:	mov    %rbp,%rax
   404f4:	sar    $0x3f,%rax
   404f8:	sar    $0x2,%rdx
   404fc:	sub    %rax,%rdx
   404ff:	mov    %rdx,0x20(%rsp)
   40504:	mov    %rbp,%rax
   40507:	movabs $0x6666666666666667,%rdx
   40511:	mov    %r12,0x28(%rsp)
   40516:	imul   %rdx
   40519:	mov    %rbp,%rax
   4051c:	mov    0x78(%rsp),%r10
   40521:	sar    $0x3f,%rax
   40525:	mov    0x20(%rsp),%r12
   4052a:	sar    $0x2,%rdx
   4052e:	sub    %rax,%rdx
   40531:	lea    (%rdx,%rdx,4),%rax
   40535:	mov    %rbp,%rdx
   40538:	xor    %ebp,%ebp
   4053a:	add    %rax,%rax
   4053d:	sub    %rax,%rdx
   40540:	jmp    40576 <__GI_____strtod_l_internal+0x9e6>
   40542:	nopw   0x0(%rax,%rax,1)
   40548:	movsbl %sil,%eax
   4054c:	je     40a20 <__GI_____strtod_l_internal+0xe90>
   40552:	sub    $0x30,%eax
   40555:	cltq   
   40557:	lea    (%r10,%r10,4),%rsi
   4055b:	add    $0x1,%rdi
   4055f:	mov    $0x1,%ebp
   40564:	lea    (%rax,%rsi,2),%r10
   40568:	movzbl (%rdi),%esi
   4056b:	lea    -0x30(%rsi),%eax
   4056e:	cmp    $0x9,%al
   40570:	ja     415b6 <__GI_____strtod_l_internal+0x1a26>
   40576:	cmp    %r10,%r12
   40579:	jge    40548 <__GI_____strtod_l_internal+0x9b8>
   4057b:	test   %bpl,%bpl
   4057e:	jne    42213 <__GI_____strtod_l_internal+0x2683>
   40584:	cmp    $0xffffffffffffffff,%rcx
   40588:	je     41597 <__GI_____strtod_l_internal+0x1a07>
   4058e:	mov    0x10(%rsp),%r10d
   40593:	mov    0x37f8ce(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   4059a:	test   %r10d,%r10d
   4059d:	movl   $0x22,%fs:(%rax)
   405a4:	je     40ffb <__GI_____strtod_l_internal+0x146b>
   405aa:	mov    0x8(%rsp),%r9d
   405af:	movsd  0x151199(%rip),%xmm0        # 191750 <conversion_rate+0x38>
   405b7:	test   %r9d,%r9d
   405ba:	jne    413bc <__GI_____strtod_l_internal+0x182c>
   405c0:	mulsd  %xmm0,%xmm0
   405c4:	nopl   0x0(%rax)
   405c8:	add    $0x1,%rdi
   405cc:	movzbl (%rdi),%eax
   405cf:	sub    $0x30,%eax
   405d2:	cmp    $0x9,%al
   405d4:	jbe    405c8 <__GI_____strtod_l_internal+0xa38>
   405d6:	mov    (%rsp),%rax
   405da:	test   %rax,%rax
   405dd:	je     3fd3c <__GI_____strtod_l_internal+0x1ac>
   405e3:	mov    %rdi,(%rax)
   405e6:	jmpq   3fd3c <__GI_____strtod_l_internal+0x1ac>
   405eb:	nopl   0x0(%rax,%rax,1)
   405f0:	movsbq %bpl,%rax
   405f4:	mov    (%rdi,%rax,4),%eax
   405f7:	sub    $0x61,%eax
   405fa:	cmp    $0x5,%al
   405fc:	ja     3fdd5 <__GI_____strtod_l_internal+0x245>
   40602:	nopw   0x0(%rax,%rax,1)
   40608:	add    $0x1,%r8
   4060c:	mov    %r12,%rax
   4060f:	movsbq 0x1(%rax),%rbp
   40614:	lea    0x1(%rax),%r12
   40618:	mov    %ebp,%ecx
   4061a:	jmpq   3fdc0 <__GI_____strtod_l_internal+0x230>
   4061f:	cmpb   $0x70,0x20(%rsp)
   40624:	jne    40a72 <__GI_____strtod_l_internal+0xee2>
   4062a:	cmp    %r10,%rbx
   4062d:	je     40a72 <__GI_____strtod_l_internal+0xee2>
   40633:	nopl   0x0(%rax,%rax,1)
   40638:	mov    %rbx,%r12
   4063b:	xor    %r8d,%r8d
   4063e:	jmpq   3fdb9 <__GI_____strtod_l_internal+0x229>
   40643:	nopl   0x0(%rax,%rax,1)
   40648:	cmp    $0x10,%r11d
   4064c:	je     40656 <__GI_____strtod_l_internal+0xac6>
   4064e:	cmp    $0x65,%al
   40650:	je     4047f <__GI_____strtod_l_internal+0x8ef>
   40656:	mov    %r12,%rdi
   40659:	cmp    %r14,%r8
   4065c:	jae    4068c <__GI_____strtod_l_internal+0xafc>
   4065e:	cmpb   $0x30,-0x1(%r12)
   40664:	jne    40380 <__GI_____strtod_l_internal+0x7f0>
   4066a:	sub    %r12,%r14
   4066d:	nopl   (%rax)
   40670:	sub    $0x1,%r12
   40674:	cmpb   $0x30,-0x1(%r12)
   4067a:	lea    (%r12,%r14,1),%rax
   4067e:	je     40670 <__GI_____strtod_l_internal+0xae0>
   40680:	cmp    %rax,%r8
   40683:	ja     421f4 <__GI_____strtod_l_internal+0x2664>
   40689:	mov    %rax,%r14
   4068c:	cmp    %r14,%r8
   4068f:	jne    40380 <__GI_____strtod_l_internal+0x7f0>
   40695:	test   %r14,%r14
   40698:	je     40380 <__GI_____strtod_l_internal+0x7f0>
   4069e:	mov    0x78(%rsp),%rdx
   406a3:	test   %rdx,%rdx
   406a6:	js     412cd <__GI_____strtod_l_internal+0x173d>
   406ac:	cmpq   $0x0,(%rsp)
   406b1:	jne    40387 <__GI_____strtod_l_internal+0x7f7>
   406b7:	nopw   0x0(%rax,%rax,1)
   406c0:	test   %rcx,%rcx
   406c3:	je     40754 <__GI_____strtod_l_internal+0xbc4>
   406c9:	movzbl 0x0(%r13),%esi
   406ce:	movzbl 0x1(%r13),%edi
   406d3:	jmp    406dc <__GI_____strtod_l_internal+0xb4c>
   406d5:	nopl   (%rax)
   406d8:	add    $0x1,%rbx
   406dc:	cmp    %sil,(%rbx)
   406df:	jne    406d8 <__GI_____strtod_l_internal+0xb48>
   406e1:	test   %dil,%dil
   406e4:	je     4070c <__GI_____strtod_l_internal+0xb7c>
   406e6:	cmp    %dil,0x1(%rbx)
   406ea:	jne    406d8 <__GI_____strtod_l_internal+0xb48>
   406ec:	mov    $0x2,%eax
   406f1:	jmp    40702 <__GI_____strtod_l_internal+0xb72>
   406f3:	nopl   0x0(%rax,%rax,1)
   406f8:	add    $0x1,%rax
   406fc:	cmp    -0x1(%rbx,%rax,1),%dl
   40700:	jne    406d8 <__GI_____strtod_l_internal+0xb48>
   40702:	movzbl 0x0(%r13,%rax,1),%edx
   40708:	test   %dl,%dl
   4070a:	jne    406f8 <__GI_____strtod_l_internal+0xb68>
   4070c:	cmp    $0x10,%r11d
   40710:	je     41970 <__GI_____strtod_l_internal+0x1de0>
   40716:	test   %rcx,%rcx
   40719:	js     42268 <__GI_____strtod_l_internal+0x26d8>
   4071f:	mov    0x78(%rsp),%rax
   40724:	movabs $0x8000000000000000,%rdx
   4072e:	add    %rax,%rdx
   40731:	cmp    %rcx,%rdx
   40734:	jb     42249 <__GI_____strtod_l_internal+0x26b9>
   4073a:	mov    %rcx,%rdx
   4073d:	mov    0x18(%rsp),%rdi
   40742:	sub    %rdx,%rax
   40745:	sub    %rcx,%r14
   40748:	mov    %rax,0x78(%rsp)
   4074d:	lea    (%rdi,%rcx,1),%rsi
   40751:	add    %rsi,%rbx
   40754:	cmp    $0x10,%r11d
   40758:	je     4112b <__GI_____strtod_l_internal+0x159b>
   4075e:	mov    0x78(%rsp),%rax
   40763:	test   %rax,%rax
   40766:	js     415d5 <__GI_____strtod_l_internal+0x1a45>
   4076c:	mov    %r14,%rdx
   4076f:	sub    %r8,%rdx
   40772:	cmp    %rax,%rdx
   40775:	cmovg  %rax,%rdx
   40779:	lea    (%rdx,%r8,1),%r13
   4077d:	sub    %rdx,%rax
   40780:	mov    $0x135,%edx
   40785:	mov    %rax,0x78(%rsp)
   4078a:	sub    %r13,%rdx
   4078d:	cmp    %rdx,%rax
   40790:	jg     41a28 <__GI_____strtod_l_internal+0x1e98>
   40796:	cmp    $0xfffffffffffffebc,%rax
   4079c:	jl     41d3a <__GI_____strtod_l_internal+0x21aa>
   407a2:	test   %r13,%r13
   407a5:	movl   $0x0,(%rsp)
   407ac:	jne    415e7 <__GI_____strtod_l_internal+0x1a57>
   407b2:	cmp    %r13,%r14
   407b5:	jbe    42095 <__GI_____strtod_l_internal+0x2505>
   407bb:	mov    0x78(%rsp),%rcx
   407c0:	lea    0x144(%rcx),%rax
   407c7:	cmp    $0x144,%rax
   407cd:	ja     42095 <__GI_____strtod_l_internal+0x2505>
   407d3:	mov    (%rsp),%ebp
   407d6:	test   %ebp,%ebp
   407d8:	jle    419af <__GI_____strtod_l_internal+0x1e1f>
   407de:	test   %rcx,%rcx
   407e1:	jne    41fd3 <__GI_____strtod_l_internal+0x2443>
   407e7:	test   %r13,%r13
   407ea:	je     41fd3 <__GI_____strtod_l_internal+0x2443>
   407f0:	mov    $0x36,%eax
   407f5:	sub    (%rsp),%eax
   407f8:	xor    %edx,%edx
   407fa:	mov    %r14,%rcx
   407fd:	cltq   
   407ff:	sub    %r13,%rcx
   40802:	cmp    %rcx,%rax
   40805:	mov    %r13d,%ecx
   40808:	jle    40812 <__GI_____strtod_l_internal+0xc82>
   4080a:	mov    %r14d,%eax
   4080d:	sub    %r13d,%eax
   40810:	cltq   
   40812:	add    %r13,%rax
   40815:	movb   $0x0,0x5f(%rsp)
   4081a:	cmp    %rax,%r14
   4081d:	jg     41386 <__GI_____strtod_l_internal+0x17f6>
   40823:	mov    %r14d,%eax
   40826:	lea    0x260(%rsp),%rdi
   4082e:	xor    %r12d,%r12d
   40831:	sub    %ecx,%eax
   40833:	mov    %r15,0x30(%rsp)
   40838:	mov    %rbx,0x38(%rsp)
   4083d:	mov    %eax,%r14d
   40840:	mov    %eax,0x28(%rsp)
   40844:	lea    0x80(%rsp),%rax
   4084c:	sub    %edx,%r14d
   4084f:	lea    0x13ee4a(%rip),%r13        # 17f6a0 <_fpioconst_pow10>
   40856:	mov    %rdi,0x20(%rsp)
   4085b:	mov    %r14d,%r15d
   4085e:	mov    %rax,0x10(%rsp)
   40863:	mov    %r12,%r14
   40866:	mov    $0x1,%ebp
   4086b:	mov    %rax,%r12
   4086e:	mov    %rdi,%rbx
   40871:	jmp    408ab <__GI_____strtod_l_internal+0xd1b>
   40873:	nopl   0x0(%rax,%rax,1)
   40878:	lea    -0x1(%rax),%r14
   4087c:	mov    0x0(%r13),%rax
   40880:	lea    0x13ef99(%rip),%rdi        # 17f820 <__tens>
   40887:	lea    0x0(,%r14,8),%rdx
   4088f:	lea    0x8(%rdi,%rax,8),%rsi
   40894:	mov    %rbx,%rdi
   40897:	callq  909a0 <memcpy@GLIBC_2.2.5>
   4089c:	add    %ebp,%ebp
   4089e:	add    $0x18,%r13
   408a2:	test   %r15d,%r15d
   408a5:	je     40b0c <__GI_____strtod_l_internal+0xf7c>
   408ab:	test   %r15d,%ebp
   408ae:	je     4089c <__GI_____strtod_l_internal+0xd0c>
   408b0:	xor    %ebp,%r15d
   408b3:	test   %r14,%r14
   408b6:	mov    0x8(%r13),%rax
   408ba:	je     40878 <__GI_____strtod_l_internal+0xce8>
   408bc:	lea    -0x1(%rax),%rdx
   408c0:	mov    0x0(%r13),%rax
   408c4:	lea    0x13ef55(%rip),%rdi        # 17f820 <__tens>
   408cb:	mov    %r14,%r8
   408ce:	mov    %rbx,%rcx
   408d1:	lea    0x8(%rdi,%rax,8),%rsi
   408d6:	mov    %r12,%rdi
   408d9:	callq  49160 <__mpn_mul>
   408de:	mov    0x8(%r13),%rdx
   408e2:	test   %rax,%rax
   408e5:	lea    -0x1(%r14,%rdx,1),%r14
   408ea:	jne    40a08 <__GI_____strtod_l_internal+0xe78>
   408f0:	mov    %rbx,%rax
   408f3:	sub    $0x1,%r14
   408f7:	mov    %r12,%rbx
   408fa:	mov    %rax,%r12
   408fd:	jmp    4089c <__GI_____strtod_l_internal+0xd0c>
   408ff:	mov    (%rsp),%rax
   40903:	pxor   %xmm0,%xmm0
   40907:	mov    %r14,(%rax)
   4090a:	jmpq   3fd3c <__GI_____strtod_l_internal+0x1ac>
   4090f:	nop
   40910:	movsbq 0x1(%rbx),%rbp
   40915:	movl   $0x1,0x8(%rsp)
   4091d:	lea    0x2(%rax),%rbx
   40921:	jmpq   3fc30 <__GI_____strtod_l_internal+0xa0>
   40926:	nopw   %cs:0x0(%rax,%rax,1)
   40930:	mov    %r8,%r14
   40933:	jmpq   4045d <__GI_____strtod_l_internal+0x8cd>
   40938:	nopl   0x0(%rax,%rax,1)
   40940:	movsbq 0x1(%rbx),%rbp
   40945:	lea    0x2(%rax),%rbx
   40949:	jmpq   3fc30 <__GI_____strtod_l_internal+0xa0>
   4094e:	xchg   %ax,%ax
   40950:	test   %sil,%sil
   40953:	je     40980 <__GI_____strtod_l_internal+0xdf0>
   40955:	cmp    %cl,%sil
   40958:	jne    40a68 <__GI_____strtod_l_internal+0xed8>
   4095e:	mov    $0x1,%eax
   40963:	jmp    40976 <__GI_____strtod_l_internal+0xde6>
   40965:	nopl   (%rax)
   40968:	add    $0x1,%rax
   4096c:	cmp    -0x1(%rbx,%rax,1),%dl
   40970:	jne    40a68 <__GI_____strtod_l_internal+0xed8>
   40976:	movzbl 0x0(%r13,%rax,1),%edx
   4097c:	test   %dl,%dl
   4097e:	jne    40968 <__GI_____strtod_l_internal+0xdd8>
   40980:	cmp    $0x10,%r11d
   40984:	jne    40638 <__GI_____strtod_l_internal+0xaa8>
   4098a:	cmp    %r10,%rbx
   4098d:	jne    40638 <__GI_____strtod_l_internal+0xaa8>
   40993:	mov    0x18(%rsp),%rax
   40998:	movsbq (%rbx,%rax,1),%rax
   4099d:	lea    -0x30(%rax),%edx
   409a0:	cmp    $0x9,%dl
   409a3:	jbe    40638 <__GI_____strtod_l_internal+0xaa8>
   409a9:	mov    (%rdi,%rax,4),%eax
   409ac:	sub    $0x61,%eax
   409af:	cmp    $0x5,%al
   409b1:	jbe    40638 <__GI_____strtod_l_internal+0xaa8>
   409b7:	jmpq   40a72 <__GI_____strtod_l_internal+0xee2>
   409bc:	mov    0x10(%rsp),%eax
   409c0:	test   %eax,%eax
   409c2:	jne    413c9 <__GI_____strtod_l_internal+0x1839>
   409c8:	test   %r8,%r8
   409cb:	je     41b43 <__GI_____strtod_l_internal+0x1fb3>
   409d1:	test   %rcx,%rcx
   409d4:	jne    420d3 <__GI_____strtod_l_internal+0x2543>
   409da:	movabs $0x1fffffffffffffff,%rax
   409e4:	cmp    %rax,%r8
   409e7:	ja     420d3 <__GI_____strtod_l_internal+0x2543>
   409ed:	mov    $0x100,%eax
   409f2:	sub    %r8,%rax
   409f5:	lea    0x3(,%rax,4),%rbp
   409fd:	jmpq   40fea <__GI_____strtod_l_internal+0x145a>
   40a02:	nopw   0x0(%rax,%rax,1)
   40a08:	mov    %rbx,%rax
   40a0b:	mov    %r12,%rbx
   40a0e:	mov    %rax,%r12
   40a11:	jmpq   4089c <__GI_____strtod_l_internal+0xd0c>
   40a16:	nopw   %cs:0x0(%rax,%rax,1)
   40a20:	sub    $0x30,%eax
   40a23:	cltq   
   40a25:	cmp    %rdx,%rax
   40a28:	jle    40557 <__GI_____strtod_l_internal+0x9c7>
   40a2e:	test   %bpl,%bpl
   40a31:	je     40584 <__GI_____strtod_l_internal+0x9f4>
   40a37:	mov    0x20(%rsp),%rax
   40a3c:	mov    %rax,0x78(%rsp)
   40a41:	jmpq   40584 <__GI_____strtod_l_internal+0x9f4>
   40a46:	nopw   %cs:0x0(%rax,%rax,1)
   40a50:	lea    0x2(%r12),%rdi
   40a55:	movzbl 0x2(%r12),%esi
   40a5b:	movl   $0x1,0x10(%rsp)
   40a63:	jmpq   404a6 <__GI_____strtod_l_internal+0x916>
   40a68:	cmp    $0x10,%r11d
   40a6c:	je     4061f <__GI_____strtod_l_internal+0xa8f>
   40a72:	cmp    $0x10,%r11d
   40a76:	je     40a89 <__GI_____strtod_l_internal+0xef9>
   40a78:	xor    %r8d,%r8d
   40a7b:	cmpb   $0x65,0x20(%rsp)
   40a80:	mov    %rbx,%r12
   40a83:	je     3fdb9 <__GI_____strtod_l_internal+0x229>
   40a89:	mov    0x10(%rsp),%rcx
   40a8e:	mov    %r15,%rdx
   40a91:	mov    %rbx,%rsi
   40a94:	mov    %r10,%rdi
   40a97:	mov    %r11d,0x18(%rsp)
   40a9c:	mov    %r10,0x10(%rsp)
   40aa1:	callq  4a820 <__correctly_grouped_prefixmb>
   40aa6:	cmpq   $0x0,(%rsp)
   40aab:	je     40397 <__GI_____strtod_l_internal+0x807>
   40ab1:	mov    0x10(%rsp),%r10
   40ab6:	mov    0x18(%rsp),%r11d
   40abb:	cmp    %r10,%rax
   40abe:	je     41e7d <__GI_____strtod_l_internal+0x22ed>
   40ac4:	mov    (%rsp),%rdi
   40ac8:	mov    %rax,(%rdi)
   40acb:	jmpq   40397 <__GI_____strtod_l_internal+0x807>
   40ad0:	mov    0x50(%rax),%rdi
   40ad4:	mov    %rdi,0x10(%rsp)
   40ad9:	movzbl (%rdi),%edi
   40adc:	lea    -0x1(%rdi),%edx
   40adf:	mov    %dil,0x8(%rsp)
   40ae4:	cmp    $0x7d,%dl
   40ae7:	ja     412bf <__GI_____strtod_l_internal+0x172f>
   40aed:	mov    0x48(%rax),%r15
   40af1:	cmpb   $0x0,(%r15)
   40af5:	jne    3fbc3 <__GI_____strtod_l_internal+0x33>
   40afb:	movq   $0x0,0x10(%rsp)
   40b04:	xor    %r15d,%r15d
   40b07:	jmpq   3fbc3 <__GI_____strtod_l_internal+0x33>
   40b0c:	mov    0x10(%rsp),%rdi
   40b11:	mov    %rbx,%rax
   40b14:	mov    %r14,%r12
   40b17:	mov    0x38(%rsp),%rbx
   40b1c:	mov    %r15d,%r14d
   40b1f:	mov    0x30(%rsp),%r15
   40b24:	cmp    %rdi,%rax
   40b27:	je     41e27 <__GI_____strtod_l_internal+0x2297>
   40b2d:	lea    0x70(%rsp),%rcx
   40b32:	sub    $0x8,%rsp
   40b36:	mov    %rbx,%rdi
   40b39:	push   %r15
   40b3b:	mov    0x28(%rsp),%r9
   40b40:	mov    0x20(%rsp),%rdx
   40b45:	mov    0x38(%rsp),%esi
   40b49:	lea    0x88(%rsp),%r8
   40b51:	callq  3f400 <str_to_mpn.isra.0>
   40b56:	lea    -0x1(%r12),%rax
   40b5b:	bsr    0x270(%rsp,%rax,8),%rbx
   40b64:	mov    %rax,0x28(%rsp)
   40b69:	pop    %r10
   40b6b:	pop    %r11
   40b6d:	xor    $0x3f,%rbx
   40b71:	test   %ebx,%ebx
   40b73:	je     40bb8 <__GI_____strtod_l_internal+0x1028>
   40b75:	mov    0x20(%rsp),%rdi
   40b7a:	mov    %ebx,%ecx
   40b7c:	mov    %r12,%rdx
   40b7f:	mov    %rdi,%rsi
   40b82:	callq  48f00 <__mpn_lshift>
   40b87:	mov    0x10(%rsp),%rdi
   40b8c:	mov    0x70(%rsp),%rdx
   40b91:	mov    %ebx,%ecx
   40b93:	mov    %rdi,%rsi
   40b96:	callq  48f00 <__mpn_lshift>
   40b9b:	test   %rax,%rax
   40b9e:	je     40bb8 <__GI_____strtod_l_internal+0x1028>
   40ba0:	mov    0x70(%rsp),%rcx
   40ba5:	lea    0x1(%rcx),%rdx
   40ba9:	mov    %rax,0x80(%rsp,%rcx,8)
   40bb1:	mov    %rdx,0x70(%rsp)
   40bb6:	jmp    40bbd <__GI_____strtod_l_internal+0x102d>
   40bb8:	mov    0x70(%rsp),%rdx
   40bbd:	movslq (%rsp),%rcx
   40bc1:	cmp    $0x1,%r12
   40bc5:	mov    %rcx,0x78(%rsp)
   40bca:	je     41816 <__GI_____strtod_l_internal+0x1c86>
   40bd0:	cmp    $0x2,%r12
   40bd4:	je     413e9 <__GI_____strtod_l_internal+0x1859>
   40bda:	mov    0x18(%rsp),%rax
   40bdf:	mov    0x20(%rsp),%rdi
   40be4:	lea    -0x2(%r12),%rbp
   40be9:	mov    %rcx,0x28(%rsp)
   40bee:	mov    0x260(%rsp,%rbp,8),%r15
   40bf6:	mov    0x260(%rsp,%rax,8),%r13
   40bfe:	mov    %r12,%rax
   40c01:	sub    %rdx,%rax
   40c04:	lea    (%rdi,%rax,8),%rsi
   40c08:	mov    0x10(%rsp),%rdi
   40c0d:	callq  48a10 <__mpn_cmp>
   40c12:	test   %eax,%eax
   40c14:	mov    0x70(%rsp),%rdx
   40c19:	mov    0x28(%rsp),%rcx
   40c1e:	jle    40c3a <__GI_____strtod_l_internal+0x10aa>
   40c20:	mov    0x70(%rsp),%rax
   40c25:	lea    0x1(%rax),%rdx
   40c29:	movq   $0x0,0x80(%rsp,%rax,8)
   40c35:	mov    %rdx,0x70(%rsp)
   40c3a:	cmp    %rdx,%r12
   40c3d:	jle    41adc <__GI_____strtod_l_internal+0x1f4c>
   40c43:	mov    %r12,%rbx
   40c46:	mov    (%rsp),%edi
   40c49:	sub    %rdx,%rbx
   40c4c:	mov    %rbx,%rax
   40c4f:	shl    $0x6,%rax
   40c53:	test   %edi,%edi
   40c55:	jle    41ecf <__GI_____strtod_l_internal+0x233f>
   40c5b:	add    %rax,%rcx
   40c5e:	cmp    $0x35,%rcx
   40c62:	jg     41f25 <__GI_____strtod_l_internal+0x2395>
   40c68:	cmp    $0x1,%rbx
   40c6c:	jne    41f76 <__GI_____strtod_l_internal+0x23e6>
   40c72:	movq   $0x0,0x60(%rsp)
   40c7b:	mov    %ebx,%eax
   40c7d:	shl    $0x6,%eax
   40c80:	add    %eax,(%rsp)
   40c83:	test   %edx,%edx
   40c85:	mov    %edx,%eax
   40c87:	jle    40d66 <__GI_____strtod_l_internal+0x11d6>
   40c8d:	mov    %edx,%r9d
   40c90:	movslq %edx,%rdx
   40c93:	lea    0x0(,%rdx,8),%rsi
   40c9b:	add    %rbx,%rdx
   40c9e:	lea    0x8(,%rdx,8),%rdi
   40ca6:	lea    -0x8(,%rdx,8),%r10
   40cae:	lea    -0x10(%rsi),%rcx
   40cb2:	cmp    %rcx,%rdi
   40cb5:	setle  %dil
   40cb9:	cmp    %rsi,%r10
   40cbc:	setge  %sil
   40cc0:	or     %sil,%dil
   40cc3:	je     41eed <__GI_____strtod_l_internal+0x235d>
   40cc9:	cmp    $0x18,%eax
   40ccc:	jbe    41eed <__GI_____strtod_l_internal+0x235d>
   40cd2:	mov    0x10(%rsp),%rdi
   40cd7:	lea    (%rdi,%rcx,1),%rsi
   40cdb:	shr    $0x3,%rsi
   40cdf:	mov    %esi,%edi
   40ce1:	and    $0x1,%edi
   40ce4:	je     40cfc <__GI_____strtod_l_internal+0x116c>
   40ce6:	sub    $0x1,%eax
   40ce9:	movslq %eax,%rsi
   40cec:	mov    0x80(%rsp,%rsi,8),%rsi
   40cf4:	mov    %rsi,0x80(%rsp,%rdx,8)
   40cfc:	mov    %r9d,%r8d
   40cff:	mov    %edi,%edx
   40d01:	sub    %edi,%r8d
   40d04:	neg    %rdx
   40d07:	mov    0x10(%rsp),%rdi
   40d0c:	lea    -0x2(%r8),%esi
   40d10:	shl    $0x3,%rdx
   40d14:	add    %rdx,%rcx
   40d17:	add    %r10,%rdx
   40d1a:	shr    %esi
   40d1c:	lea    (%rdi,%rdx,1),%r9
   40d20:	add    %rdi,%rcx
   40d23:	add    $0x1,%esi
   40d26:	xor    %edx,%edx
   40d28:	xor    %edi,%edi
   40d2a:	lea    (%rsi,%rsi,1),%r11d
   40d2e:	movdqa (%rcx,%rdx,1),%xmm0
   40d33:	add    $0x1,%edi
   40d36:	movups %xmm0,(%r9,%rdx,1)
   40d3b:	sub    $0x10,%rdx
   40d3f:	cmp    %esi,%edi
   40d41:	jb     40d2e <__GI_____strtod_l_internal+0x119e>
   40d43:	sub    %r11d,%eax
   40d46:	cmp    %r8d,%r11d
   40d49:	je     40d66 <__GI_____strtod_l_internal+0x11d6>
   40d4b:	lea    -0x1(%rax),%edx
   40d4e:	cltq   
   40d50:	add    %rbx,%rax
   40d53:	movslq %edx,%rdx
   40d56:	mov    0x80(%rsp,%rdx,8),%rdx
   40d5e:	mov    %rdx,0x80(%rsp,%rax,8)
   40d66:	mov    0x10(%rsp),%rdi
   40d6b:	lea    0x8(,%rbx,8),%rdx
   40d73:	xor    %esi,%esi
   40d75:	callq  90e00 <__GI_memset>
   40d7a:	cmpl   $0x35,(%rsp)
   40d7e:	lea    -0x1(%r12),%eax
   40d83:	movq   $0x0,0x260(%rsp,%r12,8)
   40d8f:	mov    0x80(%rsp,%r12,8),%r9
   40d97:	mov    %eax,0x30(%rsp)
   40d9b:	jg     4211b <__GI_____strtod_l_internal+0x258b>
   40da1:	lea    0x1(%r12),%rax
   40da6:	mov    0x10(%rsp),%rdi
   40dab:	mov    %r9,%rbx
   40dae:	mov    %rax,0x38(%rsp)
   40db3:	lea    -0x2(%r12),%eax
   40db8:	mov    %rdi,%rdx
   40dbb:	lea    0x8(,%rax,8),%r14
   40dc3:	movslq 0x30(%rsp),%rax
   40dc8:	sub    %r14,%rdx
   40dcb:	mov    %r14,0x50(%rsp)
   40dd0:	shl    $0x3,%rax
   40dd4:	lea    0x8(%rdx,%rax,1),%rsi
   40dd9:	sub    %r14,%rax
   40ddc:	mov    %r15,%r14
   40ddf:	add    %rdi,%rax
   40de2:	mov    %r13,%r15
   40de5:	mov    %rsi,0x48(%rsp)
   40dea:	mov    %rax,0x40(%rsp)
   40def:	nop
   40df0:	cmp    %r15,%rbx
   40df3:	mov    $0xffffffffffffffff,%r13
   40dfa:	je     40e50 <__GI_____strtod_l_internal+0x12c0>
   40dfc:	mov    0x18(%rsp),%rax
   40e01:	mov    %rbx,%rdx
   40e04:	mov    0x80(%rsp,%rax,8),%rax
   40e0c:	mov    %rax,0x28(%rsp)
   40e11:	div    %r15
   40e14:	mov    %rax,%r13
   40e17:	mov    %rdx,%rbx
   40e1a:	mov    %r14,%rax
   40e1d:	mul    %r13
   40e20:	mov    %rdx,%rcx
   40e23:	jmp    40e36 <__GI_____strtod_l_internal+0x12a6>
   40e25:	nopl   (%rax)
   40e28:	xor    %edx,%edx
   40e2a:	cmp    %r14,%rax
   40e2d:	setb   %dl
   40e30:	sub    %r14,%rax
   40e33:	sub    %rdx,%rcx
   40e36:	cmp    %rbx,%rcx
   40e39:	ja     40e47 <__GI_____strtod_l_internal+0x12b7>
   40e3b:	jne    40e50 <__GI_____strtod_l_internal+0x12c0>
   40e3d:	cmp    0x80(%rsp,%rbp,8),%rax
   40e45:	jbe    40e50 <__GI_____strtod_l_internal+0x12c0>
   40e47:	sub    $0x1,%r13
   40e4b:	add    %r15,%rbx
   40e4e:	jae    40e28 <__GI_____strtod_l_internal+0x1298>
   40e50:	mov    0x10(%rsp),%rbx
   40e55:	mov    0x38(%rsp),%rdx
   40e5a:	mov    %r13,%rcx
   40e5d:	mov    0x20(%rsp),%rsi
   40e62:	mov    %rbx,%rdi
   40e65:	callq  4a530 <__mpn_submul_1>
   40e6a:	cmp    0x80(%rsp,%r12,8),%rax
   40e72:	je     40e94 <__GI_____strtod_l_internal+0x1304>
   40e74:	mov    0x20(%rsp),%rdx
   40e79:	mov    %r12,%rcx
   40e7c:	mov    %rbx,%rsi
   40e7f:	mov    %rbx,%rdi
   40e82:	callq  48870 <__mpn_add_n>
   40e87:	test   %rax,%rax
   40e8a:	je     4212c <__GI_____strtod_l_internal+0x259c>
   40e90:	sub    $0x1,%r13
   40e94:	mov    0x18(%rsp),%rax
   40e99:	mov    0x30(%rsp),%esi
   40e9d:	mov    0x80(%rsp,%rax,8),%rbx
   40ea5:	test   %esi,%esi
   40ea7:	mov    %rbx,0x80(%rsp,%r12,8)
   40eaf:	jle    40ec5 <__GI_____strtod_l_internal+0x1335>
   40eb1:	mov    0x50(%rsp),%rdx
   40eb6:	mov    0x40(%rsp),%rsi
   40ebb:	mov    0x48(%rsp),%rdi
   40ec0:	callq  909a0 <memcpy@GLIBC_2.2.5>
   40ec5:	mov    (%rsp),%ecx
   40ec8:	movq   $0x0,0x80(%rsp)
   40ed4:	test   %ecx,%ecx
   40ed6:	jne    414e8 <__GI_____strtod_l_internal+0x1958>
   40edc:	test   %r13,%r13
   40edf:	je     414d0 <__GI_____strtod_l_internal+0x1940>
   40ee5:	bsr    %r13,%rax
   40ee9:	mov    0x78(%rsp),%rsi
   40eee:	xor    $0x3f,%rax
   40ef2:	movslq %eax,%rcx
   40ef5:	mov    %eax,%edx
   40ef7:	sub    %rcx,%rsi
   40efa:	mov    $0x40,%ecx
   40eff:	mov    %ecx,%edi
   40f01:	mov    %rsi,0x78(%rsp)
   40f06:	sub    %eax,%edi
   40f08:	cmp    $0x35,%edi
   40f0b:	jle    4221d <__GI_____strtod_l_internal+0x268d>
   40f11:	lea    0x35(%rdx),%r14d
   40f15:	mov    %r13,%rax
   40f18:	lea    0x60(%rsp),%r10
   40f1d:	mov    %r13,%rbx
   40f20:	sub    %r14d,%ecx
   40f23:	shr    %cl,%rax
   40f26:	mov    %rax,0x60(%rsp)
   40f2b:	test   %r12d,%r12d
   40f2e:	mov    %r12d,%edx
   40f31:	js     40f73 <__GI_____strtod_l_internal+0x13e3>
   40f33:	movslq %r12d,%rax
   40f36:	cmpq   $0x0,0x80(%rsp,%rax,8)
   40f3f:	jne    40f73 <__GI_____strtod_l_internal+0x13e3>
   40f41:	lea    -0x1(%r12),%eax
   40f46:	mov    %r12d,%r12d
   40f49:	mov    0x10(%rsp),%rdi
   40f4e:	cltq   
   40f50:	mov    %rax,%rcx
   40f53:	sub    %r12,%rcx
   40f56:	jmp    40f6c <__GI_____strtod_l_internal+0x13dc>
   40f58:	nopl   0x0(%rax,%rax,1)
   40f60:	sub    $0x1,%rax
   40f64:	cmpq   $0x0,0x8(%rdi,%rax,8)
   40f6a:	jne    40f73 <__GI_____strtod_l_internal+0x13e3>
   40f6c:	cmp    %rax,%rcx
   40f6f:	mov    %eax,%edx
   40f71:	jne    40f60 <__GI_____strtod_l_internal+0x13d0>
   40f73:	not    %edx
   40f75:	mov    $0x3f,%r8d
   40f7b:	sub    $0x1,%rsi
   40f7f:	mov    %edx,%r9d
   40f82:	sub    %r14d,%r8d
   40f85:	shr    $0x1f,%r9d
   40f89:	or     0x5f(%rsp),%r9b
   40f8e:	mov    0x8(%rsp),%edx
   40f92:	and    $0x1,%r9d
   40f96:	movslq %r8d,%r8
   40f99:	mov    %rbx,%rcx
   40f9c:	mov    %r10,%rdi
   40f9f:	callq  3f6e0 <round_and_return>
   40fa4:	jmpq   3fd3c <__GI_____strtod_l_internal+0x1ac>
   40fa9:	lea    0x2(%r12),%rdi
   40fae:	movzbl 0x2(%r12),%esi
   40fb4:	movl   $0x0,0x10(%rsp)
   40fbc:	jmpq   404a6 <__GI_____strtod_l_internal+0x916>
   40fc1:	test   %r8,%r8
   40fc4:	je     41393 <__GI_____strtod_l_internal+0x1803>
   40fca:	test   %rcx,%rcx
   40fcd:	jne    41f57 <__GI_____strtod_l_internal+0x23c7>
   40fd3:	mov    %r8,%rax
   40fd6:	shr    $0x3f,%rax
   40fda:	test   %al,%al
   40fdc:	jne    41f57 <__GI_____strtod_l_internal+0x23c7>
   40fe2:	mov    $0x135,%ebp
   40fe7:	sub    %r8,%rbp
   40fea:	test   %rbp,%rbp
   40fed:	mov    $0x0,%eax
   40ff2:	cmovs  %rax,%rbp
   40ff6:	jmpq   404e1 <__GI_____strtod_l_internal+0x951>
   40ffb:	mov    0x8(%rsp),%r8d
   41000:	movsd  0x150740(%rip),%xmm0        # 191748 <conversion_rate+0x30>
   41008:	test   %r8d,%r8d
   4100b:	je     405c0 <__GI_____strtod_l_internal+0xa30>
   41011:	mulsd  0x150747(%rip),%xmm0        # 191760 <conversion_rate+0x48>
   41019:	jmpq   405c8 <__GI_____strtod_l_internal+0xa38>
   4101e:	movzbl (%r15),%eax
   41022:	test   %al,%al
   41024:	je     41e8e <__GI_____strtod_l_internal+0x22fe>
   4102a:	cmp    %cl,%al
   4102c:	jne    3fdde <__GI_____strtod_l_internal+0x24e>
   41032:	mov    $0x1,%eax
   41037:	jmp    4104f <__GI_____strtod_l_internal+0x14bf>
   41039:	nopl   0x0(%rax)
   41040:	add    $0x1,%rax
   41044:	cmp    -0x1(%r12,%rax,1),%cl
   41049:	jne    3fdde <__GI_____strtod_l_internal+0x24e>
   4104f:	movzbl (%r15,%rax,1),%ecx
   41054:	test   %cl,%cl
   41056:	jne    41040 <__GI_____strtod_l_internal+0x14b0>
   41058:	sub    $0x1,%rax
   4105c:	add    %r12,%rax
   4105f:	jmpq   4060f <__GI_____strtod_l_internal+0xa7f>
   41064:	lea    0x37e775(%rip),%rcx        # 3bf7e0 <_nl_C_locobj>
   4106b:	lea    0x148819(%rip),%rsi        # 18988b <_nl_POSIX_name+0xa6>
   41072:	mov    $0x3,%edx
   41077:	mov    %rbx,%rdi
   4107a:	callq  93570 <__GI___strncasecmp_l>
   4107f:	test   %eax,%eax
   41081:	jne    3fd2d <__GI_____strtod_l_internal+0x19d>
   41087:	mov    (%rsp),%r15
   4108b:	test   %r15,%r15
   4108e:	je     410bc <__GI_____strtod_l_internal+0x152c>
   41090:	lea    0x3(%rbx),%rbp
   41094:	lea    0x37e745(%rip),%rcx        # 3bf7e0 <_nl_C_locobj>
   4109b:	lea    0x1487ed(%rip),%rsi        # 18988f <_nl_POSIX_name+0xaa>
   410a2:	mov    $0x5,%edx
   410a7:	add    $0x8,%rbx
   410ab:	mov    %rbp,%rdi
   410ae:	callq  93570 <__GI___strncasecmp_l>
   410b3:	test   %eax,%eax
   410b5:	cmove  %rbx,%rbp
   410b9:	mov    %rbp,(%r15)
   410bc:	mov    0x8(%rsp),%eax
   410c0:	movsd  0x1506b0(%rip),%xmm0        # 191778 <conversion_rate+0x60>
   410c8:	test   %eax,%eax
   410ca:	je     3fd3c <__GI_____strtod_l_internal+0x1ac>
   410d0:	movsd  0x1506a8(%rip),%xmm0        # 191780 <conversion_rate+0x68>
   410d8:	jmpq   3fd3c <__GI_____strtod_l_internal+0x1ac>
   410dd:	lea    0x37e6fc(%rip),%rcx        # 3bf7e0 <_nl_C_locobj>
   410e4:	lea    0x1487aa(%rip),%rsi        # 189895 <_nl_POSIX_name+0xb0>
   410eb:	mov    $0x3,%edx
   410f0:	mov    %rbx,%rdi
   410f3:	callq  93570 <__GI___strncasecmp_l>
   410f8:	test   %eax,%eax
   410fa:	jne    3fd2d <__GI_____strtod_l_internal+0x19d>
   41100:	cmpb   $0x28,0x3(%rbx)
   41104:	lea    0x3(%rbx),%rbp
   41108:	movsd  0x150658(%rip),%xmm0        # 191768 <conversion_rate+0x50>
   41110:	je     41ea1 <__GI_____strtod_l_internal+0x2311>
   41116:	mov    (%rsp),%rax
   4111a:	test   %rax,%rax
   4111d:	je     3fd3c <__GI_____strtod_l_internal+0x1ac>
   41123:	mov    %rbp,(%rax)
   41126:	jmpq   3fd3c <__GI_____strtod_l_internal+0x1ac>
   4112b:	movsbq (%rbx),%rdx
   4112f:	mov    0x68(%r9),%rdi
   41133:	testb  $0x10,0x1(%rdi,%rdx,2)
   41138:	mov    %rdx,%rax
   4113b:	jne    41160 <__GI_____strtod_l_internal+0x15d0>
   4113d:	nopl   (%rax)
   41140:	add    $0x1,%rbx
   41144:	movsbq (%rbx),%rdx
   41148:	testb  $0x10,0x1(%rdi,%rdx,2)
   4114d:	mov    %rdx,%rax
   41150:	je     41140 <__GI_____strtod_l_internal+0x15b0>
   41152:	jmp    41160 <__GI_____strtod_l_internal+0x15d0>
   41154:	nopl   0x0(%rax)
   41158:	add    $0x1,%rbx
   4115c:	movsbq (%rbx),%rax
   41160:	cmp    $0x30,%al
   41162:	je     41158 <__GI_____strtod_l_internal+0x15c8>
   41164:	movsbl %al,%r10d
   41168:	add    $0x1,%rbx
   4116c:	sub    $0x30,%r10d
   41170:	cmp    $0x9,%r10d
   41174:	ja     4149f <__GI_____strtod_l_internal+0x190f>
   4117a:	lea    0x13e2df(%rip),%rax        # 17f460 <nbits.11331>
   41181:	movslq %r10d,%r10
   41184:	mov    (%rax,%r10,4),%edx
   41188:	test   %edx,%edx
   4118a:	je     41fb4 <__GI_____strtod_l_internal+0x2424>
   41190:	mov    0x78(%rsp),%rsi
   41195:	mov    $0x35,%ecx
   4119a:	mov    $0x34,%eax
   4119f:	sub    %edx,%ecx
   411a1:	sub    %edx,%eax
   411a3:	shl    %cl,%r10
   411a6:	test   %rsi,%rsi
   411a9:	mov    %r10,0x60(%rsp)
   411ae:	js     414b0 <__GI_____strtod_l_internal+0x1920>
   411b4:	movabs $0x7fffffffffffffff,%r11
   411be:	movslq %edx,%rcx
   411c1:	sub    %rsi,%r11
   411c4:	sub    %rcx,%r11
   411c7:	lea    0x4(%r11),%rcx
   411cb:	add    $0x1,%r11
   411cf:	cmovns %r11,%rcx
   411d3:	sar    $0x2,%rcx
   411d7:	cmp    %r8,%rcx
   411da:	jb     4222a <__GI_____strtod_l_internal+0x269a>
   411e0:	sub    $0x1,%edx
   411e3:	movslq %edx,%rdx
   411e6:	lea    -0x4(%rdx,%r8,4),%rdx
   411eb:	add    %rdx,%rsi
   411ee:	sub    $0x1,%r14
   411f2:	mov    %rsi,0x78(%rsp)
   411f7:	je     4194d <__GI_____strtod_l_internal+0x1dbd>
   411fd:	mov    0x18(%rsp),%r8
   41202:	jmp    4121e <__GI_____strtod_l_internal+0x168e>
   41204:	nopl   0x0(%rax)
   41208:	lea    -0x3(%rax),%ecx
   4120b:	sub    $0x4,%eax
   4120e:	shl    %cl,%rdx
   41211:	or     %rdx,%r10
   41214:	sub    $0x1,%r14
   41218:	je     41948 <__GI_____strtod_l_internal+0x1db8>
   4121e:	movsbq (%rbx),%rdx
   41222:	testb  $0x10,0x1(%rdi,%rdx,2)
   41227:	mov    %rdx,%rcx
   4122a:	jne    41233 <__GI_____strtod_l_internal+0x16a3>
   4122c:	add    %r8,%rbx
   4122f:	movsbq (%rbx),%rcx
   41233:	movsbl %cl,%edx
   41236:	add    $0x1,%rbx
   4123a:	sub    $0x30,%edx
   4123d:	cmp    $0x9,%edx
   41240:	jbe    4124c <__GI_____strtod_l_internal+0x16bc>
   41242:	mov    0x70(%r9),%rdx
   41246:	mov    (%rdx,%rcx,4),%edx
   41249:	sub    $0x57,%edx
   4124c:	cmp    $0x2,%eax
   4124f:	movslq %edx,%rdx
   41252:	jg     41208 <__GI_____strtod_l_internal+0x1678>
   41254:	mov    $0x3,%ecx
   41259:	mov    %rdx,%rdi
   4125c:	sub    %eax,%ecx
   4125e:	add    $0x3d,%eax
   41261:	shr    %cl,%rdi
   41264:	mov    %eax,%ecx
   41266:	or     %rdi,%r10
   41269:	shl    %cl,%rdx
   4126c:	sub    $0x1,%r14
   41270:	mov    %r10,0x60(%rsp)
   41275:	mov    %rdx,%rcx
   41278:	je     412a3 <__GI_____strtod_l_internal+0x1713>
   4127a:	cmpb   $0x30,(%rbx)
   4127d:	lea    0x1(%rbx),%rdx
   41281:	lea    (%rbx,%r14,1),%rax
   41285:	je     4129e <__GI_____strtod_l_internal+0x170e>
   41287:	jmpq   41da5 <__GI_____strtod_l_internal+0x2215>
   4128c:	nopl   0x0(%rax)
   41290:	add    $0x1,%rdx
   41294:	cmpb   $0x30,-0x1(%rdx)
   41298:	jne    41da5 <__GI_____strtod_l_internal+0x2215>
   4129e:	cmp    %rdx,%rax
   412a1:	jne    41290 <__GI_____strtod_l_internal+0x1700>
   412a3:	xor    %r9d,%r9d
   412a6:	mov    0x8(%rsp),%edx
   412aa:	lea    0x60(%rsp),%rdi
   412af:	mov    $0x3f,%r8d
   412b5:	callq  3f6e0 <round_and_return>
   412ba:	jmpq   3fd3c <__GI_____strtod_l_internal+0x1ac>
   412bf:	movq   $0x0,0x10(%rsp)
   412c8:	jmpq   3fbc3 <__GI_____strtod_l_internal+0x33>
   412cd:	xor    %eax,%eax
   412cf:	cmp    $0x10,%r11d
   412d3:	sete   %al
   412d6:	sub    $0x1,%r12
   412da:	xor    %r10d,%r10d
   412dd:	cmp    $0x10,%r11d
   412e1:	lea    0x1(%rax,%rax,2),%rbp
   412e6:	jne    4136f <__GI_____strtod_l_internal+0x17df>
   412ec:	mov    0x68(%r9),%rax
   412f0:	mov    %rdi,0x10(%rsp)
   412f5:	mov    %rax,%rdi
   412f8:	jmp    41323 <__GI_____strtod_l_internal+0x1793>
   412fa:	nopw   0x0(%rax,%rax,1)
   41300:	add    %rbp,%rdx
   41303:	sub    $0x1,%r8
   41307:	sub    $0x1,%r14
   4130b:	mov    %rdx,%rax
   4130e:	setne  %r10b
   41312:	shr    $0x3f,%rax
   41316:	and    %al,%r10b
   41319:	je     41e41 <__GI_____strtod_l_internal+0x22b1>
   4131f:	sub    $0x1,%r12
   41323:	movsbq (%r12),%rsi
   41328:	testb  $0x10,0x1(%rdi,%rsi,2)
   4132d:	je     4131f <__GI_____strtod_l_internal+0x178f>
   4132f:	cmp    $0x30,%sil
   41333:	je     41300 <__GI_____strtod_l_internal+0x1770>
   41335:	mov    0x10(%rsp),%rdi
   4133a:	test   %r10b,%r10b
   4133d:	je     40380 <__GI_____strtod_l_internal+0x7f0>
   41343:	mov    %rdx,0x78(%rsp)
   41348:	jmpq   40380 <__GI_____strtod_l_internal+0x7f0>
   4134d:	nopl   (%rax)
   41350:	add    %rbp,%rdx
   41353:	sub    $0x1,%r8
   41357:	mov    %rdx,%rax
   4135a:	shr    $0x3f,%rax
   4135e:	sub    $0x1,%r14
   41362:	setne  %r10b
   41366:	and    %al,%r10b
   41369:	je     41343 <__GI_____strtod_l_internal+0x17b3>
   4136b:	sub    $0x1,%r12
   4136f:	movsbl (%r12),%eax
   41374:	mov    %eax,%esi
   41376:	sub    $0x30,%eax
   41379:	cmp    $0x9,%eax
   4137c:	ja     4136b <__GI_____strtod_l_internal+0x17db>
   4137e:	cmp    $0x30,%sil
   41382:	je     41350 <__GI_____strtod_l_internal+0x17c0>
   41384:	jmp    4133a <__GI_____strtod_l_internal+0x17aa>
   41386:	mov    %rax,%r14
   41389:	movb   $0x1,0x5f(%rsp)
   4138e:	jmpq   40823 <__GI_____strtod_l_internal+0xc93>
   41393:	cmp    $0xffffffffffffffff,%rcx
   41397:	je     41d27 <__GI_____strtod_l_internal+0x2197>
   4139d:	movabs $0x7ffffffffffffeca,%rax
   413a7:	cmp    %rax,%rcx
   413aa:	ja     41ff2 <__GI_____strtod_l_internal+0x2462>
   413b0:	lea    0x135(%rcx),%rbp
   413b7:	jmpq   404e1 <__GI_____strtod_l_internal+0x951>
   413bc:	mulsd  0x150394(%rip),%xmm0        # 191758 <conversion_rate+0x40>
   413c4:	jmpq   405c8 <__GI_____strtod_l_internal+0xa38>
   413c9:	movabs $0x1ffffffffffffef3,%rax
   413d3:	cmp    %rax,%r8
   413d6:	ja     41f95 <__GI_____strtod_l_internal+0x2405>
   413dc:	lea    0x432(,%r8,4),%rbp
   413e4:	jmpq   404e1 <__GI_____strtod_l_internal+0x951>
   413e9:	cmp    $0x1,%rdx
   413ed:	mov    0x260(%rsp),%r8
   413f5:	mov    0x268(%rsp),%rdi
   413fd:	jg     41b6d <__GI_____strtod_l_internal+0x1fdd>
   41403:	mov    0x80(%rsp),%r12
   4140b:	cmp    %r12,%rdi
   4140e:	jbe    41e0b <__GI_____strtod_l_internal+0x227b>
   41414:	mov    (%rsp),%r9d
   41418:	test   %r9d,%r9d
   4141b:	jle    41ed9 <__GI_____strtod_l_internal+0x2349>
   41421:	mov    $0x35,%ebx
   41426:	sub    (%rsp),%ebx
   41429:	lea    0x60(%rsp),%r10
   4142e:	mov    %rcx,%rax
   41431:	je     4145a <__GI_____strtod_l_internal+0x18ca>
   41433:	mov    %r10,%rsi
   41436:	mov    %r10,%rdi
   41439:	mov    %ebx,%ecx
   4143b:	mov    $0x1,%edx
   41440:	mov    %r10,(%rsp)
   41444:	callq  48f00 <__mpn_lshift>
   41449:	mov    0x80(%rsp),%r12
   41451:	mov    (%rsp),%r10
   41455:	mov    0x78(%rsp),%rax
   4145a:	mov    $0x3f,%r8d
   41460:	mov    %r12,%rbp
   41463:	xor    %r12d,%r12d
   41466:	sub    %ebx,%r8d
   41469:	xor    %ebx,%ebx
   4146b:	movslq %r8d,%r8
   4146e:	test   %r12,%r12
   41471:	lea    -0x1(%rax),%rsi
   41475:	mov    %rbx,%rcx
   41478:	setne  %r9b
   4147c:	test   %rbp,%rbp
   4147f:	mov    %r10,%rdi
   41482:	setne  %dl
   41485:	or     %edx,%r9d
   41488:	or     0x5f(%rsp),%r9b
   4148d:	mov    0x8(%rsp),%edx
   41491:	and    $0x1,%r9d
   41495:	callq  3f6e0 <round_and_return>
   4149a:	jmpq   3fd3c <__GI_____strtod_l_internal+0x1ac>
   4149f:	mov    0x70(%r9),%rdx
   414a3:	mov    (%rdx,%rax,4),%r10d
   414a7:	sub    $0x57,%r10d
   414ab:	jmpq   4117a <__GI_____strtod_l_internal+0x15ea>
   414b0:	movslq %edx,%r11
   414b3:	movabs $0x8000000000000000,%rcx
   414bd:	sub    %r11,%rcx
   414c0:	sar    $0x2,%rcx
   414c4:	jmpq   411d7 <__GI_____strtod_l_internal+0x1647>
   414c9:	nopl   0x0(%rax)
   414d0:	subq   $0x40,0x78(%rsp)
   414d6:	movq   $0x0,0x60(%rsp)
   414df:	jmpq   40df0 <__GI_____strtod_l_internal+0x1260>
   414e4:	nopl   0x0(%rax)
   414e8:	mov    (%rsp),%eax
   414eb:	cmp    $0xfffffff6,%eax
   414ee:	jge    41500 <__GI_____strtod_l_internal+0x1970>
   414f0:	add    $0x40,%eax
   414f3:	mov    %r13,0x60(%rsp)
   414f8:	mov    %eax,(%rsp)
   414fb:	jmpq   40df0 <__GI_____strtod_l_internal+0x1260>
   41500:	mov    $0x35,%r14d
   41506:	sub    (%rsp),%r14d
   4150a:	mov    %r13,%rbx
   4150d:	lea    0x60(%rsp),%r10
   41512:	je     41542 <__GI_____strtod_l_internal+0x19b2>
   41514:	mov    %r14d,%ecx
   41517:	mov    %r10,%rsi
   4151a:	mov    %r10,%rdi
   4151d:	mov    $0x1,%edx
   41522:	mov    %r10,(%rsp)
   41526:	callq  48f00 <__mpn_lshift>
   4152b:	mov    $0x40,%ecx
   41530:	mov    %r13,%rax
   41533:	mov    (%rsp),%r10
   41537:	sub    %r14d,%ecx
   4153a:	shr    %cl,%rax
   4153d:	or     %rax,0x60(%rsp)
   41542:	mov    0x78(%rsp),%rsi
   41547:	jmpq   40f2b <__GI_____strtod_l_internal+0x139b>
   4154c:	nopl   0x0(%rax)
   41550:	xor    %eax,%eax
   41552:	jmpq   3fc68 <__GI_____strtod_l_internal+0xd8>
   41557:	mov    %ebp,%ecx
   41559:	mov    %rbx,%r10
   4155c:	mov    $0xa,%r11d
   41562:	jmpq   3fd88 <__GI_____strtod_l_internal+0x1f8>
   41567:	test   %r15,%r15
   4156a:	lea    0x2(%rbx),%r10
   4156e:	movsbq 0x2(%rbx),%rbp
   41573:	jne    421a2 <__GI_____strtod_l_internal+0x2612>
   41579:	cmp    $0x30,%bpl
   4157d:	jne    42189 <__GI_____strtod_l_internal+0x25f9>
   41583:	movq   $0x0,0x10(%rsp)
   4158c:	mov    $0x10,%r11d
   41592:	jmpq   3fd71 <__GI_____strtod_l_internal+0x1e1>
   41597:	mov    0x8(%rsp),%r11d
   4159c:	pxor   %xmm0,%xmm0
   415a0:	test   %r11d,%r11d
   415a3:	je     405c8 <__GI_____strtod_l_internal+0xa38>
   415a9:	movsd  0x1501bf(%rip),%xmm0        # 191770 <conversion_rate+0x58>
   415b1:	jmpq   405c8 <__GI_____strtod_l_internal+0xa38>
   415b6:	mov    0x10(%rsp),%edx
   415ba:	mov    %r10,%rax
   415bd:	mov    0x28(%rsp),%r12
   415c2:	neg    %rax
   415c5:	test   %edx,%edx
   415c7:	cmovne %rax,%r10
   415cb:	mov    %r10,0x78(%rsp)
   415d0:	jmpq   40659 <__GI_____strtod_l_internal+0xac9>
   415d5:	mov    %r8,%rdx
   415d8:	neg    %rdx
   415db:	cmp    %rax,%rdx
   415de:	cmovl  %rax,%rdx
   415e2:	jmpq   40779 <__GI_____strtod_l_internal+0xbe9>
   415e7:	lea    0x80(%rsp),%rax
   415ef:	lea    0x70(%rsp),%rcx
   415f4:	sub    $0x8,%rsp
   415f8:	mov    %rbx,%rdi
   415fb:	mov    %r13d,%esi
   415fe:	mov    %rax,0x18(%rsp)
   41603:	push   %r15
   41605:	mov    %rax,%rdx
   41608:	mov    0x28(%rsp),%r9
   4160d:	lea    0x88(%rsp),%r8
   41615:	callq  3f400 <str_to_mpn.isra.0>
   4161a:	mov    %rax,%rbx
   4161d:	mov    0x88(%rsp),%rax
   41625:	pop    %r12
   41627:	pop    %rdx
   41628:	test   %rax,%rax
   4162b:	mov    0x70(%rsp),%r12
   41630:	jle    41758 <__GI_____strtod_l_internal+0x1bc8>
   41636:	lea    0x260(%rsp),%rdi
   4163e:	lea    0x13e05b(%rip),%r10        # 17f6a0 <_fpioconst_pow10>
   41645:	mov    $0x1,%r9d
   4164b:	mov    %rdi,0x20(%rsp)
   41650:	mov    %rdi,%rbp
   41653:	mov    0x10(%rsp),%rdi
   41658:	mov    %rdi,(%rsp)
   4165c:	nopl   0x0(%rax)
   41660:	movslq %r9d,%rcx
   41663:	test   %rax,%rcx
   41666:	je     41703 <__GI_____strtod_l_internal+0x1b73>
   4166c:	mov    0x8(%r10),%rdi
   41670:	xor    %rax,%rcx
   41673:	mov    %r9d,0x38(%rsp)
   41678:	mov    %rcx,0x78(%rsp)
   4167d:	mov    (%r10),%rax
   41680:	mov    %r10,0x30(%rsp)
   41685:	lea    -0x1(%rdi),%r11
   41689:	lea    0x13e190(%rip),%rdi        # 17f820 <__tens>
   41690:	cmp    %r12,%r11
   41693:	jg     4170f <__GI_____strtod_l_internal+0x1b7f>
   41695:	mov    (%rsp),%rsi
   41699:	lea    0x8(%rdi,%rax,8),%rcx
   4169e:	mov    %r11,%r8
   416a1:	mov    %r12,%rdx
   416a4:	mov    %rbp,%rdi
   416a7:	mov    %r11,0x28(%rsp)
   416ac:	callq  49160 <__mpn_mul>
   416b1:	mov    0x28(%rsp),%r11
   416b6:	mov    0x30(%rsp),%r10
   416bb:	mov    0x38(%rsp),%r9d
   416c0:	add    0x70(%rsp),%r11
   416c5:	test   %rax,%rax
   416c8:	mov    %r11,%r12
   416cb:	mov    %r11,0x70(%rsp)
   416d0:	jne    416db <__GI_____strtod_l_internal+0x1b4b>
   416d2:	sub    $0x1,%r12
   416d6:	mov    %r12,0x70(%rsp)
   416db:	mov    0x78(%rsp),%rax
   416e0:	add    %r9d,%r9d
   416e3:	add    $0x18,%r10
   416e7:	test   %rax,%rax
   416ea:	je     4173c <__GI_____strtod_l_internal+0x1bac>
   416ec:	mov    (%rsp),%rdx
   416f0:	movslq %r9d,%rcx
   416f3:	mov    %rbp,(%rsp)
   416f7:	test   %rax,%rcx
   416fa:	mov    %rdx,%rbp
   416fd:	jne    4166c <__GI_____strtod_l_internal+0x1adc>
   41703:	add    %r9d,%r9d
   41706:	add    $0x18,%r10
   4170a:	jmpq   41660 <__GI_____strtod_l_internal+0x1ad0>
   4170f:	mov    (%rsp),%rcx
   41713:	lea    0x8(%rdi,%rax,8),%rsi
   41718:	mov    %r11,%rdx
   4171b:	mov    %r12,%r8
   4171e:	mov    %rbp,%rdi
   41721:	mov    %r11,0x28(%rsp)
   41726:	callq  49160 <__mpn_mul>
   4172b:	mov    0x38(%rsp),%r9d
   41730:	mov    0x30(%rsp),%r10
   41735:	mov    0x28(%rsp),%r11
   4173a:	jmp    416c0 <__GI_____strtod_l_internal+0x1b30>
   4173c:	cmp    0x20(%rsp),%rbp
   41741:	jne    41758 <__GI_____strtod_l_internal+0x1bc8>
   41743:	mov    0x10(%rsp),%rdi
   41748:	lea    0x0(,%r12,8),%rdx
   41750:	mov    %rbp,%rsi
   41753:	callq  909a0 <memcpy@GLIBC_2.2.5>
   41758:	lea    -0x1(%r12),%rdi
   4175d:	mov    %r12d,%esi
   41760:	shl    $0x6,%esi
   41763:	bsr    0x80(%rsp,%rdi,8),%rax
   4176c:	xor    $0x3f,%rax
   41770:	sub    %eax,%esi
   41772:	cmp    $0x400,%esi
   41778:	mov    %esi,(%rsp)
   4177b:	jg     41a28 <__GI_____strtod_l_internal+0x1e98>
   41781:	cmp    $0x35,%esi
   41784:	jle    41a57 <__GI_____strtod_l_internal+0x1ec7>
   4178a:	lea    -0x35(%rsi),%edx
   4178d:	mov    %edx,%ecx
   4178f:	sar    $0x6,%ecx
   41792:	and    $0x3f,%edx
   41795:	movslq %ecx,%rax
   41798:	jne    41db0 <__GI_____strtod_l_internal+0x2220>
   4179e:	mov    0x80(%rsp,%rax,8),%rdx
   417a6:	lea    -0x1(%rax),%rcx
   417aa:	mov    $0x3f,%r8d
   417b0:	mov    %rdx,0x60(%rsp)
   417b5:	cmpq   $0x0,0x80(%rsp)
   417be:	jne    42011 <__GI_____strtod_l_internal+0x2481>
   417c4:	mov    0x10(%rsp),%rdi
   417c9:	mov    $0x1,%eax
   417ce:	xchg   %ax,%ax
   417d0:	movslq %eax,%rdx
   417d3:	add    $0x1,%rax
   417d7:	cmpq   $0x0,-0x8(%rdi,%rax,8)
   417dd:	je     417d0 <__GI_____strtod_l_internal+0x1c40>
   417df:	cmp    %r13,%r14
   417e2:	mov    $0x1,%r9d
   417e8:	ja     417f1 <__GI_____strtod_l_internal+0x1c61>
   417ea:	cmp    %rcx,%rdx
   417ed:	setl   %r9b
   417f1:	mov    0x80(%rsp,%rcx,8),%rcx
   417f9:	mov    0x8(%rsp),%edx
   417fd:	sub    $0x1,%esi
   41800:	lea    0x60(%rsp),%rdi
   41805:	movslq %esi,%rsi
   41808:	and    $0x1,%r9d
   4180c:	callq  3f6e0 <round_and_return>
   41811:	jmpq   3fd3c <__GI_____strtod_l_internal+0x1ac>
   41816:	mov    0x80(%rsp),%rbp
   4181e:	mov    0x260(%rsp),%rsi
   41826:	cmp    %rsi,%rbp
   41829:	jae    420f2 <__GI_____strtod_l_internal+0x2562>
   4182f:	cmp    $0x1,%rdx
   41833:	jne    420f2 <__GI_____strtod_l_internal+0x2562>
   41839:	mov    (%rsp),%r8d
   4183d:	xor    %edi,%edi
   4183f:	mov    $0x40,%ecx
   41844:	mov    %rbp,%rdx
   41847:	mov    %rdi,%rax
   4184a:	div    %rsi
   4184d:	test   %r8d,%r8d
   41850:	jne    418de <__GI_____strtod_l_internal+0x1d4e>
   41856:	nopw   %cs:0x0(%rax,%rax,1)
   41860:	test   %rax,%rax
   41863:	je     418d0 <__GI_____strtod_l_internal+0x1d40>
   41865:	bsr    %rax,%r8
   41869:	mov    0x78(%rsp),%rbx
   4186e:	xor    $0x3f,%r8
   41872:	movslq %r8d,%r9
   41875:	mov    %r8d,%r14d
   41878:	sub    %r9,%rbx
   4187b:	mov    %rbx,%r9
   4187e:	mov    %rbx,0x78(%rsp)
   41883:	mov    %ecx,%ebx
   41885:	sub    %r8d,%ebx
   41888:	cmp    $0x35,%ebx
   4188b:	mov    %ebx,%r8d
   4188e:	jle    42111 <__GI_____strtod_l_internal+0x2581>
   41894:	add    $0x35,%r14d
   41898:	mov    %rax,%rbx
   4189b:	lea    0x60(%rsp),%r10
   418a0:	sub    %r14d,%ecx
   418a3:	mov    %rdx,%rbp
   418a6:	mov    %r9,%rdx
   418a9:	shr    %cl,%rax
   418ac:	mov    %rax,0x60(%rsp)
   418b1:	test   %rbp,%rbp
   418b4:	mov    $0x3f,%r8d
   418ba:	lea    -0x1(%rdx),%rsi
   418be:	setne  %r9b
   418c2:	sub    %r14d,%r8d
   418c5:	or     0x5f(%rsp),%r9b
   418ca:	jmpq   40f8e <__GI_____strtod_l_internal+0x13fe>
   418cf:	nop
   418d0:	subq   $0x40,0x78(%rsp)
   418d6:	div    %rsi
   418d9:	jmpq   41860 <__GI_____strtod_l_internal+0x1cd0>
   418de:	cmp    $0xfffffff6,%r8d
   418e2:	jge    418f2 <__GI_____strtod_l_internal+0x1d62>
   418e4:	mov    %rax,0x60(%rsp)
   418e9:	add    $0x40,%r8d
   418ed:	jmpq   41847 <__GI_____strtod_l_internal+0x1cb7>
   418f2:	mov    $0x35,%r14d
   418f8:	mov    %rdx,%rbp
   418fb:	mov    %rax,%rbx
   418fe:	sub    %r8d,%r14d
   41901:	lea    0x60(%rsp),%r10
   41906:	je     41936 <__GI_____strtod_l_internal+0x1da6>
   41908:	mov    %r14d,%ecx
   4190b:	mov    %r10,%rsi
   4190e:	mov    %r10,%rdi
   41911:	mov    $0x1,%edx
   41916:	mov    %r10,(%rsp)
   4191a:	callq  48f00 <__mpn_lshift>
   4191f:	mov    $0x40,%ecx
   41924:	mov    %rbx,%rax
   41927:	mov    (%rsp),%r10
   4192b:	sub    %r14d,%ecx
   4192e:	shr    %cl,%rax
   41931:	or     %rax,0x60(%rsp)
   41936:	mov    0x78(%rsp),%rdx
   4193b:	jmpq   418b1 <__GI_____strtod_l_internal+0x1d21>
   41940:	mov    %r12,%rax
   41943:	jmpq   3fceb <__GI_____strtod_l_internal+0x15b>
   41948:	mov    %r10,0x60(%rsp)
   4194d:	mov    0x8(%rsp),%edx
   41951:	lea    0x60(%rsp),%rdi
   41956:	xor    %r9d,%r9d
   41959:	xor    %r8d,%r8d
   4195c:	xor    %ecx,%ecx
   4195e:	callq  3f6e0 <round_and_return>
   41963:	jmpq   3fd3c <__GI_____strtod_l_internal+0x1ac>
   41968:	nopl   0x0(%rax,%rax,1)
   41970:	movabs $0x1fffffffffffffff,%rax
   4197a:	cmp    %rax,%rcx
   4197d:	ja     42268 <__GI_____strtod_l_internal+0x26d8>
   41983:	mov    0x78(%rsp),%rax
   41988:	movabs $0x8000000000000000,%rdx
   41992:	add    %rax,%rdx
   41995:	shr    $0x2,%rdx
   41999:	cmp    %rcx,%rdx
   4199c:	jb     42249 <__GI_____strtod_l_internal+0x26b9>
   419a2:	lea    0x0(,%rcx,4),%rdx
   419aa:	jmpq   4073d <__GI_____strtod_l_internal+0xbad>
   419af:	test   %r13,%r13
   419b2:	jne    42076 <__GI_____strtod_l_internal+0x24e6>
   419b8:	cmpb   $0x30,(%rbx)
   419bb:	je     42076 <__GI_____strtod_l_internal+0x24e6>
   419c1:	mov    $0x1,%eax
   419c6:	movabs $0x5555555555555556,%rdx
   419d0:	sub    %rcx,%rax
   419d3:	lea    (%rax,%rax,4),%rsi
   419d7:	add    %rsi,%rsi
   419da:	mov    %rsi,%rax
   419dd:	sar    $0x3f,%rsi
   419e1:	imul   %rdx
   419e4:	mov    %rdx,%rax
   419e7:	mov    %ecx,%edx
   419e9:	sub    %rsi,%rax
   419ec:	mov    $0x434,%esi
   419f1:	add    $0x36,%eax
   419f4:	cmp    $0x434,%eax
   419f9:	cmovg  %esi,%eax
   419fc:	add    %ecx,%eax
   419fe:	test   %eax,%eax
   41a00:	jg     407fa <__GI_____strtod_l_internal+0xc6a>
   41a06:	lea    0x14ee03(%rip),%rcx        # 190810 <__PRETTY_FUNCTION__.11243>
   41a0d:	lea    0x147f17(%rip),%rsi        # 18992b <_nl_POSIX_name+0x146>
   41a14:	lea    0x147eb5(%rip),%rdi        # 1898d0 <_nl_POSIX_name+0xeb>
   41a1b:	mov    $0x559,%edx
   41a20:	callq  2dea0 <__assert_fail>
   41a25:	nopl   (%rax)
   41a28:	mov    0x8(%rsp),%esi
   41a2c:	mov    0x37e435(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   41a33:	movsd  0x14fd0d(%rip),%xmm0        # 191748 <conversion_rate+0x30>
   41a3b:	test   %esi,%esi
   41a3d:	movl   $0x22,%fs:(%rax)
   41a44:	je     41d1e <__GI_____strtod_l_internal+0x218e>
   41a4a:	mulsd  0x14fd0e(%rip),%xmm0        # 191760 <conversion_rate+0x48>
   41a52:	jmpq   3fd3c <__GI_____strtod_l_internal+0x1ac>
   41a57:	cmp    %r13,%r14
   41a5a:	jne    41e4b <__GI_____strtod_l_internal+0x22bb>
   41a60:	lea    -0x1(%rsi),%ebx
   41a63:	mov    %ebx,%edx
   41a65:	sar    $0x1f,%edx
   41a68:	shr    $0x1a,%edx
   41a6b:	lea    (%rbx,%rdx,1),%eax
   41a6e:	and    $0x3f,%eax
   41a71:	sub    %edx,%eax
   41a73:	cmp    $0x34,%eax
   41a76:	je     42018 <__GI_____strtod_l_internal+0x2488>
   41a7c:	mov    $0x1,%r13d
   41a82:	mov    $0x34,%ecx
   41a87:	lea    0x60(%rsp),%r10
   41a8c:	sub    %eax,%ecx
   41a8e:	mov    %r13,%rax
   41a91:	mov    0x10(%rsp),%rsi
   41a96:	sub    %r12,%rax
   41a99:	mov    %r12,%rdx
   41a9c:	mov    %r10,(%rsp)
   41aa0:	lea    (%r10,%rax,8),%rdi
   41aa4:	callq  48f00 <__mpn_lshift>
   41aa9:	sub    0x70(%rsp),%r13
   41aae:	mov    (%rsp),%r10
   41ab2:	test   %r13,%r13
   41ab5:	jle    41ac0 <__GI_____strtod_l_internal+0x1f30>
   41ab7:	movq   $0x0,0x60(%rsp)
   41ac0:	mov    0x8(%rsp),%edx
   41ac4:	movslq %ebx,%rsi
   41ac7:	xor    %r9d,%r9d
   41aca:	xor    %r8d,%r8d
   41acd:	xor    %ecx,%ecx
   41acf:	mov    %r10,%rdi
   41ad2:	callq  3f6e0 <round_and_return>
   41ad7:	jmpq   3fd3c <__GI_____strtod_l_internal+0x1ac>
   41adc:	jne    420b4 <__GI_____strtod_l_internal+0x2524>
   41ae2:	lea    -0x1(%r12),%eax
   41ae7:	test   %r12d,%r12d
   41aea:	mov    %eax,0x30(%rsp)
   41aee:	jle    41b1e <__GI_____strtod_l_internal+0x1f8e>
   41af0:	cltq   
   41af2:	mov    0x10(%rsp),%rcx
   41af7:	lea    0x8(,%rax,8),%rdx
   41aff:	movslq %r12d,%rax
   41b02:	shl    $0x3,%rax
   41b06:	lea    0x8(%rax),%rdi
   41b0a:	mov    %rax,%rsi
   41b0d:	sub    %rdx,%rsi
   41b10:	sub    %rdx,%rdi
   41b13:	add    %rcx,%rsi
   41b16:	add    %rcx,%rdi
   41b19:	callq  909a0 <memcpy@GLIBC_2.2.5>
   41b1e:	movq   $0x0,0x80(%rsp)
   41b2a:	movq   $0x0,0x260(%rsp,%r12,8)
   41b36:	mov    0x80(%rsp,%r12,8),%r9
   41b3e:	jmpq   40da1 <__GI_____strtod_l_internal+0x1211>
   41b43:	cmp    $0xffffffffffffffff,%rcx
   41b47:	je     41e6a <__GI_____strtod_l_internal+0x22da>
   41b4d:	movabs $0x1ffffffffffffeff,%rax
   41b57:	cmp    %rax,%rcx
   41b5a:	ja     421d5 <__GI_____strtod_l_internal+0x2645>
   41b60:	lea    0x403(,%rcx,4),%rbp
   41b68:	jmpq   404e1 <__GI_____strtod_l_internal+0x951>
   41b6d:	mov    0x88(%rsp),%rbp
   41b75:	mov    0x80(%rsp),%r12
   41b7d:	mov    (%rsp),%ecx
   41b80:	mov    %r8,%r11
   41b83:	xor    %r9d,%r9d
   41b86:	mov    $0x40,%r10d
   41b8c:	neg    %r11
   41b8f:	nop
   41b90:	cmp    %rbp,%rdi
   41b93:	je     41c4d <__GI_____strtod_l_internal+0x20bd>
   41b99:	mov    %rbp,%rdx
   41b9c:	mov    %r12,%rax
   41b9f:	div    %rdi
   41ba2:	mov    %rax,%rbx
   41ba5:	mov    %rdx,%rbp
   41ba8:	mov    %r8,%rax
   41bab:	mul    %rbx
   41bae:	xchg   %ax,%ax
   41bb0:	cmp    %rbp,%rdx
   41bb3:	ja     41bbc <__GI_____strtod_l_internal+0x202c>
   41bb5:	jne    41bcc <__GI_____strtod_l_internal+0x203c>
   41bb7:	test   %rax,%rax
   41bba:	je     41bcc <__GI_____strtod_l_internal+0x203c>
   41bbc:	sub    $0x1,%rbx
   41bc0:	sub    %r8,%rax
   41bc3:	sbb    $0x0,%rdx
   41bc7:	add    %rdi,%rbp
   41bca:	jae    41bb0 <__GI_____strtod_l_internal+0x2020>
   41bcc:	mov    %r9,%r12
   41bcf:	sub    %rax,%r12
   41bd2:	sbb    %rdx,%rbp
   41bd5:	test   %ecx,%ecx
   41bd7:	jne    41c78 <__GI_____strtod_l_internal+0x20e8>
   41bdd:	test   %rbx,%rbx
   41be0:	je     41c39 <__GI_____strtod_l_internal+0x20a9>
   41be2:	bsr    %rbx,%rdx
   41be6:	mov    0x78(%rsp),%rsi
   41beb:	xor    $0x3f,%rdx
   41bef:	movslq %edx,%rax
   41bf2:	mov    %edx,%ecx
   41bf4:	sub    %rax,%rsi
   41bf7:	mov    %rsi,%rax
   41bfa:	mov    %rsi,0x78(%rsp)
   41bff:	mov    %r10d,%esi
   41c02:	sub    %edx,%esi
   41c04:	cmp    $0x35,%esi
   41c07:	jle    42052 <__GI_____strtod_l_internal+0x24c2>
   41c0d:	lea    0x35(%rcx),%edx
   41c10:	mov    %r10d,%ecx
   41c13:	mov    %rbx,%rdi
   41c16:	mov    $0x3f,%r8d
   41c1c:	sub    %edx,%ecx
   41c1e:	sub    %edx,%r8d
   41c21:	shr    %cl,%rdi
   41c24:	movslq %r8d,%r8
   41c27:	mov    %rdi,%rcx
   41c2a:	mov    %rcx,0x60(%rsp)
   41c2f:	lea    0x60(%rsp),%r10
   41c34:	jmpq   4146e <__GI_____strtod_l_internal+0x18de>
   41c39:	subq   $0x40,0x78(%rsp)
   41c3f:	movq   $0x0,0x60(%rsp)
   41c48:	jmpq   41b90 <__GI_____strtod_l_internal+0x2000>
   41c4d:	add    %rdi,%r12
   41c50:	mov    %r12,%rbp
   41c53:	jae    41ce0 <__GI_____strtod_l_internal+0x2150>
   41c59:	sub    %r8,%rbp
   41c5c:	mov    %r9,%r12
   41c5f:	add    %r8,%r12
   41c62:	adc    $0x0,%rbp
   41c66:	test   %ecx,%ecx
   41c68:	je     41cfd <__GI_____strtod_l_internal+0x216d>
   41c6e:	mov    $0xffffffffffffffff,%rbx
   41c75:	nopl   (%rax)
   41c78:	cmp    $0xfffffff6,%ecx
   41c7b:	jge    41c8a <__GI_____strtod_l_internal+0x20fa>
   41c7d:	mov    %rbx,0x60(%rsp)
   41c82:	add    $0x40,%ecx
   41c85:	jmpq   41b90 <__GI_____strtod_l_internal+0x2000>
   41c8a:	mov    $0x35,%r14d
   41c90:	lea    0x60(%rsp),%r10
   41c95:	sub    %ecx,%r14d
   41c98:	je     41cc8 <__GI_____strtod_l_internal+0x2138>
   41c9a:	mov    %r14d,%ecx
   41c9d:	mov    %r10,%rsi
   41ca0:	mov    %r10,%rdi
   41ca3:	mov    $0x1,%edx
   41ca8:	mov    %r10,(%rsp)
   41cac:	callq  48f00 <__mpn_lshift>
   41cb1:	mov    $0x40,%ecx
   41cb6:	mov    %rbx,%rax
   41cb9:	mov    (%rsp),%r10
   41cbd:	sub    %r14d,%ecx
   41cc0:	shr    %cl,%rax
   41cc3:	or     %rax,0x60(%rsp)
   41cc8:	mov    $0x3f,%r8d
   41cce:	mov    0x78(%rsp),%rax
   41cd3:	sub    %r14d,%r8d
   41cd6:	movslq %r8d,%r8
   41cd9:	jmpq   4146e <__GI_____strtod_l_internal+0x18de>
   41cde:	xchg   %ax,%ax
   41ce0:	xor    %eax,%eax
   41ce2:	test   %r8,%r8
   41ce5:	mov    %r8,%rdx
   41ce8:	setne  %al
   41ceb:	mov    $0xffffffffffffffff,%rbx
   41cf2:	sub    %rax,%rdx
   41cf5:	mov    %r11,%rax
   41cf8:	jmpq   41bb0 <__GI_____strtod_l_internal+0x2020>
   41cfd:	mov    0x78(%rsp),%rax
   41d02:	mov    $0xa,%r8d
   41d08:	movabs $0x1fffffffffffff,%rcx
   41d12:	mov    $0xffffffffffffffff,%rbx
   41d19:	jmpq   41c2a <__GI_____strtod_l_internal+0x209a>
   41d1e:	mulsd  %xmm0,%xmm0
   41d22:	jmpq   3fd3c <__GI_____strtod_l_internal+0x1ac>
   41d27:	movq   $0x1e,0x20(%rsp)
   41d30:	mov    $0x135,%ebp
   41d35:	jmpq   40504 <__GI_____strtod_l_internal+0x974>
   41d3a:	mov    0x8(%rsp),%ecx
   41d3e:	mov    0x37e123(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   41d45:	movsd  0x14fa03(%rip),%xmm0        # 191750 <conversion_rate+0x38>
   41d4d:	test   %ecx,%ecx
   41d4f:	movl   $0x22,%fs:(%rax)
   41d56:	je     41d1e <__GI_____strtod_l_internal+0x218e>
   41d58:	mulsd  0x14f9f8(%rip),%xmm0        # 191758 <conversion_rate+0x40>
   41d60:	jmpq   3fd3c <__GI_____strtod_l_internal+0x1ac>
   41d65:	mov    %r8,%rdx
   41d68:	sub    %rsi,%rdx
   41d6b:	jmp    41d94 <__GI_____strtod_l_internal+0x2204>
   41d6d:	nopl   (%rax)
   41d70:	cmp    $0xffffffffffffffff,%rcx
   41d74:	jne    41d8b <__GI_____strtod_l_internal+0x21fb>
   41d76:	cmp    $0x30,%bpl
   41d7a:	mov    %r12,%rax
   41d7d:	setne  %dil
   41d81:	sub    %rsi,%rax
   41d84:	test   %dil,%dil
   41d87:	cmovne %rax,%rcx
   41d8b:	add    $0x1,%r12
   41d8f:	movsbq (%r12),%rbp
   41d94:	lea    -0x30(%rbp),%eax
   41d97:	lea    (%r12,%rdx,1),%r14
   41d9b:	cmp    $0x9,%al
   41d9d:	ja     4045d <__GI_____strtod_l_internal+0x8cd>
   41da3:	jmp    41d70 <__GI_____strtod_l_internal+0x21e0>
   41da5:	mov    $0x1,%r9d
   41dab:	jmpq   412a6 <__GI_____strtod_l_internal+0x1716>
   41db0:	movslq %edx,%r8
   41db3:	sub    $0x1,%r8
   41db7:	cmp    %rax,%rdi
   41dba:	jg     41dd6 <__GI_____strtod_l_internal+0x2246>
   41dbc:	mov    0x80(%rsp,%rax,8),%rdi
   41dc4:	mov    %edx,%ecx
   41dc6:	shr    %cl,%rdi
   41dc9:	mov    %rax,%rcx
   41dcc:	mov    %rdi,0x60(%rsp)
   41dd1:	jmpq   417b5 <__GI_____strtod_l_internal+0x1c25>
   41dd6:	add    $0x1,%ecx
   41dd9:	mov    0x80(%rsp,%rax,8),%rbx
   41de1:	movslq %ecx,%rdi
   41de4:	mov    $0x40,%ecx
   41de9:	mov    0x80(%rsp,%rdi,8),%rdi
   41df1:	sub    %edx,%ecx
   41df3:	shl    %cl,%rdi
   41df6:	mov    %edx,%ecx
   41df8:	shr    %cl,%rbx
   41dfb:	mov    %rax,%rcx
   41dfe:	or     %rbx,%rdi
   41e01:	mov    %rdi,0x60(%rsp)
   41e06:	jmpq   417b5 <__GI_____strtod_l_internal+0x1c25>
   41e0b:	xor    %ebp,%ebp
   41e0d:	jmpq   41b7d <__GI_____strtod_l_internal+0x1fed>
   41e12:	mov    (%rsp),%rax
   41e16:	test   %rax,%rax
   41e19:	je     40397 <__GI_____strtod_l_internal+0x807>
   41e1f:	mov    %rdi,(%rax)
   41e22:	jmpq   40397 <__GI_____strtod_l_internal+0x807>
   41e27:	mov    %rdi,%rsi
   41e2a:	mov    0x20(%rsp),%rdi
   41e2f:	lea    0x0(,%r12,8),%rdx
   41e37:	callq  909a0 <memcpy@GLIBC_2.2.5>
   41e3c:	jmpq   40b2d <__GI_____strtod_l_internal+0xf9d>
   41e41:	mov    0x10(%rsp),%rdi
   41e46:	jmpq   41343 <__GI_____strtod_l_internal+0x17b3>
   41e4b:	lea    0x60(%rsp),%r10
   41e50:	mov    0x10(%rsp),%rsi
   41e55:	lea    0x0(,%r12,8),%rdx
   41e5d:	mov    %r10,%rdi
   41e60:	callq  909a0 <memcpy@GLIBC_2.2.5>
   41e65:	jmpq   407b2 <__GI_____strtod_l_internal+0xc22>
   41e6a:	movq   $0x66,0x20(%rsp)
   41e73:	mov    $0x403,%ebp
   41e78:	jmpq   40504 <__GI_____strtod_l_internal+0x974>
   41e7d:	lea    -0x1(%rbx),%rax
   41e81:	cmp    $0x10,%r11d
   41e85:	cmovne %r14,%rax
   41e89:	jmpq   40ac4 <__GI_____strtod_l_internal+0xf34>
   41e8e:	mov    %rdx,%rax
   41e91:	jmpq   4105c <__GI_____strtod_l_internal+0x14cc>
   41e96:	mov    %rbx,%rax
   41e99:	xor    %r14d,%r14d
   41e9c:	jmpq   4008a <__GI_____strtod_l_internal+0x4fa>
   41ea1:	lea    0x260(%rsp),%rsi
   41ea9:	lea    0x4(%rbx),%rdi
   41ead:	mov    $0x29,%edx
   41eb2:	callq  45150 <__strtod_nan>
   41eb7:	mov    0x260(%rsp),%rax
   41ebf:	cmpb   $0x29,(%rax)
   41ec2:	lea    0x1(%rax),%rdx
   41ec6:	cmove  %rdx,%rbp
   41eca:	jmpq   41116 <__GI_____strtod_l_internal+0x1586>
   41ecf:	sub    %rax,0x78(%rsp)
   41ed4:	jmpq   40c83 <__GI_____strtod_l_internal+0x10f3>
   41ed9:	sub    $0x40,%rcx
   41edd:	mov    %r12,%rbp
   41ee0:	xor    %r12d,%r12d
   41ee3:	mov    %rcx,0x78(%rsp)
   41ee8:	jmpq   41b7d <__GI_____strtod_l_internal+0x1fed>
   41eed:	sub    $0x1,%eax
   41ef0:	mov    0x10(%rsp),%rdi
   41ef5:	lea    -0x1(%r9),%esi
   41ef9:	movslq %eax,%rcx
   41efc:	mov    %rcx,%r11
   41eff:	sub    %rcx,%rdx
   41f02:	sub    %rsi,%r11
   41f05:	lea    (%rdi,%rcx,8),%rax
   41f09:	lea    -0x8(%rdi,%r11,8),%rsi
   41f0e:	xchg   %ax,%ax
   41f10:	mov    (%rax),%rcx
   41f13:	mov    %rcx,(%rax,%rdx,8)
   41f17:	sub    $0x8,%rax
   41f1b:	cmp    %rax,%rsi
   41f1e:	jne    41f10 <__GI_____strtod_l_internal+0x2380>
   41f20:	jmpq   40d66 <__GI_____strtod_l_internal+0x11d6>
   41f25:	mov    $0x35,%r14d
   41f2b:	sub    (%rsp),%r14d
   41f2f:	je     40c7b <__GI_____strtod_l_internal+0x10eb>
   41f35:	lea    0x60(%rsp),%r10
   41f3a:	mov    $0x1,%edx
   41f3f:	mov    %r14d,%ecx
   41f42:	mov    %r10,%rsi
   41f45:	mov    %r10,%rdi
   41f48:	callq  48f00 <__mpn_lshift>
   41f4d:	mov    0x70(%rsp),%rdx
   41f52:	jmpq   40c7b <__GI_____strtod_l_internal+0x10eb>
   41f57:	lea    0x14e8b2(%rip),%rcx        # 190810 <__PRETTY_FUNCTION__.11243>
   41f5e:	lea    0x1479c6(%rip),%rsi        # 18992b <_nl_POSIX_name+0x146>
   41f65:	lea    0x14b26c(%rip),%rdi        # 18d1d8 <__PRETTY_FUNCTION__.7436+0x128>
   41f6c:	mov    $0x396,%edx
   41f71:	callq  2dea0 <__assert_fail>
   41f76:	lea    0x14e893(%rip),%rcx        # 190810 <__PRETTY_FUNCTION__.11243>
   41f7d:	lea    0x1479a7(%rip),%rsi        # 18992b <_nl_POSIX_name+0x146>
   41f84:	lea    0x147970(%rip),%rdi        # 1898fb <_nl_POSIX_name+0x116>
   41f8b:	mov    $0x66b,%edx
   41f90:	callq  2dea0 <__assert_fail>
   41f95:	lea    0x14e874(%rip),%rcx        # 190810 <__PRETTY_FUNCTION__.11243>
   41f9c:	lea    0x147988(%rip),%rsi        # 18992b <_nl_POSIX_name+0x146>
   41fa3:	lea    0x14b13e(%rip),%rdi        # 18d0e8 <__PRETTY_FUNCTION__.7436+0x38>
   41faa:	mov    $0x36e,%edx
   41faf:	callq  2dea0 <__assert_fail>
   41fb4:	lea    0x14e855(%rip),%rcx        # 190810 <__PRETTY_FUNCTION__.11243>
   41fbb:	lea    0x147969(%rip),%rsi        # 18992b <_nl_POSIX_name+0x146>
   41fc2:	lea    0x1478e1(%rip),%rdi        # 1898aa <_nl_POSIX_name+0xc5>
   41fc9:	mov    $0x430,%edx
   41fce:	callq  2dea0 <__assert_fail>
   41fd3:	lea    0x14e836(%rip),%rcx        # 190810 <__PRETTY_FUNCTION__.11243>
   41fda:	lea    0x14794a(%rip),%rsi        # 18992b <_nl_POSIX_name+0x146>
   41fe1:	lea    0x1478cc(%rip),%rdi        # 1898b4 <_nl_POSIX_name+0xcf>
   41fe8:	mov    $0x53e,%edx
   41fed:	callq  2dea0 <__assert_fail>
   41ff2:	lea    0x14e817(%rip),%rcx        # 190810 <__PRETTY_FUNCTION__.11243>
   41ff9:	lea    0x14792b(%rip),%rsi        # 18992b <_nl_POSIX_name+0x146>
   42000:	lea    0x14b209(%rip),%rdi        # 18d210 <__PRETTY_FUNCTION__.7436+0x160>
   42007:	mov    $0x3a2,%edx
   4200c:	callq  2dea0 <__assert_fail>
   42011:	xor    %edx,%edx
   42013:	jmpq   417df <__GI_____strtod_l_internal+0x1c4f>
   42018:	lea    0x60(%rsp),%r10
   4201d:	mov    $0x1,%r13d
   42023:	mov    0x10(%rsp),%rsi
   42028:	sub    %r12,%r13
   4202b:	lea    0x0(,%r12,8),%rdx
   42033:	lea    (%r10,%r13,8),%rdi
   42037:	mov    %r10,(%rsp)
   4203b:	callq  909a0 <memcpy@GLIBC_2.2.5>
   42040:	test   %r13,%r13
   42043:	mov    (%rsp),%r10
   42047:	jle    41ac0 <__GI_____strtod_l_internal+0x1f30>
   4204d:	jmpq   41ab7 <__GI_____strtod_l_internal+0x1f27>
   42052:	mov    %esi,%ecx
   42054:	mov    %rbx,0x60(%rsp)
   42059:	jmpq   41b90 <__GI_____strtod_l_internal+0x2000>
   4205e:	cmpq   $0x0,(%rsp)
   42063:	je     40397 <__GI_____strtod_l_internal+0x807>
   42069:	xor    %ecx,%ecx
   4206b:	xor    %r8d,%r8d
   4206e:	xor    %r14d,%r14d
   42071:	jmpq   40387 <__GI_____strtod_l_internal+0x7f7>
   42076:	lea    0x14e793(%rip),%rcx        # 190810 <__PRETTY_FUNCTION__.11243>
   4207d:	lea    0x1478a7(%rip),%rsi        # 18992b <_nl_POSIX_name+0x146>
   42084:	lea    0x14b34d(%rip),%rdi        # 18d3d8 <__PRETTY_FUNCTION__.7436+0x328>
   4208b:	mov    $0x544,%edx
   42090:	callq  2dea0 <__assert_fail>
   42095:	lea    0x14e774(%rip),%rcx        # 190810 <__PRETTY_FUNCTION__.11243>
   4209c:	lea    0x147888(%rip),%rsi        # 18992b <_nl_POSIX_name+0x146>
   420a3:	lea    0x14b2e6(%rip),%rdi        # 18d390 <__PRETTY_FUNCTION__.7436+0x2e0>
   420aa:	mov    $0x534,%edx
   420af:	callq  2dea0 <__assert_fail>
   420b4:	lea    0x14e755(%rip),%rcx        # 190810 <__PRETTY_FUNCTION__.11243>
   420bb:	lea    0x147869(%rip),%rsi        # 18992b <_nl_POSIX_name+0x146>
   420c2:	lea    0x14783d(%rip),%rdi        # 189906 <_nl_POSIX_name+0x121>
   420c9:	mov    $0x690,%edx
   420ce:	callq  2dea0 <__assert_fail>
   420d3:	lea    0x14e736(%rip),%rcx        # 190810 <__PRETTY_FUNCTION__.11243>
   420da:	lea    0x14784a(%rip),%rsi        # 18992b <_nl_POSIX_name+0x146>
   420e1:	lea    0x14b040(%rip),%rdi        # 18d128 <__PRETTY_FUNCTION__.7436+0x78>
   420e8:	mov    $0x376,%edx
   420ed:	callq  2dea0 <__assert_fail>
   420f2:	lea    0x14e717(%rip),%rcx        # 190810 <__PRETTY_FUNCTION__.11243>
   420f9:	lea    0x14782b(%rip),%rsi        # 18992b <_nl_POSIX_name+0x146>
   42100:	lea    0x1477de(%rip),%rdi        # 1898e5 <_nl_POSIX_name+0x100>
   42107:	mov    $0x5bd,%edx
   4210c:	callq  2dea0 <__assert_fail>
   42111:	mov    %rax,0x60(%rsp)
   42116:	jmpq   41847 <__GI_____strtod_l_internal+0x1cb7>
   4211b:	mov    0x78(%rsp),%rsi
   42120:	xor    %ebx,%ebx
   42122:	lea    0x60(%rsp),%r10
   42127:	jmpq   40f2b <__GI_____strtod_l_internal+0x139b>
   4212c:	lea    0x14e6dd(%rip),%rcx        # 190810 <__PRETTY_FUNCTION__.11243>
   42133:	lea    0x1477f1(%rip),%rsi        # 18992b <_nl_POSIX_name+0x146>
   4213a:	lea    0x1477d8(%rip),%rdi        # 189919 <_nl_POSIX_name+0x134>
   42141:	mov    $0x6ba,%edx
   42146:	callq  2dea0 <__assert_fail>
   4214b:	lea    0x14e6be(%rip),%rcx        # 190810 <__PRETTY_FUNCTION__.11243>
   42152:	lea    0x1477d2(%rip),%rsi        # 18992b <_nl_POSIX_name+0x146>
   42159:	lea    0x14771b(%rip),%rdi        # 18987b <_nl_POSIX_name+0x96>
   42160:	mov    $0x23a,%edx
   42165:	callq  2dea0 <__assert_fail>
   4216a:	lea    0x14e69f(%rip),%rcx        # 190810 <__PRETTY_FUNCTION__.11243>
   42171:	lea    0x1477b3(%rip),%rsi        # 18992b <_nl_POSIX_name+0x146>
   42178:	lea    0x14af41(%rip),%rdi        # 18d0c0 <__PRETTY_FUNCTION__.7436+0x10>
   4217f:	mov    $0x34f,%edx
   42184:	callq  2dea0 <__assert_fail>
   42189:	mov    %ebp,%ecx
   4218b:	movq   $0x0,0x10(%rsp)
   42194:	mov    %r10,%rbx
   42197:	mov    $0x10,%r11d
   4219d:	jmpq   3fd88 <__GI_____strtod_l_internal+0x1f8>
   421a2:	movq   $0x0,0x10(%rsp)
   421ab:	mov    $0x10,%r11d
   421b1:	jmpq   3fc97 <__GI_____strtod_l_internal+0x107>
   421b6:	lea    0x14e653(%rip),%rcx        # 190810 <__PRETTY_FUNCTION__.11243>
   421bd:	lea    0x147767(%rip),%rsi        # 18992b <_nl_POSIX_name+0x146>
   421c4:	lea    0x14afcd(%rip),%rdi        # 18d198 <__PRETTY_FUNCTION__.7436+0xe8>
   421cb:	mov    $0x38e,%edx
   421d0:	callq  2dea0 <__assert_fail>
   421d5:	lea    0x14e634(%rip),%rcx        # 190810 <__PRETTY_FUNCTION__.11243>
   421dc:	lea    0x147748(%rip),%rsi        # 18992b <_nl_POSIX_name+0x146>
   421e3:	lea    0x14af76(%rip),%rdi        # 18d160 <__PRETTY_FUNCTION__.7436+0xb0>
   421ea:	mov    $0x382,%edx
   421ef:	callq  2dea0 <__assert_fail>
   421f4:	lea    0x14e615(%rip),%rcx        # 190810 <__PRETTY_FUNCTION__.11243>
   421fb:	lea    0x147729(%rip),%rsi        # 18992b <_nl_POSIX_name+0x146>
   42202:	lea    0x147690(%rip),%rdi        # 189899 <_nl_POSIX_name+0xb4>
   42209:	mov    $0x3e1,%edx
   4220e:	callq  2dea0 <__assert_fail>
   42213:	mov    %r10,0x78(%rsp)
   42218:	jmpq   40584 <__GI_____strtod_l_internal+0x9f4>
   4221d:	mov    %edi,(%rsp)
   42220:	mov    %r13,0x60(%rsp)
   42225:	jmpq   40df0 <__GI_____strtod_l_internal+0x1260>
   4222a:	lea    0x14e5df(%rip),%rcx        # 190810 <__PRETTY_FUNCTION__.11243>
   42231:	lea    0x1476f3(%rip),%rsi        # 18992b <_nl_POSIX_name+0x146>
   42238:	lea    0x14b0e1(%rip),%rdi        # 18d320 <__PRETTY_FUNCTION__.7436+0x270>
   4223f:	mov    $0x445,%edx
   42244:	callq  2dea0 <__assert_fail>
   42249:	lea    0x14e5c0(%rip),%rcx        # 190810 <__PRETTY_FUNCTION__.11243>
   42250:	lea    0x1476d4(%rip),%rsi        # 18992b <_nl_POSIX_name+0x146>
   42257:	lea    0x14b03a(%rip),%rdi        # 18d298 <__PRETTY_FUNCTION__.7436+0x1e8>
   4225e:	mov    $0x418,%edx
   42263:	callq  2dea0 <__assert_fail>
   42268:	lea    0x14e5a1(%rip),%rcx        # 190810 <__PRETTY_FUNCTION__.11243>
   4226f:	lea    0x1476b5(%rip),%rsi        # 18992b <_nl_POSIX_name+0x146>
   42276:	lea    0x14afcb(%rip),%rdi        # 18d248 <__PRETTY_FUNCTION__.7436+0x198>
   4227d:	mov    $0x414,%edx
   42282:	callq  2dea0 <__assert_fail>
   42287:	nopw   0x0(%rax,%rax,1)
