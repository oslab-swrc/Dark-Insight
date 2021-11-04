// TC_OUT
000000000003bb60 <strtold>:
   3bb60:	mov    0x388259(%rip),%rax        # 3c3dc0 <_IO_file_jumps+0x580>
   3bb67:	xor    %edx,%edx
   3bb69:	mov    %fs:(%rax),%rcx
   3bb6d:	jmpq   41ce0 <__strtod_l+0x7a0>
   3bb72:	nopw   %cs:0x0(%rax,%rax,1)
   3bb7c:	nopl   0x0(%rax)
   3bb80:	push   %r15
   3bb82:	push   %r14
   3bb84:	mov    %rcx,%r14
   3bb87:	push   %r13
   3bb89:	push   %r12
   3bb8b:	mov    %esi,%r12d
   3bb8e:	push   %rbp
   3bb8f:	push   %rbx
   3bb90:	sub    $0x18,%rsp
   3bb94:	test   %esi,%esi
   3bb96:	movq   $0x0,(%rcx)
   3bb9d:	mov    %r8,0x8(%rsp)
   3bba2:	mov    0x50(%rsp),%r8
   3bba7:	jle    3be1b <strtold+0x2bb>
   3bbad:	mov    %rdi,%rbp
   3bbb0:	mov    %rdx,%r15
   3bbb3:	mov    %r9,%r13
   3bbb6:	xor    %ebx,%ebx
   3bbb8:	xor    %ecx,%ecx
   3bbba:	nopw   0x0(%rax,%rax,1)
   3bbc0:	movzbl 0x0(%rbp),%edx
   3bbc4:	lea    -0x30(%rdx),%esi
   3bbc7:	movsbq %dl,%rax
   3bbcb:	cmp    $0x9,%sil
   3bbcf:	jbe    3bbe3 <strtold+0x83>
   3bbd1:	test   %r8,%r8
   3bbd4:	je     3bbdb <strtold+0x7b>
   3bbd6:	cmp    (%r8),%dl
   3bbd9:	je     3bc30 <strtold+0xd0>
   3bbdb:	add    %r13,%rbp
   3bbde:	movsbq 0x0(%rbp),%rax
   3bbe3:	lea    (%rbx,%rbx,4),%rdx
   3bbe7:	add    $0x1,%rbp
   3bbeb:	lea    -0x30(%rdx,%rdx,1),%rbx
   3bbf0:	add    %rax,%rbx
   3bbf3:	sub    $0x1,%r12d
   3bbf7:	lea    0x1(%rcx),%eax
   3bbfa:	je     3bd10 <strtold+0x1b0>
   3bc00:	cmp    $0x13,%eax
   3bc03:	je     3bc10 <strtold+0xb0>
   3bc05:	mov    %eax,%ecx
   3bc07:	jmp    3bbc0 <strtold+0x60>
   3bc09:	nopl   0x0(%rax)
   3bc10:	mov    (%r14),%rdx
   3bc13:	test   %rdx,%rdx
   3bc16:	jne    3bc70 <strtold+0x110>
   3bc18:	xor    %al,%al
   3bc1a:	mov    %rbx,(%r15)
   3bc1d:	movq   $0x1,(%r14)
   3bc24:	xor    %ebx,%ebx
   3bc26:	mov    %eax,%ecx
   3bc28:	jmp    3bbc0 <strtold+0x60>
   3bc2a:	nopw   0x0(%rax,%rax,1)
   3bc30:	movzbl 0x1(%r8),%eax
   3bc35:	test   %al,%al
   3bc37:	je     3bdea <strtold+0x28a>
   3bc3d:	cmp    %al,0x1(%rbp)
   3bc40:	jne    3bbdb <strtold+0x7b>
   3bc42:	mov    $0x2,%eax
   3bc47:	jmp    3bc5a <strtold+0xfa>
   3bc49:	nopl   0x0(%rax)
   3bc50:	add    $0x1,%rax
   3bc54:	cmp    %dl,-0x1(%rbp,%rax,1)
   3bc58:	jne    3bbdb <strtold+0x7b>
   3bc5a:	movzbl (%r8,%rax,1),%edx
   3bc5f:	test   %dl,%dl
   3bc61:	jne    3bc50 <strtold+0xf0>
   3bc63:	add    %rax,%rbp
   3bc66:	movsbq 0x0(%rbp),%rax
   3bc6b:	jmpq   3bbe3 <strtold+0x83>
   3bc70:	mov    %r15,%rsi
   3bc73:	movabs $0x8ac7230489e80000,%rcx
   3bc7d:	mov    %r15,%rdi
   3bc80:	mov    %r8,(%rsp)
   3bc84:	callq  47fd0 <swapcontext+0x1150>
   3bc89:	mov    (%r15),%rdx
   3bc8c:	mov    (%r14),%rsi
   3bc8f:	mov    (%rsp),%r8
   3bc93:	add    %rdx,%rbx
   3bc96:	cmp    %rbx,%rdx
   3bc99:	mov    %rbx,(%r15)
   3bc9c:	jbe    3bce0 <strtold+0x180>
   3bc9e:	lea    0x8(%r15),%rcx
   3bca2:	jmp    3bcbd <strtold+0x15d>
   3bca4:	nopl   0x0(%rax)
   3bca8:	add    $0x8,%rcx
   3bcac:	mov    -0x8(%rcx),%rdi
   3bcb0:	lea    0x1(%rdi),%rdx
   3bcb4:	test   %rdx,%rdx
   3bcb7:	mov    %rdx,-0x8(%rcx)
   3bcbb:	jne    3bce0 <strtold+0x180>
   3bcbd:	sub    $0x1,%rsi
   3bcc1:	jne    3bca8 <strtold+0x148>
   3bcc3:	mov    $0x1,%edx
   3bcc8:	add    %rdx,%rax
   3bccb:	jne    3bce7 <strtold+0x187>
   3bccd:	nopl   (%rax)
   3bcd0:	xor    %eax,%eax
   3bcd2:	xor    %ebx,%ebx
   3bcd4:	mov    %eax,%ecx
   3bcd6:	jmpq   3bbc0 <strtold+0x60>
   3bcdb:	nopl   0x0(%rax,%rax,1)
   3bce0:	xor    %edx,%edx
   3bce2:	add    %rdx,%rax
   3bce5:	je     3bcd0 <strtold+0x170>
   3bce7:	mov    (%r14),%rdx
   3bcea:	cmp    $0x9,%rdx
   3bcee:	jg     3be3a <strtold+0x2da>
   3bcf4:	mov    %rax,(%r15,%rdx,8)
   3bcf8:	xor    %eax,%eax
   3bcfa:	addq   $0x1,(%r14)
   3bcfe:	xor    %ebx,%ebx
   3bd00:	mov    %eax,%ecx
   3bd02:	jmpq   3bbc0 <strtold+0x60>
   3bd07:	nopw   0x0(%rax,%rax,1)
   3bd10:	mov    0x8(%rsp),%rdi
   3bd15:	mov    (%rdi),%rsi
   3bd18:	test   %rsi,%rsi
   3bd1b:	jle    3bd2c <strtold+0x1cc>
   3bd1d:	mov    $0x12,%edx
   3bd22:	sub    %ecx,%edx
   3bd24:	movslq %edx,%rdx
   3bd27:	cmp    %rdx,%rsi
   3bd2a:	jle    3bd60 <strtold+0x200>
   3bd2c:	lea    0x145ecd(%rip),%rdx        # 181c00 <__libc_thread_freeres+0xdce0>
   3bd33:	cltq   
   3bd35:	mov    (%rdx,%rax,8),%rcx
   3bd39:	mov    (%r14),%rdx
   3bd3c:	test   %rdx,%rdx
   3bd3f:	jne    3bd84 <strtold+0x224>
   3bd41:	mov    %rbx,(%r15)
   3bd44:	movq   $0x1,(%r14)
   3bd4b:	add    $0x18,%rsp
   3bd4f:	mov    %rbp,%rax
   3bd52:	pop    %rbx
   3bd53:	pop    %rbp
   3bd54:	pop    %r12
   3bd56:	pop    %r13
   3bd58:	pop    %r14
   3bd5a:	pop    %r15
   3bd5c:	retq   
   3bd5d:	nopl   (%rax)
   3bd60:	lea    0x145e99(%rip),%rdx        # 181c00 <__libc_thread_freeres+0xdce0>
   3bd67:	cltq   
   3bd69:	movq   $0x0,(%rdi)
   3bd70:	add    %rsi,%rax
   3bd73:	imul   (%rdx,%rsi,8),%rbx
   3bd78:	mov    (%rdx,%rax,8),%rcx
   3bd7c:	mov    (%r14),%rdx
   3bd7f:	test   %rdx,%rdx
   3bd82:	je     3bd41 <strtold+0x1e1>
   3bd84:	mov    %r15,%rsi
   3bd87:	mov    %r15,%rdi
   3bd8a:	callq  47fd0 <swapcontext+0x1150>
   3bd8f:	mov    (%r15),%rdx
   3bd92:	mov    (%r14),%rsi
   3bd95:	add    %rdx,%rbx
   3bd98:	cmp    %rbx,%rdx
   3bd9b:	mov    %rbx,(%r15)
   3bd9e:	ja     3bdbd <strtold+0x25d>
   3bda0:	xor    %edx,%edx
   3bda2:	add    %rdx,%rax
   3bda5:	je     3bd4b <strtold+0x1eb>
   3bda7:	mov    (%r14),%rdx
   3bdaa:	cmp    $0x9,%rdx
   3bdae:	jg     3bdfc <strtold+0x29c>
   3bdb0:	lea    0x1(%rdx),%rcx
   3bdb4:	mov    %rcx,(%r14)
   3bdb7:	mov    %rax,(%r15,%rdx,8)
   3bdbb:	jmp    3bd4b <strtold+0x1eb>
   3bdbd:	lea    0x8(%r15),%rcx
   3bdc1:	jmp    3bddd <strtold+0x27d>
   3bdc3:	nopl   0x0(%rax,%rax,1)
   3bdc8:	add    $0x8,%rcx
   3bdcc:	mov    -0x8(%rcx),%rdi
   3bdd0:	lea    0x1(%rdi),%rdx
   3bdd4:	test   %rdx,%rdx
   3bdd7:	mov    %rdx,-0x8(%rcx)
   3bddb:	jne    3bda0 <strtold+0x240>
   3bddd:	sub    $0x1,%rsi
   3bde1:	jne    3bdc8 <strtold+0x268>
   3bde3:	mov    $0x1,%edx
   3bde8:	jmp    3bda2 <strtold+0x242>
   3bdea:	mov    $0x1,%eax
   3bdef:	add    %rax,%rbp
   3bdf2:	movsbq 0x0(%rbp),%rax
   3bdf7:	jmpq   3bbe3 <strtold+0x83>
   3bdfc:	lea    0x1505b7(%rip),%rcx        # 18c3ba <_libc_intl_domainname+0x191>
   3be03:	lea    0x1505c5(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3be0a:	lea    0x1542ef(%rip),%rdi        # 190100 <_libc_intl_domainname+0x3ed7>
   3be11:	mov    $0x1b7,%edx
   3be16:	callq  2e0b0 <__assert_fail>
   3be1b:	lea    0x150598(%rip),%rcx        # 18c3ba <_libc_intl_domainname+0x191>
   3be22:	lea    0x1505a6(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3be29:	lea    0x1504bb(%rip),%rdi        # 18c2eb <_libc_intl_domainname+0xc2>
   3be30:	mov    $0x16e,%edx
   3be35:	callq  2e0b0 <__assert_fail>
   3be3a:	lea    0x150579(%rip),%rcx        # 18c3ba <_libc_intl_domainname+0x191>
   3be41:	lea    0x150587(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3be48:	lea    0x1542b1(%rip),%rdi        # 190100 <_libc_intl_domainname+0x3ed7>
   3be4f:	mov    $0x17f,%edx
   3be54:	callq  2e0b0 <__assert_fail>
   3be59:	nopl   0x0(%rax)
   3be60:	push   %r15
   3be62:	push   %r14
   3be64:	push   %r13
   3be66:	push   %r12
   3be68:	mov    %rcx,%r13
   3be6b:	push   %rbp
   3be6c:	push   %rbx
   3be6d:	mov    %rdi,%r12
   3be70:	mov    %rsi,%rbx
   3be73:	mov    %edx,%ebp
   3be75:	sub    $0x28,%rsp
   3be79:	fnstcw 0x1c(%rsp)
   3be7d:	movzwl 0x1c(%rsp),%eax
   3be82:	and    $0xc00,%ax
   3be86:	cmp    $0x400,%ax
   3be8a:	je     3bf78 <strtold+0x418>
   3be90:	jbe    3bf60 <strtold+0x400>
   3be96:	cmp    $0x800,%ax
   3be9a:	je     3bef8 <strtold+0x398>
   3be9c:	cmp    $0xc00,%ax
   3bea0:	mov    $0xc00,%r14d
   3bea6:	jne    3bf6c <strtold+0x40c>
   3beac:	cmp    $0xffffffffffffff82,%rbx
   3beb0:	jge    3bf04 <strtold+0x3a4>
   3beb2:	cmp    $0xffffffffffffff6a,%rbx
   3beb9:	jge    3bf88 <strtold+0x428>
   3bebf:	mov    0x387fa2(%rip),%rax        # 3c3e68 <_IO_file_jumps+0x628>
   3bec6:	test   %ebp,%ebp
   3bec8:	movl   $0x22,%fs:(%rax)
   3becf:	je     3c040 <strtold+0x4e0>
   3bed5:	movss  0x159d73(%rip),%xmm0        # 195c50 <in6addr_loopback+0xbc0>
   3bedd:	mulss  0x159d67(%rip),%xmm0        # 195c4c <in6addr_loopback+0xbbc>
   3bee5:	add    $0x28,%rsp
   3bee9:	pop    %rbx
   3beea:	pop    %rbp
   3beeb:	pop    %r12
   3beed:	pop    %r13
   3beef:	pop    %r14
   3bef1:	pop    %r15
   3bef3:	retq   
   3bef4:	nopl   0x0(%rax)
   3bef8:	cmp    $0xffffffffffffff82,%rbx
   3befc:	mov    $0x800,%r14d
   3bf02:	jl     3beb2 <strtold+0x352>
   3bf04:	cmp    $0x80,%rbx
   3bf0b:	jle    3c060 <strtold+0x500>
   3bf11:	mov    0x387f50(%rip),%rax        # 3c3e68 <_IO_file_jumps+0x628>
   3bf18:	test   %ebp,%ebp
   3bf1a:	movl   $0x22,%fs:(%rax)
   3bf21:	jne    3bf40 <strtold+0x3e0>
   3bf23:	movss  0x159d29(%rip),%xmm0        # 195c54 <in6addr_loopback+0xbc4>
   3bf2b:	mulss  %xmm0,%xmm0
   3bf2f:	add    $0x28,%rsp
   3bf33:	pop    %rbx
   3bf34:	pop    %rbp
   3bf35:	pop    %r12
   3bf37:	pop    %r13
   3bf39:	pop    %r14
   3bf3b:	pop    %r15
   3bf3d:	retq   
   3bf3e:	xchg   %ax,%ax
   3bf40:	movss  0x159d10(%rip),%xmm0        # 195c58 <in6addr_loopback+0xbc8>
   3bf48:	mulss  0x159d04(%rip),%xmm0        # 195c54 <in6addr_loopback+0xbc4>
   3bf50:	add    $0x28,%rsp
   3bf54:	pop    %rbx
   3bf55:	pop    %rbp
   3bf56:	pop    %r12
   3bf58:	pop    %r13
   3bf5a:	pop    %r14
   3bf5c:	pop    %r15
   3bf5e:	retq   
   3bf5f:	nop
   3bf60:	xor    %r14d,%r14d
   3bf63:	test   %ax,%ax
   3bf66:	je     3beac <strtold+0x34c>
   3bf6c:	callq  36d60 <abort>
   3bf71:	nopl   0x0(%rax)
   3bf78:	mov    $0x400,%r14d
   3bf7e:	jmpq   3beac <strtold+0x34c>
   3bf83:	nopl   0x0(%rax,%rax,1)
   3bf88:	mov    $0x1,%eax
   3bf8d:	mov    %r8d,%ecx
   3bf90:	mov    $0xffffffffffffff82,%rdx
   3bf97:	shl    %cl,%rax
   3bf9a:	sub    %rbx,%rdx
   3bf9d:	sub    $0x1,%rax
   3bfa1:	test   %r13,%rax
   3bfa4:	setne  %al
   3bfa7:	movzbl %al,%eax
   3bfaa:	or     %eax,%r9d
   3bfad:	cmp    $0x18,%rdx
   3bfb1:	je     3c1e0 <strtold+0x680>
   3bfb7:	cmp    $0x1,%rdx
   3bfbb:	je     3c150 <strtold+0x5f0>
   3bfc1:	mov    %edx,%ecx
   3bfc3:	mov    %r12,%rdi
   3bfc6:	mov    $0x1,%edx
   3bfcb:	mov    %r12,%rsi
   3bfce:	mov    %r9d,0xc(%rsp)
   3bfd3:	mov    (%r12),%r13
   3bfd7:	callq  47a50 <swapcontext+0xbd0>
   3bfdc:	mov    (%r12),%rdx
   3bfe0:	mov    0xc(%rsp),%r9d
   3bfe5:	mov    $0xffffffffffffff81,%rdi
   3bfec:	sub    %ebx,%edi
   3bfee:	mov    %edx,%r8d
   3bff1:	and    $0x1,%r8d
   3bff5:	mov    %r13,%rax
   3bff8:	mov    %edi,%ecx
   3bffa:	shr    %cl,%rax
   3bffd:	and    $0x1,%eax
   3c000:	jne    3c200 <strtold+0x6a0>
   3c006:	test   %r9d,%r9d
   3c009:	jne    3c200 <strtold+0x6a0>
   3c00f:	mov    $0x1,%esi
   3c014:	shl    %cl,%rsi
   3c017:	sub    $0x1,%rsi
   3c01b:	test   %r13,%rsi
   3c01e:	jne    3c200 <strtold+0x6a0>
   3c024:	test   %ebp,%ebp
   3c026:	setne  %r15b
   3c02a:	xor    %eax,%eax
   3c02c:	nopl   0x0(%rax)
   3c030:	mov    $0xffffffffffffff81,%rbx
   3c037:	jmp    3c080 <strtold+0x520>
   3c039:	nopl   0x0(%rax)
   3c040:	movss  0x159c04(%rip),%xmm0        # 195c4c <in6addr_loopback+0xbbc>
   3c048:	add    $0x28,%rsp
   3c04c:	pop    %rbx
   3c04d:	mulss  %xmm0,%xmm0
   3c051:	pop    %rbp
   3c052:	pop    %r12
   3c054:	pop    %r13
   3c056:	pop    %r14
   3c058:	pop    %r15
   3c05a:	retq   
   3c05b:	nopl   0x0(%rax,%rax,1)
   3c060:	mov    (%r12),%rdx
   3c064:	test   %ebp,%ebp
   3c066:	mov    %r8d,%ecx
   3c069:	mov    %r13,%rax
   3c06c:	setne  %r15b
   3c070:	mov    %r8d,%edi
   3c073:	shr    %cl,%rax
   3c076:	mov    %edx,%r8d
   3c079:	and    $0x1,%eax
   3c07c:	and    $0x1,%r8d
   3c080:	test   %r9d,%r9d
   3c083:	mov    $0x1,%ecx
   3c088:	jne    3c09e <strtold+0x53e>
   3c08a:	mov    %edi,%ecx
   3c08c:	mov    $0x1,%esi
   3c091:	shl    %cl,%rsi
   3c094:	sub    $0x1,%rsi
   3c098:	test   %r13,%rsi
   3c09b:	setne  %cl
   3c09e:	mov    %eax,%esi
   3c0a0:	and    $0x1,%esi
   3c0a3:	cmp    $0x400,%r14d
   3c0aa:	je     3c140 <strtold+0x5e0>
   3c0b0:	jle    3c0e0 <strtold+0x580>
   3c0b2:	cmp    $0x800,%r14d
   3c0b9:	je     3c100 <strtold+0x5a0>
   3c0bb:	cmp    $0xc00,%r14d
   3c0c2:	jne    3bf6c <strtold+0x40c>
   3c0c8:	mov    %ebx,%esi
   3c0ca:	mov    %ebp,%edx
   3c0cc:	mov    %r12,%rdi
   3c0cf:	callq  491a0 <swapcontext+0x2320>
   3c0d4:	jmpq   3bf2f <strtold+0x3cf>
   3c0d9:	nopl   0x0(%rax)
   3c0e0:	test   %r14d,%r14d
   3c0e3:	jne    3bf6c <strtold+0x40c>
   3c0e9:	test   %rax,%rax
   3c0ec:	je     3c0c8 <strtold+0x568>
   3c0ee:	or     %r8d,%ecx
   3c0f1:	mov    %ecx,%r15d
   3c0f4:	jmp    3c10a <strtold+0x5aa>
   3c0f6:	nopw   %cs:0x0(%rax,%rax,1)
   3c100:	test   %r15b,%r15b
   3c103:	jne    3c0c8 <strtold+0x568>
   3c105:	or     %esi,%ecx
   3c107:	mov    %ecx,%r15d
   3c10a:	test   %r15b,%r15b
   3c10d:	je     3c0c8 <strtold+0x568>
   3c10f:	add    $0x1,%rdx
   3c113:	test   $0x1000000,%edx
   3c119:	mov    %rdx,(%r12)
   3c11d:	jne    3c238 <strtold+0x6d8>
   3c123:	cmp    $0xffffffffffffff81,%rbx
   3c127:	jne    3c0c8 <strtold+0x568>
   3c129:	and    $0x800000,%edx
   3c12f:	cmp    $0x1,%rdx
   3c133:	sbb    %esi,%esi
   3c135:	sub    $0x7e,%esi
   3c138:	jmp    3c0ca <strtold+0x56a>
   3c13a:	nopw   0x0(%rax,%rax,1)
   3c140:	test   %r15b,%r15b
   3c143:	je     3c0c8 <strtold+0x568>
   3c145:	jmp    3c105 <strtold+0x5a5>
   3c147:	nopw   0x0(%rax,%rax,1)
   3c150:	test   %r9d,%r9d
   3c153:	mov    %r8d,%ecx
   3c156:	setne  %dl
   3c159:	shr    %cl,%r13
   3c15c:	mov    %r13,%rax
   3c15f:	mov    (%r12),%r13
   3c163:	and    $0x1,%eax
   3c166:	mov    %eax,%ecx
   3c168:	and    $0x1,%ecx
   3c16b:	test   %ebp,%ebp
   3c16d:	setne  %r15b
   3c171:	cmp    $0x400,%r14d
   3c178:	je     3c2f7 <strtold+0x797>
   3c17e:	jle    3c270 <strtold+0x710>
   3c184:	cmp    $0x800,%r14d
   3c18b:	je     3c2ea <strtold+0x78a>
   3c191:	cmp    $0xc00,%r14d
   3c198:	jne    3bf6c <strtold+0x40c>
   3c19e:	mov    $0xffffffffffffff81,%rax
   3c1a5:	mov    $0x1,%ecx
   3c1aa:	mov    $0x1,%edx
   3c1af:	sub    %rbx,%rax
   3c1b2:	mov    %r12,%rsi
   3c1b5:	mov    %r12,%rdi
   3c1b8:	mov    %r9d,0xc(%rsp)
   3c1bd:	mov    %rax,%rbx
   3c1c0:	callq  47a50 <swapcontext+0xbd0>
   3c1c5:	mov    0xc(%rsp),%r9d
   3c1ca:	mov    (%r12),%rdx
   3c1ce:	mov    %ebx,%edi
   3c1d0:	mov    %edx,%r8d
   3c1d3:	and    $0x1,%r8d
   3c1d7:	jmpq   3bff5 <strtold+0x495>
   3c1dc:	nopl   0x0(%rax)
   3c1e0:	mov    (%r12),%r13
   3c1e4:	xor    %r8d,%r8d
   3c1e7:	movq   $0x0,(%r12)
   3c1ef:	xor    %dl,%dl
   3c1f1:	mov    $0x17,%edi
   3c1f6:	jmpq   3bff5 <strtold+0x495>
   3c1fb:	nopl   0x0(%rax,%rax,1)
   3c200:	movss  0x159a44(%rip),%xmm0        # 195c4c <in6addr_loopback+0xbbc>
   3c208:	mov    0x387c59(%rip),%rcx        # 3c3e68 <_IO_file_jumps+0x628>
   3c20f:	mulss  %xmm0,%xmm0
   3c213:	test   %ebp,%ebp
   3c215:	setne  %r15b
   3c219:	movl   $0x22,%fs:(%rcx)
   3c220:	movss  %xmm0,0x1c(%rsp)
   3c226:	movss  0x1c(%rsp),%xmm0
   3c22c:	jmpq   3c030 <strtold+0x4d0>
   3c231:	nopl   0x0(%rax)
   3c238:	add    $0x1,%rbx
   3c23c:	mov    $0x1,%ecx
   3c241:	mov    $0x1,%edx
   3c246:	mov    %r12,%rsi
   3c249:	mov    %r12,%rdi
   3c24c:	callq  47a50 <swapcontext+0xbd0>
   3c251:	orq    $0x800000,(%r12)
   3c259:	cmp    $0x81,%rbx
   3c260:	je     3bf11 <strtold+0x3b1>
   3c266:	jmpq   3c0c8 <strtold+0x568>
   3c26b:	nopl   0x0(%rax,%rax,1)
   3c270:	test   %r14d,%r14d
   3c273:	jne    3bf6c <strtold+0x40c>
   3c279:	test   %rax,%rax
   3c27c:	je     3c19e <strtold+0x63e>
   3c282:	mov    %r13d,%eax
   3c285:	and    $0x1,%eax
   3c288:	or     %eax,%edx
   3c28a:	test   %dl,%dl
   3c28c:	je     3c19e <strtold+0x63e>
   3c292:	mov    $0xffffffffffffff81,%rax
   3c299:	mov    $0x1,%ecx
   3c29e:	mov    $0x1,%edx
   3c2a3:	sub    %rbx,%rax
   3c2a6:	mov    %r12,%rsi
   3c2a9:	mov    %r12,%rdi
   3c2ac:	mov    %r9d,0xc(%rsp)
   3c2b1:	mov    %rax,%rbx
   3c2b4:	callq  47a50 <swapcontext+0xbd0>
   3c2b9:	lea    0x1(%r13),%rax
   3c2bd:	mov    0xc(%rsp),%r9d
   3c2c2:	test   $0x1000000,%eax
   3c2c7:	je     3c1ca <strtold+0x66a>
   3c2cd:	mov    (%r12),%rdx
   3c2d1:	mov    %r13,%rax
   3c2d4:	mov    %ebx,%ecx
   3c2d6:	shr    %cl,%rax
   3c2d9:	mov    %ebx,%edi
   3c2db:	and    $0x1,%eax
   3c2de:	mov    %edx,%r8d
   3c2e1:	and    $0x1,%r8d
   3c2e5:	jmpq   3c030 <strtold+0x4d0>
   3c2ea:	test   %r15b,%r15b
   3c2ed:	jne    3c19e <strtold+0x63e>
   3c2f3:	or     %ecx,%edx
   3c2f5:	jmp    3c28a <strtold+0x72a>
   3c2f7:	test   %r15b,%r15b
   3c2fa:	je     3c19e <strtold+0x63e>
   3c300:	or     %ecx,%edx
   3c302:	jmp    3c28a <strtold+0x72a>
   3c304:	xchg   %ax,%ax
   3c306:	nopw   %cs:0x0(%rax,%rax,1)
   3c310:	push   %r15
   3c312:	push   %r14
   3c314:	mov    %rcx,%r8
   3c317:	push   %r13
   3c319:	push   %r12
   3c31b:	push   %rbp
   3c31c:	push   %rbx
   3c31d:	sub    $0x148,%rsp
   3c324:	test   %edx,%edx
   3c326:	mov    %rsi,(%rsp)
   3c32a:	mov    %rdi,0x8(%rsp)
   3c32f:	mov    0x8(%rcx),%rsi
   3c333:	je     3c347 <strtold+0x7e7>
   3c335:	mov    0x50(%rsi),%rcx
   3c339:	movzbl (%rcx),%eax
   3c33c:	sub    $0x1,%eax
   3c33f:	cmp    $0x7d,%al
   3c341:	jbe    3c4e1 <strtold+0x981>
   3c347:	xor    %ecx,%ecx
   3c349:	xor    %ebx,%ebx
   3c34b:	mov    0x40(%rsi),%r14
   3c34f:	mov    %r8,0x18(%rsp)
   3c354:	mov    %rcx,0x10(%rsp)
   3c359:	mov    %r14,%rdi
   3c35c:	callq  8b6d0 <strlen>
   3c361:	test   %rax,%rax
   3c364:	mov    %rax,0x20(%rsp)
   3c369:	mov    0x10(%rsp),%rcx
   3c36e:	mov    0x18(%rsp),%r8
   3c373:	je     3e71c <strtold+0x2bbc>
   3c379:	mov    0x8(%rsp),%rax
   3c37e:	mov    0x68(%r8),%rsi
   3c382:	movq   $0x0,0x98(%rsp)
   3c38e:	sub    $0x1,%rax
   3c392:	nopw   0x0(%rax,%rax,1)
   3c398:	add    $0x1,%rax
   3c39c:	movsbq (%rax),%rdx
   3c3a0:	testb  $0x20,0x1(%rsi,%rdx,2)
   3c3a5:	mov    %rdx,%r12
   3c3a8:	jne    3c398 <strtold+0x838>
   3c3aa:	cmp    $0x2d,%dl
   3c3ad:	mov    %rax,%r10
   3c3b0:	je     3c87b <strtold+0xd1b>
   3c3b6:	cmp    $0x2b,%dl
   3c3b9:	movl   $0x0,0x10(%rsp)
   3c3c1:	je     3c8b0 <strtold+0xd50>
   3c3c7:	movzbl (%r14),%edi
   3c3cb:	test   %dil,%dil
   3c3ce:	je     3d0cb <strtold+0x156b>
   3c3d4:	cmp    %dil,%r12b
   3c3d7:	jne    3c498 <strtold+0x938>
   3c3dd:	mov    $0x1,%eax
   3c3e2:	jmp    3c3f7 <strtold+0x897>
   3c3e4:	nopl   0x0(%rax)
   3c3e8:	add    $0x1,%rax
   3c3ec:	cmp    -0x1(%r10,%rax,1),%dl
   3c3f1:	jne    3c498 <strtold+0x938>
   3c3f7:	movzbl (%r14,%rax,1),%edx
   3c3fc:	test   %dl,%dl
   3c3fe:	jne    3c3e8 <strtold+0x888>
   3c400:	movzbl (%r10,%rax,1),%eax
   3c405:	sub    $0x30,%eax
   3c408:	cmp    $0x9,%al
   3c40a:	ja     3c498 <strtold+0x938>
   3c410:	cmp    $0x30,%r12b
   3c414:	mov    0x70(%r8),%rsi
   3c418:	je     3ca7b <strtold+0xf1b>
   3c41e:	test   %rbx,%rbx
   3c421:	je     3ce42 <strtold+0x12e2>
   3c427:	mov    $0xa,%r9d
   3c42d:	cmp    $0x30,%r12b
   3c431:	movzbl (%rbx),%edx
   3c434:	mov    %r10,%r13
   3c437:	je     3c48f <strtold+0x92f>
   3c439:	nopl   0x0(%rax)
   3c440:	test   %dl,%dl
   3c442:	je     3c89d <strtold+0xd3d>
   3c448:	movzbl 0x0(%r13),%eax
   3c44d:	cmp    %dl,%al
   3c44f:	jne    3c8a9 <strtold+0xd49>
   3c455:	mov    $0x1,%eax
   3c45a:	jmp    3c46f <strtold+0x90f>
   3c45c:	nopl   0x0(%rax)
   3c460:	add    $0x1,%rax
   3c464:	cmp    -0x1(%r13,%rax,1),%r11b
   3c469:	jne    3c538 <strtold+0x9d8>
   3c46f:	movzbl (%rbx,%rax,1),%r11d
   3c474:	test   %r11b,%r11b
   3c477:	jne    3c460 <strtold+0x900>
   3c479:	sub    $0x1,%rax
   3c47d:	add    %r13,%rax
   3c480:	movsbq 0x1(%rax),%r12
   3c485:	lea    0x1(%rax),%r13
   3c489:	cmp    $0x30,%r12b
   3c48d:	jne    3c440 <strtold+0x8e0>
   3c48f:	mov    %r13,%rax
   3c492:	jmp    3c480 <strtold+0x920>
   3c494:	nopl   0x0(%rax)
   3c498:	lea    -0x30(%r12),%eax
   3c49d:	cmp    $0x9,%al
   3c49f:	jbe    3c410 <strtold+0x8b0>
   3c4a5:	mov    0x386884(%rip),%rax        # 3c2d30 <h_errlist+0x9b0>
   3c4ac:	mov    (%rax,%r12,4),%eax
   3c4b0:	cmp    $0x69,%al
   3c4b2:	je     3cdbf <strtold+0x125f>
   3c4b8:	cmp    $0x6e,%al
   3c4ba:	je     3d053 <strtold+0x14f3>
   3c4c0:	cmpq   $0x0,(%rsp)
   3c4c5:	jne    3c866 <strtold+0xd06>
   3c4cb:	pxor   %xmm0,%xmm0
   3c4cf:	add    $0x148,%rsp
   3c4d6:	pop    %rbx
   3c4d7:	pop    %rbp
   3c4d8:	pop    %r12
   3c4da:	pop    %r13
   3c4dc:	pop    %r14
   3c4de:	pop    %r15
   3c4e0:	retq   
   3c4e1:	mov    0x48(%rsi),%rbx
   3c4e5:	cmpb   $0x0,(%rbx)
   3c4e8:	jne    3c34b <strtold+0x7eb>
   3c4ee:	jmpq   3c347 <strtold+0x7e7>
   3c4f3:	test   %rbx,%rbx
   3c4f6:	lea    0x2(%r10),%rax
   3c4fa:	movsbq 0x2(%r10),%r12
   3c4ff:	jne    3d0d2 <strtold+0x1572>
   3c505:	cmp    $0x30,%r12b
   3c509:	jne    3e0af <strtold+0x254f>
   3c50f:	xor    %ecx,%ecx
   3c511:	mov    $0x10,%r9d
   3c517:	mov    %rax,%r13
   3c51a:	nopw   0x0(%rax,%rax,1)
   3c520:	add    $0x1,%r13
   3c524:	movsbq 0x0(%r13),%r12
   3c529:	cmp    $0x30,%r12b
   3c52d:	je     3c520 <strtold+0x9c0>
   3c52f:	mov    %r12d,%edx
   3c532:	mov    %rax,%r10
   3c535:	nopl   (%rax)
   3c538:	movsbq %r12b,%rax
   3c53c:	mov    (%rsi,%rax,4),%r15d
   3c540:	lea    -0x30(%r12),%eax
   3c545:	cmp    $0x9,%al
   3c547:	jbe    3c648 <strtold+0xae8>
   3c54d:	lea    -0x61(%r15),%eax
   3c551:	cmp    $0x10,%r9d
   3c555:	setne  0x18(%rsp)
   3c55a:	movzbl 0x18(%rsp),%r11d
   3c560:	cmp    $0x5,%al
   3c562:	ja     3c5eb <strtold+0xa8b>
   3c568:	test   %r11b,%r11b
   3c56b:	mov    %r13,%rbp
   3c56e:	jne    3c5eb <strtold+0xa8b>
   3c570:	lea    -0x30(%r12),%eax
   3c575:	xor    %r15d,%r15d
   3c578:	cmp    $0x9,%al
   3c57a:	jbe    3c5e2 <strtold+0xa82>
   3c57c:	nopl   0x0(%rax)
   3c580:	cmp    $0x10,%r9d
   3c584:	je     3c848 <strtold+0xce8>
   3c58a:	test   %rbx,%rbx
   3c58d:	je     3c650 <strtold+0xaf0>
   3c593:	movzbl (%rbx),%eax
   3c596:	test   %al,%al
   3c598:	je     3c891 <strtold+0xd31>
   3c59e:	cmp    %dl,%al
   3c5a0:	jne    3c650 <strtold+0xaf0>
   3c5a6:	mov    $0x1,%eax
   3c5ab:	jmp    3c5be <strtold+0xa5e>
   3c5ad:	nopl   (%rax)
   3c5b0:	add    $0x1,%rax
   3c5b4:	cmp    -0x1(%rbp,%rax,1),%dl
   3c5b8:	jne    3c650 <strtold+0xaf0>
   3c5be:	movzbl (%rbx,%rax,1),%edx
   3c5c2:	test   %dl,%dl
   3c5c4:	jne    3c5b0 <strtold+0xa50>
   3c5c6:	sub    $0x1,%rax
   3c5ca:	add    %rbp,%rax
   3c5cd:	movsbq 0x1(%rax),%r12
   3c5d2:	lea    0x1(%rax),%rbp
   3c5d6:	lea    -0x30(%r12),%eax
   3c5db:	mov    %r12d,%edx
   3c5de:	cmp    $0x9,%al
   3c5e0:	ja     3c580 <strtold+0xa20>
   3c5e2:	add    $0x1,%r15
   3c5e6:	mov    %rbp,%rax
   3c5e9:	jmp    3c5cd <strtold+0xa6d>
   3c5eb:	test   %dil,%dil
   3c5ee:	je     3c61a <strtold+0xaba>
   3c5f0:	cmp    %dl,%dil
   3c5f3:	jne    3cb39 <strtold+0xfd9>
   3c5f9:	xor    %eax,%eax
   3c5fb:	jmp    3c60f <strtold+0xaaf>
   3c5fd:	nopl   (%rax)
   3c600:	add    $0x1,%rax
   3c604:	cmp    0x0(%r13,%rax,1),%r11b
   3c609:	jne    3cb39 <strtold+0xfd9>
   3c60f:	movzbl 0x1(%r14,%rax,1),%r11d
   3c615:	test   %r11b,%r11b
   3c618:	jne    3c600 <strtold+0xaa0>
   3c61a:	cmp    %r13,%r10
   3c61d:	jne    3c648 <strtold+0xae8>
   3c61f:	cmp    $0x10,%r9d
   3c623:	jne    3c648 <strtold+0xae8>
   3c625:	mov    0x20(%rsp),%rax
   3c62a:	movsbq 0x0(%r13,%rax,1),%rax
   3c630:	lea    -0x30(%rax),%r11d
   3c634:	cmp    $0x9,%r11b
   3c638:	jbe    3c648 <strtold+0xae8>
   3c63a:	mov    (%rsi,%rax,4),%eax
   3c63d:	sub    $0x61,%eax
   3c640:	cmp    $0x5,%al
   3c642:	ja     3cb44 <strtold+0xfe4>
   3c648:	mov    %r13,%rbp
   3c64b:	jmpq   3c570 <strtold+0xa10>
   3c650:	cmp    %rbp,%r10
   3c653:	jae    3c65e <strtold+0xafe>
   3c655:	test   %rcx,%rcx
   3c658:	jne    3cac0 <strtold+0xf60>
   3c65e:	xor    %ecx,%ecx
   3c660:	test   %r15,%r15
   3c663:	sete   %cl
   3c666:	neg    %rcx
   3c669:	test   %dil,%dil
   3c66c:	je     3c698 <strtold+0xb38>
   3c66e:	cmp    %dil,0x0(%rbp)
   3c672:	jne    3ca73 <strtold+0xf13>
   3c678:	xor    %eax,%eax
   3c67a:	jmp    3c68e <strtold+0xb2e>
   3c67c:	nopl   0x0(%rax)
   3c680:	add    $0x1,%rax
   3c684:	cmp    0x0(%rbp,%rax,1),%dl
   3c688:	jne    3ca73 <strtold+0xf13>
   3c68e:	movzbl 0x1(%r14,%rax,1),%edx
   3c694:	test   %dl,%dl
   3c696:	jne    3c680 <strtold+0xb20>
   3c698:	mov    0x20(%rsp),%rax
   3c69d:	cmp    $0x10,%r9d
   3c6a1:	lea    0x0(%rbp,%rax,1),%rdi
   3c6a6:	movsbq (%rdi),%r12
   3c6aa:	mov    %rdi,%rbp
   3c6ad:	jne    3e3dd <strtold+0x287d>
   3c6b3:	lea    -0x30(%r12),%eax
   3c6b8:	mov    %r15,%rdx
   3c6bb:	mov    0x70(%r8),%rsi
   3c6bf:	sub    %rdi,%rdx
   3c6c2:	cmp    $0x9,%al
   3c6c4:	lea    0x0(%rbp,%rdx,1),%r10
   3c6c9:	ja     3c702 <strtold+0xba2>
   3c6cb:	nopl   0x0(%rax,%rax,1)
   3c6d0:	cmp    $0xffffffffffffffff,%rcx
   3c6d4:	jne    3c6eb <strtold+0xb8b>
   3c6d6:	cmp    $0x30,%r12b
   3c6da:	mov    %rbp,%rax
   3c6dd:	setne  %r10b
   3c6e1:	sub    %rdi,%rax
   3c6e4:	test   %r10b,%r10b
   3c6e7:	cmovne %rax,%rcx
   3c6eb:	add    $0x1,%rbp
   3c6ef:	movsbq 0x0(%rbp),%r12
   3c6f4:	lea    0x0(%rbp,%rdx,1),%r10
   3c6f9:	lea    -0x30(%r12),%eax
   3c6fe:	cmp    $0x9,%al
   3c700:	jbe    3c6d0 <strtold+0xb70>
   3c702:	movsbq %r12b,%rax
   3c706:	mov    (%rsi,%rax,4),%eax
   3c709:	sub    $0x61,%eax
   3c70c:	cmp    $0x5,%al
   3c70e:	jbe    3c6d0 <strtold+0xb70>
   3c710:	test   %r10,%r10
   3c713:	js     3ea1d <strtold+0x2ebd>
   3c719:	mov    0x70(%r8),%rax
   3c71d:	cmp    $0x10,%r9d
   3c721:	sete   0x8(%rsp)
   3c726:	movzbl 0x8(%rsp),%edi
   3c72b:	mov    (%rax,%r12,4),%eax
   3c72f:	cmp    $0x70,%al
   3c731:	jne    3c8be <strtold+0xd5e>
   3c737:	test   %dil,%dil
   3c73a:	je     3c8be <strtold+0xd5e>
   3c740:	movzbl 0x1(%rbp),%esi
   3c744:	cmp    $0x2d,%sil
   3c748:	je     3cba1 <strtold+0x1041>
   3c74e:	cmp    $0x2b,%sil
   3c752:	je     3caa1 <strtold+0xf41>
   3c758:	lea    0x1(%rbp),%rdi
   3c75c:	movl   $0x0,0x28(%rsp)
   3c764:	lea    -0x30(%rsi),%eax
   3c767:	cmp    $0x9,%al
   3c769:	ja     3c8cc <strtold+0xd6c>
   3c76f:	cmpb   $0x0,0x8(%rsp)
   3c774:	jne    3d1f0 <strtold+0x1690>
   3c77a:	mov    0x28(%rsp),%eax
   3c77e:	test   %eax,%eax
   3c780:	je     3ce53 <strtold+0x12f3>
   3c786:	movabs $0x7fffffffffffffc2,%rax
   3c790:	cmp    %rax,%r15
   3c793:	ja     3e7e6 <strtold+0x2c86>
   3c799:	lea    0x3d(%r15),%rax
   3c79d:	movabs $0x6666666666666667,%rdx
   3c7a7:	mov    %rax,%r11
   3c7aa:	mov    %rax,0x18(%rsp)
   3c7af:	imul   %rdx
   3c7b2:	mov    %r11,%rax
   3c7b5:	sar    $0x3f,%rax
   3c7b9:	sar    $0x2,%rdx
   3c7bd:	sub    %rax,%rdx
   3c7c0:	mov    %r11,%rax
   3c7c3:	mov    %rdx,%r12
   3c7c6:	movabs $0x6666666666666667,%rdx
   3c7d0:	mov    0x98(%rsp),%r11
   3c7d8:	imul   %rdx
   3c7db:	mov    0x18(%rsp),%rax
   3c7e0:	sar    $0x3f,%rax
   3c7e4:	sar    $0x2,%rdx
   3c7e8:	sub    %rax,%rdx
   3c7eb:	lea    (%rdx,%rdx,4),%rax
   3c7ef:	mov    0x18(%rsp),%rdx
   3c7f4:	add    %rax,%rax
   3c7f7:	sub    %rax,%rdx
   3c7fa:	jmp    3c81f <strtold+0xcbf>
   3c7fc:	nopl   0x0(%rax)
   3c800:	sub    $0x30,%eax
   3c803:	cltq   
   3c805:	lea    (%r11,%r11,4),%rsi
   3c809:	add    $0x1,%rdi
   3c80d:	lea    (%rax,%rsi,2),%r11
   3c811:	movzbl (%rdi),%esi
   3c814:	lea    -0x30(%rsi),%eax
   3c817:	cmp    $0x9,%al
   3c819:	ja     3cbb6 <strtold+0x1056>
   3c81f:	cmp    %r11,%r12
   3c822:	jl     3cbdc <strtold+0x107c>
   3c828:	movsbl %sil,%eax
   3c82c:	jne    3c800 <strtold+0xca0>
   3c82e:	sub    $0x30,%eax
   3c831:	cltq   
   3c833:	cmp    %rdx,%rax
   3c836:	jle    3c805 <strtold+0xca5>
   3c838:	mov    %r12,0x98(%rsp)
   3c840:	jmpq   3cbe4 <strtold+0x1084>
   3c845:	nopl   (%rax)
   3c848:	movsbq %r12b,%rax
   3c84c:	mov    (%rsi,%rax,4),%eax
   3c84f:	sub    $0x61,%eax
   3c852:	cmp    $0x5,%al
   3c854:	ja     3c58a <strtold+0xa2a>
   3c85a:	add    $0x1,%r15
   3c85e:	mov    %rbp,%rax
   3c861:	jmpq   3c5cd <strtold+0xa6d>
   3c866:	mov    (%rsp),%rax
   3c86a:	mov    0x8(%rsp),%rdi
   3c86f:	pxor   %xmm0,%xmm0
   3c873:	mov    %rdi,(%rax)
   3c876:	jmpq   3c4cf <strtold+0x96f>
   3c87b:	add    $0x1,%r10
   3c87f:	movsbq 0x1(%rax),%r12
   3c884:	movl   $0x1,0x10(%rsp)
   3c88c:	jmpq   3c3c7 <strtold+0x867>
   3c891:	mov    $0xffffffffffffffff,%rax
   3c898:	jmpq   3c5ca <strtold+0xa6a>
   3c89d:	mov    $0xffffffffffffffff,%rax
   3c8a4:	jmpq   3c47d <strtold+0x91d>
   3c8a9:	mov    %eax,%edx
   3c8ab:	jmpq   3c538 <strtold+0x9d8>
   3c8b0:	add    $0x1,%r10
   3c8b4:	movsbq 0x1(%rax),%r12
   3c8b9:	jmpq   3c3c7 <strtold+0x867>
   3c8be:	cmp    $0x65,%al
   3c8c0:	jne    3c8cc <strtold+0xd6c>
   3c8c2:	cmp    $0x10,%r9d
   3c8c6:	jne    3c740 <strtold+0xbe0>
   3c8cc:	mov    %rbp,%rdi
   3c8cf:	cmp    %r15,%r10
   3c8d2:	jbe    3c8fb <strtold+0xd9b>
   3c8d4:	cmpb   $0x30,-0x1(%rbp)
   3c8d8:	jne    3c8f2 <strtold+0xd92>
   3c8da:	sub    %rbp,%r10
   3c8dd:	nopl   (%rax)
   3c8e0:	sub    $0x1,%rbp
   3c8e4:	cmpb   $0x30,-0x1(%rbp)
   3c8e8:	lea    0x0(%rbp,%r10,1),%rax
   3c8ed:	je     3c8e0 <strtold+0xd80>
   3c8ef:	mov    %rax,%r10
   3c8f2:	cmp    %r15,%r10
   3c8f5:	jb     3e73b <strtold+0x2bdb>
   3c8fb:	test   %r10,%r10
   3c8fe:	je     3ca43 <strtold+0xee3>
   3c904:	cmp    %r15,%r10
   3c907:	jne    3ca43 <strtold+0xee3>
   3c90d:	mov    0x98(%rsp),%rdx
   3c915:	test   %rdx,%rdx
   3c918:	js     3d197 <strtold+0x1637>
   3c91e:	cmpq   $0x0,(%rsp)
   3c923:	jne    3ca4a <strtold+0xeea>
   3c929:	test   %rcx,%rcx
   3c92c:	je     3c9c3 <strtold+0xe63>
   3c932:	movzbl (%r14),%esi
   3c936:	movzbl 0x1(%r14),%edi
   3c93b:	jmp    3c944 <strtold+0xde4>
   3c93d:	nopl   (%rax)
   3c940:	add    $0x1,%r13
   3c944:	cmp    %sil,0x0(%r13)
   3c948:	jne    3c940 <strtold+0xde0>
   3c94a:	test   %dil,%dil
   3c94d:	je     3c975 <strtold+0xe15>
   3c94f:	cmp    %dil,0x1(%r13)
   3c953:	jne    3c940 <strtold+0xde0>
   3c955:	xor    %eax,%eax
   3c957:	jmp    3c96b <strtold+0xe0b>
   3c959:	nopl   0x0(%rax)
   3c960:	add    $0x1,%rax
   3c964:	cmp    0x1(%r13,%rax,1),%dl
   3c969:	jne    3c940 <strtold+0xde0>
   3c96b:	movzbl 0x2(%r14,%rax,1),%edx
   3c971:	test   %dl,%dl
   3c973:	jne    3c960 <strtold+0xe00>
   3c975:	cmp    $0x10,%r9d
   3c979:	je     3d26b <strtold+0x170b>
   3c97f:	test   %rcx,%rcx
   3c982:	js     3e9fe <strtold+0x2e9e>
   3c988:	mov    0x98(%rsp),%rax
   3c990:	movabs $0x8000000000000000,%rdx
   3c99a:	add    %rax,%rdx
   3c99d:	cmp    %rcx,%rdx
   3c9a0:	jb     3e9c0 <strtold+0x2e60>
   3c9a6:	mov    %rcx,%rdx
   3c9a9:	mov    0x20(%rsp),%rdi
   3c9ae:	sub    %rdx,%rax
   3c9b1:	sub    %rcx,%r10
   3c9b4:	mov    %rax,0x98(%rsp)
   3c9bc:	lea    (%rcx,%rdi,1),%rsi
   3c9c0:	add    %rsi,%r13
   3c9c3:	cmp    $0x10,%r9d
   3c9c7:	je     3cea3 <strtold+0x1343>
   3c9cd:	mov    0x98(%rsp),%rax
   3c9d5:	test   %rax,%rax
   3c9d8:	js     3d22a <strtold+0x16ca>
   3c9de:	mov    %r10,%rdx
   3c9e1:	sub    %r15,%rdx
   3c9e4:	cmp    %rax,%rdx
   3c9e7:	cmovg  %rax,%rdx
   3c9eb:	add    %rdx,%r15
   3c9ee:	sub    %rdx,%rax
   3c9f1:	mov    $0x27,%edx
   3c9f6:	sub    %r15,%rdx
   3c9f9:	mov    %rax,0x98(%rsp)
   3ca01:	cmp    %rdx,%rax
   3ca04:	jle    3cc53 <strtold+0x10f3>
   3ca0a:	mov    0x10(%rsp),%r10d
   3ca0f:	mov    0x387452(%rip),%rax        # 3c3e68 <_IO_file_jumps+0x628>
   3ca16:	test   %r10d,%r10d
   3ca19:	movl   $0x22,%fs:(%rax)
   3ca20:	je     3d0e2 <strtold+0x1582>
   3ca26:	movss  0x15922a(%rip),%xmm0        # 195c58 <in6addr_loopback+0xbc8>
   3ca2e:	mulss  0x15921e(%rip),%xmm0        # 195c54 <in6addr_loopback+0xbc4>
   3ca36:	jmpq   3c4cf <strtold+0x96f>
   3ca3b:	mov    %rdx,0x98(%rsp)
   3ca43:	cmpq   $0x0,(%rsp)
   3ca48:	je     3ca51 <strtold+0xef1>
   3ca4a:	mov    (%rsp),%rax
   3ca4e:	mov    %rdi,(%rax)
   3ca51:	test   %r10,%r10
   3ca54:	jne    3c929 <strtold+0xdc9>
   3ca5a:	mov    0x10(%rsp),%eax
   3ca5e:	movss  0x1591fa(%rip),%xmm0        # 195c60 <in6addr_loopback+0xbd0>
   3ca66:	test   %eax,%eax
   3ca68:	je     3c4cb <strtold+0x96b>
   3ca6e:	jmpq   3c4cf <strtold+0x96f>
   3ca73:	mov    %r15,%r10
   3ca76:	jmpq   3c710 <strtold+0xbb0>
   3ca7b:	movsbq 0x1(%r10),%rax
   3ca80:	cmpl   $0x78,(%rsi,%rax,4)
   3ca84:	je     3c4f3 <strtold+0x993>
   3ca8a:	test   %rbx,%rbx
   3ca8d:	jne    3c427 <strtold+0x8c7>
   3ca93:	mov    %r10,%rax
   3ca96:	mov    $0xa,%r9d
   3ca9c:	jmpq   3c517 <strtold+0x9b7>
   3caa1:	lea    0x2(%rbp),%rdi
   3caa5:	movzbl 0x2(%rbp),%esi
   3caa9:	movl   $0x0,0x28(%rsp)
   3cab1:	jmpq   3c764 <strtold+0xc04>
   3cab6:	nopw   %cs:0x0(%rax,%rax,1)
   3cac0:	mov    %r10,%rdi
   3cac3:	mov    %rbx,%rdx
   3cac6:	mov    %rbp,%rsi
   3cac9:	mov    %r8,0x30(%rsp)
   3cace:	mov    %r9d,0x28(%rsp)
   3cad3:	mov    %r10,0x18(%rsp)
   3cad8:	callq  49250 <swapcontext+0x23d0>
   3cadd:	cmp    %rbp,%rax
   3cae0:	mov    %rax,%rdi
   3cae3:	mov    0x18(%rsp),%r10
   3cae8:	mov    0x28(%rsp),%r9d
   3caed:	mov    0x30(%rsp),%r8
   3caf2:	je     3d262 <strtold+0x1702>
   3caf8:	cmp    %rax,%r10
   3cafb:	je     3c4c0 <strtold+0x960>
   3cb01:	cmp    %rax,%r13
   3cb04:	ja     3d0b6 <strtold+0x1556>
   3cb0a:	mov    %r13,%rax
   3cb0d:	mov    $0x0,%r10d
   3cb13:	jae    3cb2f <strtold+0xfcf>
   3cb15:	movzbl (%rax),%esi
   3cb18:	lea    0x1(%r10),%rcx
   3cb1c:	lea    -0x30(%rsi),%edx
   3cb1f:	cmp    $0x9,%dl
   3cb22:	cmovbe %rcx,%r10
   3cb26:	add    $0x1,%rax
   3cb2a:	cmp    %rdi,%rax
   3cb2d:	jne    3cb15 <strtold+0xfb5>
   3cb2f:	mov    %r10,%r15
   3cb32:	xor    %ecx,%ecx
   3cb34:	jmpq   3ca43 <strtold+0xee3>
   3cb39:	cmpb   $0x0,0x18(%rsp)
   3cb3e:	je     3d464 <strtold+0x1904>
   3cb44:	cmp    $0x10,%r9d
   3cb48:	sete   %r11b
   3cb4c:	cmp    $0x65,%r15b
   3cb50:	jne    3cb5e <strtold+0xffe>
   3cb52:	test   %r11b,%r11b
   3cb55:	mov    %r13,%rbp
   3cb58:	je     3c570 <strtold+0xa10>
   3cb5e:	mov    %rbx,%rdx
   3cb61:	mov    %r13,%rsi
   3cb64:	mov    %r10,%rdi
   3cb67:	mov    %r11b,0x20(%rsp)
   3cb6c:	mov    %r10,0x18(%rsp)
   3cb71:	callq  49250 <swapcontext+0x23d0>
   3cb76:	cmpq   $0x0,(%rsp)
   3cb7b:	je     3ca5a <strtold+0xefa>
   3cb81:	mov    0x18(%rsp),%r10
   3cb86:	movzbl 0x20(%rsp),%r11d
   3cb8c:	cmp    %rax,%r10
   3cb8f:	je     3d579 <strtold+0x1a19>
   3cb95:	mov    (%rsp),%rdi
   3cb99:	mov    %rax,(%rdi)
   3cb9c:	jmpq   3ca5a <strtold+0xefa>
   3cba1:	lea    0x2(%rbp),%rdi
   3cba5:	movzbl 0x2(%rbp),%esi
   3cba9:	movl   $0x1,0x28(%rsp)
   3cbb1:	jmpq   3c764 <strtold+0xc04>
   3cbb6:	mov    0x28(%rsp),%r12d
   3cbbb:	mov    %r11,0x98(%rsp)
   3cbc3:	test   %r12d,%r12d
   3cbc6:	je     3c8cf <strtold+0xd6f>
   3cbcc:	neg    %r11
   3cbcf:	mov    %r11,0x98(%rsp)
   3cbd7:	jmpq   3c8cf <strtold+0xd6f>
   3cbdc:	mov    %r11,0x98(%rsp)
   3cbe4:	cmp    $0xffffffffffffffff,%rcx
   3cbe8:	je     3d447 <strtold+0x18e7>
   3cbee:	mov    0x28(%rsp),%r15d
   3cbf3:	mov    0x38726e(%rip),%rax        # 3c3e68 <_IO_file_jumps+0x628>
   3cbfa:	test   %r15d,%r15d
   3cbfd:	movl   $0x22,%fs:(%rax)
   3cc04:	jne    3d124 <strtold+0x15c4>
   3cc0a:	mov    0x10(%rsp),%r13d
   3cc0f:	test   %r13d,%r13d
   3cc12:	je     3d521 <strtold+0x19c1>
   3cc18:	movss  0x159038(%rip),%xmm0        # 195c58 <in6addr_loopback+0xbc8>
   3cc20:	mulss  0x15902c(%rip),%xmm0        # 195c54 <in6addr_loopback+0xbc4>
   3cc28:	nopl   0x0(%rax,%rax,1)
   3cc30:	add    $0x1,%rdi
   3cc34:	movzbl (%rdi),%eax
   3cc37:	sub    $0x30,%eax
   3cc3a:	cmp    $0x9,%al
   3cc3c:	jbe    3cc30 <strtold+0x10d0>
   3cc3e:	mov    (%rsp),%rax
   3cc42:	test   %rax,%rax
   3cc45:	je     3c4cf <strtold+0x96f>
   3cc4b:	mov    %rdi,(%rax)
   3cc4e:	jmpq   3c4cf <strtold+0x96f>
   3cc53:	cmp    $0xffffffffffffffd4,%rax
   3cc57:	jl     3d0f3 <strtold+0x1593>
   3cc5d:	xor    %ebp,%ebp
   3cc5f:	test   %r15,%r15
   3cc62:	jne    3e140 <strtold+0x25e0>
   3cc68:	cmp    %r15,%r10
   3cc6b:	jbe    3e75a <strtold+0x2bfa>
   3cc71:	mov    0x98(%rsp),%rcx
   3cc79:	lea    0x2c(%rcx),%rax
   3cc7d:	cmp    $0x2c,%rax
   3cc81:	ja     3e75a <strtold+0x2bfa>
   3cc87:	test   %ebp,%ebp
   3cc89:	jle    3e0c5 <strtold+0x2565>
   3cc8f:	test   %r15,%r15
   3cc92:	je     3e536 <strtold+0x29d6>
   3cc98:	test   %rcx,%rcx
   3cc9b:	jne    3e536 <strtold+0x29d6>
   3cca1:	mov    $0x19,%eax
   3cca6:	xor    %edx,%edx
   3cca8:	sub    %ebp,%eax
   3ccaa:	mov    %r10,%rcx
   3ccad:	cltq   
   3ccaf:	sub    %r15,%rcx
   3ccb2:	cmp    %rcx,%rax
   3ccb5:	mov    %r15d,%ecx
   3ccb8:	jle    3ccc2 <strtold+0x1162>
   3ccba:	mov    %r10d,%eax
   3ccbd:	sub    %r15d,%eax
   3ccc0:	cltq   
   3ccc2:	add    %r15,%rax
   3ccc5:	movb   $0x0,0x28(%rsp)
   3ccca:	cmp    %rax,%r10
   3cccd:	jle    3ccd7 <strtold+0x1177>
   3cccf:	mov    %rax,%r10
   3ccd2:	movb   $0x1,0x28(%rsp)
   3ccd7:	mov    %r10d,%eax
   3ccda:	lea    0xa0(%rsp),%r14
   3cce2:	lea    0x144fd7(%rip),%r9        # 181cc0 <__libc_thread_freeres+0xdda0>
   3cce9:	sub    %ecx,%eax
   3cceb:	xor    %r15d,%r15d
   3ccee:	mov    %r13,0x18(%rsp)
   3ccf3:	mov    %eax,0x8(%rsp)
   3ccf7:	sub    %edx,%eax
   3ccf9:	mov    %rbx,0x30(%rsp)
   3ccfe:	mov    %eax,%r10d
   3cd01:	lea    0xf0(%rsp),%rax
   3cd09:	mov    %ebp,0x3c(%rsp)
   3cd0d:	mov    %r14,0x40(%rsp)
   3cd12:	mov    %r15,%rbp
   3cd15:	mov    $0x1,%r12d
   3cd1b:	mov    %r14,%r15
   3cd1e:	mov    %rax,(%rsp)
   3cd22:	mov    %r10d,%r13d
   3cd25:	mov    %r9,%rbx
   3cd28:	mov    %rax,%r14
   3cd2b:	jmp    3cd66 <strtold+0x1206>
   3cd2d:	lea    -0x1(%rax),%rbp
   3cd31:	mov    (%rbx),%rax
   3cd34:	mov    %r14,%rdi
   3cd37:	lea    0x0(,%rbp,8),%rdx
   3cd3f:	lea    0x8(,%rax,8),%rsi
   3cd47:	lea    0x1450f2(%rip),%rax        # 181e40 <__libc_thread_freeres+0xdf20>
   3cd4e:	add    %rax,%rsi
   3cd51:	callq  943f0 <memcpy+0x70>
   3cd56:	add    %r12d,%r12d
   3cd59:	add    $0x18,%rbx
   3cd5d:	test   %r13d,%r13d
   3cd60:	je     3d2b0 <strtold+0x1750>
   3cd66:	test   %r12d,%r13d
   3cd69:	je     3cd56 <strtold+0x11f6>
   3cd6b:	xor    %r12d,%r13d
   3cd6e:	test   %rbp,%rbp
   3cd71:	mov    0x8(%rbx),%rax
   3cd75:	je     3cd2d <strtold+0x11cd>
   3cd77:	lea    -0x1(%rax),%rdx
   3cd7b:	mov    (%rbx),%rax
   3cd7e:	mov    %rbp,%r8
   3cd81:	mov    %r14,%rcx
   3cd84:	mov    %r15,%rdi
   3cd87:	lea    0x8(,%rax,8),%rsi
   3cd8f:	lea    0x1450aa(%rip),%rax        # 181e40 <__libc_thread_freeres+0xdf20>
   3cd96:	add    %rax,%rsi
   3cd99:	callq  47bb0 <swapcontext+0xd30>
   3cd9e:	mov    0x8(%rbx),%rdx
   3cda2:	test   %rax,%rax
   3cda5:	lea    -0x1(%rbp,%rdx,1),%rbp
   3cdaa:	jne    3d21c <strtold+0x16bc>
   3cdb0:	mov    %r14,%rax
   3cdb3:	sub    $0x1,%rbp
   3cdb7:	mov    %r15,%r14
   3cdba:	mov    %rax,%r15
   3cdbd:	jmp    3cd56 <strtold+0x11f6>
   3cdbf:	lea    0x385efa(%rip),%rcx        # 3c2cc0 <h_errlist+0x940>
   3cdc6:	lea    0x14f539(%rip),%rsi        # 18c306 <_libc_intl_domainname+0xdd>
   3cdcd:	mov    %r10,%rdi
   3cdd0:	mov    $0x3,%edx
   3cdd5:	mov    %r10,0x18(%rsp)
   3cdda:	callq  91d10 <strncasecmp+0x70>
   3cddf:	test   %eax,%eax
   3cde1:	mov    0x18(%rsp),%r10
   3cde6:	jne    3c4c0 <strtold+0x960>
   3cdec:	mov    (%rsp),%r15
   3cdf0:	test   %r15,%r15
   3cdf3:	je     3ce29 <strtold+0x12c9>
   3cdf5:	lea    0x3(%r10),%rbx
   3cdf9:	lea    0x385ec0(%rip),%rcx        # 3c2cc0 <h_errlist+0x940>
   3ce00:	lea    0x14f503(%rip),%rsi        # 18c30a <_libc_intl_domainname+0xe1>
   3ce07:	mov    $0x5,%edx
   3ce0c:	mov    %r10,(%rsp)
   3ce10:	mov    %rbx,%rdi
   3ce13:	callq  91d10 <strncasecmp+0x70>
   3ce18:	mov    (%rsp),%r10
   3ce1c:	add    $0x8,%r10
   3ce20:	test   %eax,%eax
   3ce22:	cmove  %r10,%rbx
   3ce26:	mov    %rbx,(%r15)
   3ce29:	mov    0x10(%rsp),%eax
   3ce2d:	test   %eax,%eax
   3ce2f:	jne    3d514 <strtold+0x19b4>
   3ce35:	movss  0x158e27(%rip),%xmm0        # 195c64 <in6addr_loopback+0xbd4>
   3ce3d:	jmpq   3c4cf <strtold+0x96f>
   3ce42:	mov    %r12d,%edx
   3ce45:	mov    %r10,%r13
   3ce48:	mov    $0xa,%r9d
   3ce4e:	jmpq   3c538 <strtold+0x9d8>
   3ce53:	test   %r15,%r15
   3ce56:	je     3d158 <strtold+0x15f8>
   3ce5c:	test   %rcx,%rcx
   3ce5f:	jne    3e4bc <strtold+0x295c>
   3ce65:	mov    %r15,%rax
   3ce68:	shr    $0x3f,%rax
   3ce6c:	test   %al,%al
   3ce6e:	jne    3e4bc <strtold+0x295c>
   3ce74:	mov    $0x27,%eax
   3ce79:	sub    %r15,%rax
   3ce7c:	mov    %rax,0x18(%rsp)
   3ce81:	cmpq   $0x0,0x18(%rsp)
   3ce87:	jns    3e48d <strtold+0x292d>
   3ce8d:	movq   $0x0,0x18(%rsp)
   3ce96:	xor    %r12d,%r12d
   3ce99:	mov    0x18(%rsp),%rax
   3ce9e:	jmpq   3c7c6 <strtold+0xc66>
   3cea3:	movsbq 0x0(%r13),%rcx
   3cea8:	mov    0x68(%r8),%rdx
   3ceac:	testb  $0x10,0x1(%rdx,%rcx,2)
   3ceb1:	mov    %rcx,%rax
   3ceb4:	jne    3ced9 <strtold+0x1379>
   3ceb6:	add    $0x1,%r13
   3ceba:	movsbq 0x0(%r13),%rcx
   3cebf:	testb  $0x10,0x1(%rdx,%rcx,2)
   3cec4:	mov    %rcx,%rax
   3cec7:	je     3ceb6 <strtold+0x1356>
   3cec9:	jmp    3ced9 <strtold+0x1379>
   3cecb:	nopl   0x0(%rax,%rax,1)
   3ced0:	add    $0x1,%r13
   3ced4:	movsbq 0x0(%r13),%rax
   3ced9:	cmp    $0x30,%al
   3cedb:	je     3ced0 <strtold+0x1370>
   3cedd:	movsbl %al,%r11d
   3cee1:	add    $0x1,%r13
   3cee5:	sub    $0x30,%r11d
   3cee9:	cmp    $0x9,%r11d
   3ceed:	ja     3d147 <strtold+0x15e7>
   3cef3:	lea    0x144b06(%rip),%rax        # 181a00 <__libc_thread_freeres+0xdae0>
   3cefa:	movslq %r11d,%r11
   3cefd:	mov    (%rax,%r11,4),%eax
   3cf01:	test   %eax,%eax
   3cf03:	je     3e914 <strtold+0x2db4>
   3cf09:	mov    $0x18,%ecx
   3cf0e:	mov    0x98(%rsp),%rsi
   3cf16:	sub    %eax,%ecx
   3cf18:	shl    %cl,%r11
   3cf1b:	mov    $0x17,%ecx
   3cf20:	sub    %eax,%ecx
   3cf22:	test   %rsi,%rsi
   3cf25:	mov    %r11,0x80(%rsp)
   3cf2d:	mov    %ecx,%r9d
   3cf30:	js     3d17e <strtold+0x161e>
   3cf36:	movabs $0x7fffffffffffffff,%rdi
   3cf40:	movslq %eax,%rcx
   3cf43:	sub    %rsi,%rdi
   3cf46:	sub    %rcx,%rdi
   3cf49:	lea    0x4(%rdi),%rcx
   3cf4d:	add    $0x1,%rdi
   3cf51:	cmovns %rdi,%rcx
   3cf55:	sar    $0x2,%rcx
   3cf59:	cmp    %r15,%rcx
   3cf5c:	jb     3e872 <strtold+0x2d12>
   3cf62:	sub    $0x1,%eax
   3cf65:	lea    (%rsi,%r15,4),%rcx
   3cf69:	sub    $0x1,%r10
   3cf6d:	cltq   
   3cf6f:	lea    -0x4(%rcx,%rax,1),%rsi
   3cf74:	mov    %rsi,0x98(%rsp)
   3cf7c:	je     3d244 <strtold+0x16e4>
   3cf82:	mov    0x20(%rsp),%rbx
   3cf87:	jmp    3cfab <strtold+0x144b>
   3cf89:	nopl   0x0(%rax)
   3cf90:	lea    -0x3(%r9),%ecx
   3cf94:	mov    %rdi,%rax
   3cf97:	sub    $0x4,%r9d
   3cf9b:	shl    %cl,%rax
   3cf9e:	or     %rax,%r11
   3cfa1:	sub    $0x1,%r10
   3cfa5:	je     3d23c <strtold+0x16dc>
   3cfab:	movsbq 0x0(%r13),%rax
   3cfb0:	testb  $0x10,0x1(%rdx,%rax,2)
   3cfb5:	mov    %rax,%rcx
   3cfb8:	jne    3cfc2 <strtold+0x1462>
   3cfba:	add    %rbx,%r13
   3cfbd:	movsbq 0x0(%r13),%rcx
   3cfc2:	movsbl %cl,%eax
   3cfc5:	add    $0x1,%r13
   3cfc9:	sub    $0x30,%eax
   3cfcc:	cmp    $0x9,%eax
   3cfcf:	jbe    3cfdb <strtold+0x147b>
   3cfd1:	mov    0x70(%r8),%rax
   3cfd5:	mov    (%rax,%rcx,4),%eax
   3cfd8:	sub    $0x57,%eax
   3cfdb:	cmp    $0x2,%r9d
   3cfdf:	movslq %eax,%rdi
   3cfe2:	jg     3cf90 <strtold+0x1430>
   3cfe4:	mov    $0x3,%ecx
   3cfe9:	mov    %rdi,%rax
   3cfec:	sub    %r9d,%ecx
   3cfef:	shr    %cl,%rax
   3cff2:	lea    0x3d(%r9),%ecx
   3cff6:	or     %rax,%r11
   3cff9:	shl    %cl,%rdi
   3cffc:	sub    $0x1,%r10
   3d000:	mov    %r11,0x80(%rsp)
   3d008:	mov    %rdi,%rcx
   3d00b:	je     3d034 <strtold+0x14d4>
   3d00d:	cmpb   $0x30,0x0(%r13)
   3d012:	jne    3d56e <strtold+0x1a0e>
   3d018:	lea    0x1(%r13),%rax
   3d01c:	add    %r10,%r13
   3d01f:	jmp    3d02f <strtold+0x14cf>
   3d021:	add    $0x1,%rax
   3d025:	cmpb   $0x30,-0x1(%rax)
   3d029:	jne    3d56e <strtold+0x1a0e>
   3d02f:	cmp    %r13,%rax
   3d032:	jne    3d021 <strtold+0x14c1>
   3d034:	xor    %r9d,%r9d
   3d037:	mov    0x10(%rsp),%edx
   3d03b:	lea    0x80(%rsp),%rdi
   3d043:	mov    $0x3f,%r8d
   3d049:	callq  3be60 <strtold+0x300>
   3d04e:	jmpq   3c4cf <strtold+0x96f>
   3d053:	lea    0x385c66(%rip),%rcx        # 3c2cc0 <h_errlist+0x940>
   3d05a:	lea    0x14f2af(%rip),%rsi        # 18c310 <_libc_intl_domainname+0xe7>
   3d061:	mov    %r10,%rdi
   3d064:	mov    $0x3,%edx
   3d069:	mov    %r8,0x18(%rsp)
   3d06e:	mov    %r10,0x10(%rsp)
   3d073:	callq  91d10 <strncasecmp+0x70>
   3d078:	test   %eax,%eax
   3d07a:	mov    0x10(%rsp),%r10
   3d07f:	mov    0x18(%rsp),%r8
   3d084:	jne    3c4c0 <strtold+0x960>
   3d08a:	cmpb   $0x28,0x3(%r10)
   3d08f:	lea    0x3(%r10),%rcx
   3d093:	movss  0x158bc1(%rip),%xmm0        # 195c5c <in6addr_loopback+0xbcc>
   3d09b:	je     3e420 <strtold+0x28c0>
   3d0a1:	mov    (%rsp),%rax
   3d0a5:	test   %rax,%rax
   3d0a8:	je     3c4cf <strtold+0x96f>
   3d0ae:	mov    %rcx,(%rax)
   3d0b1:	jmpq   3c4cf <strtold+0x96f>
   3d0b6:	mov    (%rsp),%rax
   3d0ba:	test   %rax,%rax
   3d0bd:	je     3ca5a <strtold+0xefa>
   3d0c3:	mov    %rdi,(%rax)
   3d0c6:	jmpq   3ca5a <strtold+0xefa>
   3d0cb:	xor    %eax,%eax
   3d0cd:	jmpq   3c400 <strtold+0x8a0>
   3d0d2:	mov    %rax,%r10
   3d0d5:	xor    %ecx,%ecx
   3d0d7:	mov    $0x10,%r9d
   3d0dd:	jmpq   3c42d <strtold+0x8cd>
   3d0e2:	movss  0x158b6a(%rip),%xmm0        # 195c54 <in6addr_loopback+0xbc4>
   3d0ea:	mulss  %xmm0,%xmm0
   3d0ee:	jmpq   3c4cf <strtold+0x96f>
   3d0f3:	mov    0x10(%rsp),%r9d
   3d0f8:	mov    0x386d69(%rip),%rax        # 3c3e68 <_IO_file_jumps+0x628>
   3d0ff:	test   %r9d,%r9d
   3d102:	movl   $0x22,%fs:(%rax)
   3d109:	je     3d4c8 <strtold+0x1968>
   3d10f:	movss  0x158b39(%rip),%xmm0        # 195c50 <in6addr_loopback+0xbc0>
   3d117:	mulss  0x158b2d(%rip),%xmm0        # 195c4c <in6addr_loopback+0xbbc>
   3d11f:	jmpq   3c4cf <strtold+0x96f>
   3d124:	mov    0x10(%rsp),%r14d
   3d129:	test   %r14d,%r14d
   3d12c:	je     3d503 <strtold+0x19a3>
   3d132:	movss  0x158b16(%rip),%xmm0        # 195c50 <in6addr_loopback+0xbc0>
   3d13a:	mulss  0x158b0a(%rip),%xmm0        # 195c4c <in6addr_loopback+0xbbc>
   3d142:	jmpq   3cc30 <strtold+0x10d0>
   3d147:	mov    0x70(%r8),%rcx
   3d14b:	mov    (%rcx,%rax,4),%r11d
   3d14f:	sub    $0x57,%r11d
   3d153:	jmpq   3cef3 <strtold+0x1393>
   3d158:	cmp    $0xffffffffffffffff,%rcx
   3d15c:	je     3d5a4 <strtold+0x1a44>
   3d162:	movabs $0x7fffffffffffffd8,%rax
   3d16c:	cmp    %rax,%rcx
   3d16f:	ja     3e8f5 <strtold+0x2d95>
   3d175:	lea    0x27(%rcx),%rax
   3d179:	jmpq   3c79d <strtold+0xc3d>
   3d17e:	movslq %eax,%rdi
   3d181:	movabs $0x8000000000000000,%rcx
   3d18b:	sub    %rdi,%rcx
   3d18e:	sar    $0x2,%rcx
   3d192:	jmpq   3cf59 <strtold+0x13f9>
   3d197:	cmpb   $0x0,0x8(%rsp)
   3d19c:	lea    -0x1(%rbp),%rax
   3d1a0:	je     3d1cf <strtold+0x166f>
   3d1a2:	jmpq   3d532 <strtold+0x19d2>
   3d1a7:	nopw   0x0(%rax,%rax,1)
   3d1b0:	sub    $0x1,%r10
   3d1b4:	sub    $0x1,%r15
   3d1b8:	add    $0x1,%rdx
   3d1bc:	jns    3ca3b <strtold+0xedb>
   3d1c2:	test   %r10,%r10
   3d1c5:	je     3ca3b <strtold+0xedb>
   3d1cb:	sub    $0x1,%rax
   3d1cf:	movsbl (%rax),%esi
   3d1d2:	mov    %esi,%r11d
   3d1d5:	sub    $0x30,%esi
   3d1d8:	cmp    $0x9,%esi
   3d1db:	ja     3d1cb <strtold+0x166b>
   3d1dd:	cmp    $0x30,%r11b
   3d1e1:	je     3d1b0 <strtold+0x1650>
   3d1e3:	mov    %rdx,0x98(%rsp)
   3d1eb:	jmpq   3c91e <strtold+0xdbe>
   3d1f0:	mov    0x28(%rsp),%eax
   3d1f4:	test   %eax,%eax
   3d1f6:	je     3d48d <strtold+0x192d>
   3d1fc:	movabs $0x1fffffffffffffda,%rax
   3d206:	cmp    %rax,%r15
   3d209:	ja     3e82d <strtold+0x2ccd>
   3d20f:	lea    0x95(,%r15,4),%rax
   3d217:	jmpq   3c79d <strtold+0xc3d>
   3d21c:	mov    %r14,%rax
   3d21f:	mov    %r15,%r14
   3d222:	mov    %rax,%r15
   3d225:	jmpq   3cd56 <strtold+0x11f6>
   3d22a:	mov    %r15,%rdx
   3d22d:	neg    %rdx
   3d230:	cmp    %rax,%rdx
   3d233:	cmovl  %rax,%rdx
   3d237:	jmpq   3c9eb <strtold+0xe8b>
   3d23c:	mov    %r11,0x80(%rsp)
   3d244:	mov    0x10(%rsp),%edx
   3d248:	lea    0x80(%rsp),%rdi
   3d250:	xor    %r9d,%r9d
   3d253:	xor    %r8d,%r8d
   3d256:	xor    %ecx,%ecx
   3d258:	callq  3be60 <strtold+0x300>
   3d25d:	jmpq   3c4cf <strtold+0x96f>
   3d262:	movzbl (%r14),%edi
   3d266:	jmpq   3c65e <strtold+0xafe>
   3d26b:	movabs $0x1fffffffffffffff,%rax
   3d275:	cmp    %rax,%rcx
   3d278:	ja     3e9fe <strtold+0x2e9e>
   3d27e:	mov    0x98(%rsp),%rax
   3d286:	movabs $0x8000000000000000,%rdx
   3d290:	add    %rax,%rdx
   3d293:	shr    $0x2,%rdx
   3d297:	cmp    %rcx,%rdx
   3d29a:	jb     3e9c0 <strtold+0x2e60>
   3d2a0:	lea    0x0(,%rcx,4),%rdx
   3d2a8:	jmpq   3c9a9 <strtold+0xe49>
   3d2ad:	nopl   (%rax)
   3d2b0:	mov    %r14,%r11
   3d2b3:	mov    0x40(%rsp),%r14
   3d2b8:	mov    %rbp,%r15
   3d2bb:	mov    0x18(%rsp),%r13
   3d2c0:	mov    0x30(%rsp),%rbx
   3d2c5:	mov    0x3c(%rsp),%ebp
   3d2c9:	cmp    %r14,%r11
   3d2cc:	je     3e933 <strtold+0x2dd3>
   3d2d2:	sub    $0x8,%rsp
   3d2d6:	mov    %r14,%rdx
   3d2d9:	mov    %r13,%rdi
   3d2dc:	lea    0x98(%rsp),%rcx
   3d2e4:	push   %rbx
   3d2e5:	mov    0x30(%rsp),%r9
   3d2ea:	mov    0x18(%rsp),%esi
   3d2ee:	lea    0xa8(%rsp),%r8
   3d2f6:	callq  3bb80 <strtold+0x20>
   3d2fb:	lea    -0x1(%r15),%rax
   3d2ff:	bsr    0x100(%rsp,%rax,8),%rbx
   3d308:	mov    %rax,0x28(%rsp)
   3d30d:	pop    %rcx
   3d30e:	pop    %rsi
   3d30f:	xor    $0x3f,%rbx
   3d313:	test   %ebx,%ebx
   3d315:	je     3d480 <strtold+0x1920>
   3d31b:	mov    (%rsp),%rdi
   3d31f:	mov    %ebx,%ecx
   3d321:	mov    %r15,%rdx
   3d324:	mov    %rdi,%rsi
   3d327:	callq  47940 <swapcontext+0xac0>
   3d32c:	mov    0x90(%rsp),%rdx
   3d334:	mov    %ebx,%ecx
   3d336:	mov    %r14,%rsi
   3d339:	mov    %r14,%rdi
   3d33c:	callq  47940 <swapcontext+0xac0>
   3d341:	test   %rax,%rax
   3d344:	je     3d480 <strtold+0x1920>
   3d34a:	mov    0x90(%rsp),%rcx
   3d352:	lea    0x1(%rcx),%rdx
   3d356:	mov    %rax,0xa0(%rsp,%rcx,8)
   3d35e:	mov    %rdx,0x90(%rsp)
   3d366:	movslq %ebp,%r12
   3d369:	cmp    $0x1,%r15
   3d36d:	mov    %r12,0x98(%rsp)
   3d375:	je     3dd63 <strtold+0x2203>
   3d37b:	cmp    $0x2,%r15
   3d37f:	jne    3d5bd <strtold+0x1a5d>
   3d385:	cmp    $0x1,%rdx
   3d389:	mov    0xf0(%rsp),%r14
   3d391:	mov    0xf8(%rsp),%r15
   3d399:	jg     3e08f <strtold+0x252f>
   3d39f:	mov    0xa0(%rsp),%rbx
   3d3a7:	cmp    %rbx,%r15
   3d3aa:	jbe    3dea9 <strtold+0x2349>
   3d3b0:	test   %ebp,%ebp
   3d3b2:	jle    3e7a8 <strtold+0x2c48>
   3d3b8:	mov    $0x18,%r8d
   3d3be:	sub    %ebp,%r8d
   3d3c1:	je     3e798 <strtold+0x2c38>
   3d3c7:	lea    0x80(%rsp),%r12
   3d3cf:	mov    %r8d,%ecx
   3d3d2:	mov    $0x1,%edx
   3d3d7:	mov    %r8d,(%rsp)
   3d3db:	mov    %r12,%rsi
   3d3de:	mov    %r12,%rdi
   3d3e1:	callq  47940 <swapcontext+0xac0>
   3d3e6:	mov    0xa0(%rsp),%r9
   3d3ee:	mov    (%rsp),%r8d
   3d3f2:	add    $0x40,%ebp
   3d3f5:	cmp    $0x18,%ebp
   3d3f8:	jle    3e84c <strtold+0x2cec>
   3d3fe:	mov    $0x3f,%eax
   3d403:	xor    %r13d,%r13d
   3d406:	xor    %ebx,%ebx
   3d408:	sub    %r8d,%eax
   3d40b:	movslq %eax,%r8
   3d40e:	mov    0x98(%rsp),%rax
   3d416:	test   %r9,%r9
   3d419:	lea    -0x1(%rax),%rsi
   3d41d:	mov    %r13,%rcx
   3d420:	setne  %r9b
   3d424:	test   %rbx,%rbx
   3d427:	mov    %r12,%rdi
   3d42a:	setne  %dl
   3d42d:	or     %edx,%r9d
   3d430:	or     0x28(%rsp),%r9b
   3d435:	mov    0x10(%rsp),%edx
   3d439:	and    $0x1,%r9d
   3d43d:	callq  3be60 <strtold+0x300>
   3d442:	jmpq   3c4cf <strtold+0x96f>
   3d447:	mov    0x10(%rsp),%eax
   3d44b:	movss  0x15880d(%rip),%xmm0        # 195c60 <in6addr_loopback+0xbd0>
   3d453:	test   %eax,%eax
   3d455:	jne    3cc30 <strtold+0x10d0>
   3d45b:	pxor   %xmm0,%xmm0
   3d45f:	jmpq   3cc30 <strtold+0x10d0>
   3d464:	cmp    $0x70,%r15b
   3d468:	jne    3cb44 <strtold+0xfe4>
   3d46e:	cmp    %r10,%r13
   3d471:	jne    3c648 <strtold+0xae8>
   3d477:	jmpq   3cb44 <strtold+0xfe4>
   3d47c:	nopl   0x0(%rax)
   3d480:	mov    0x90(%rsp),%rdx
   3d488:	jmpq   3d366 <strtold+0x1806>
   3d48d:	test   %r15,%r15
   3d490:	je     3d4d9 <strtold+0x1979>
   3d492:	test   %rcx,%rcx
   3d495:	jne    3e853 <strtold+0x2cf3>
   3d49b:	movabs $0x1fffffffffffffff,%rax
   3d4a5:	cmp    %rax,%r15
   3d4a8:	ja     3e853 <strtold+0x2cf3>
   3d4ae:	mov    $0x20,%eax
   3d4b3:	sub    %r15,%rax
   3d4b6:	lea    0x3(,%rax,4),%rax
   3d4be:	mov    %rax,0x18(%rsp)
   3d4c3:	jmpq   3ce81 <strtold+0x1321>
   3d4c8:	movss  0x15877c(%rip),%xmm0        # 195c4c <in6addr_loopback+0xbbc>
   3d4d0:	mulss  %xmm0,%xmm0
   3d4d4:	jmpq   3c4cf <strtold+0x96f>
   3d4d9:	cmp    $0xffffffffffffffff,%rcx
   3d4dd:	je     3d58b <strtold+0x1a2b>
   3d4e3:	movabs $0x1fffffffffffffdf,%rax
   3d4ed:	cmp    %rax,%rcx
   3d4f0:	ja     3e9df <strtold+0x2e7f>
   3d4f6:	lea    0x83(,%rcx,4),%rax
   3d4fe:	jmpq   3c79d <strtold+0xc3d>
   3d503:	movss  0x158741(%rip),%xmm0        # 195c4c <in6addr_loopback+0xbbc>
   3d50b:	mulss  %xmm0,%xmm0
   3d50f:	jmpq   3cc30 <strtold+0x10d0>
   3d514:	movss  0x15874c(%rip),%xmm0        # 195c68 <in6addr_loopback+0xbd8>
   3d51c:	jmpq   3c4cf <strtold+0x96f>
   3d521:	movss  0x15872b(%rip),%xmm0        # 195c54 <in6addr_loopback+0xbc4>
   3d529:	mulss  %xmm0,%xmm0
   3d52d:	jmpq   3cc30 <strtold+0x10d0>
   3d532:	mov    0x68(%r8),%r12
   3d536:	jmp    3d557 <strtold+0x19f7>
   3d538:	sub    $0x1,%r10
   3d53c:	sub    $0x1,%r15
   3d540:	add    $0x4,%rdx
   3d544:	jns    3ca3b <strtold+0xedb>
   3d54a:	test   %r10,%r10
   3d54d:	je     3ca3b <strtold+0xedb>
   3d553:	sub    $0x1,%rax
   3d557:	movsbq (%rax),%r11
   3d55b:	testb  $0x10,0x1(%r12,%r11,2)
   3d561:	je     3d553 <strtold+0x19f3>
   3d563:	cmp    $0x30,%r11b
   3d567:	je     3d538 <strtold+0x19d8>
   3d569:	jmpq   3d1e3 <strtold+0x1683>
   3d56e:	mov    $0x1,%r9d
   3d574:	jmpq   3d037 <strtold+0x14d7>
   3d579:	lea    -0x1(%r13),%rax
   3d57d:	test   %r11b,%r11b
   3d580:	cmove  0x8(%rsp),%rax
   3d586:	jmpq   3cb95 <strtold+0x1035>
   3d58b:	movq   $0x83,0x18(%rsp)
   3d594:	mov    $0xd,%r12d
   3d59a:	mov    0x18(%rsp),%rax
   3d59f:	jmpq   3c7c6 <strtold+0xc66>
   3d5a4:	movq   $0x27,0x18(%rsp)
   3d5ad:	mov    $0x3,%r12d
   3d5b3:	mov    0x18(%rsp),%rax
   3d5b8:	jmpq   3c7c6 <strtold+0xc66>
   3d5bd:	mov    0x18(%rsp),%rax
   3d5c2:	lea    -0x2(%r15),%r9
   3d5c6:	mov    (%rsp),%rdi
   3d5ca:	mov    0xf0(%rsp,%r9,8),%r8
   3d5d2:	mov    %r9,0x20(%rsp)
   3d5d7:	mov    0xf0(%rsp,%rax,8),%r13
   3d5df:	mov    %r15,%rax
   3d5e2:	sub    %rdx,%rax
   3d5e5:	lea    (%rdi,%rax,8),%rsi
   3d5e9:	mov    %r14,%rdi
   3d5ec:	mov    %r8,0x8(%rsp)
   3d5f1:	callq  47450 <swapcontext+0x5d0>
   3d5f6:	test   %eax,%eax
   3d5f8:	mov    0x90(%rsp),%rdx
   3d600:	mov    0x8(%rsp),%r8
   3d605:	mov    0x20(%rsp),%r9
   3d60a:	jle    3d62c <strtold+0x1acc>
   3d60c:	mov    0x90(%rsp),%rax
   3d614:	lea    0x1(%rax),%rdx
   3d618:	movq   $0x0,0xa0(%rsp,%rax,8)
   3d624:	mov    %rdx,0x90(%rsp)
   3d62c:	cmp    %r15,%rdx
   3d62f:	jge    3d989 <strtold+0x1e29>
   3d635:	mov    %r15,%rbx
   3d638:	sub    %rdx,%rbx
   3d63b:	mov    %rbx,%rax
   3d63e:	shl    $0x6,%rax
   3d642:	test   %ebp,%ebp
   3d644:	jle    3e8b0 <strtold+0x2d50>
   3d64a:	add    %rax,%r12
   3d64d:	cmp    $0x18,%r12
   3d651:	jg     3e974 <strtold+0x2e14>
   3d657:	cmp    $0x1,%rbx
   3d65b:	jne    3e955 <strtold+0x2df5>
   3d661:	movq   $0x0,0x80(%rsp)
   3d66d:	movl   $0x0,0x8(%rsp)
   3d675:	mov    %ebx,%eax
   3d677:	shl    $0x6,%eax
   3d67a:	add    %eax,%ebp
   3d67c:	test   %edx,%edx
   3d67e:	mov    %edx,%eax
   3d680:	jle    3d7ba <strtold+0x1c5a>
   3d686:	lea    -0x1(%rdx),%esi
   3d689:	movslq %edx,%rdx
   3d68c:	add    %rbx,%rdx
   3d68f:	movslq %esi,%rcx
   3d692:	test   %esi,%esi
   3d694:	mov    0xa0(%rsp,%rcx,8),%rdi
   3d69c:	mov    %rdi,0xa0(%rsp,%rdx,8)
   3d6a4:	je     3d7ba <strtold+0x1c5a>
   3d6aa:	lea    -0x2(%rax),%edx
   3d6ad:	add    %rbx,%rcx
   3d6b0:	movslq %edx,%rsi
   3d6b3:	test   %edx,%edx
   3d6b5:	mov    0xa0(%rsp,%rsi,8),%rdi
   3d6bd:	mov    %rdi,0xa0(%rsp,%rcx,8)
   3d6c5:	je     3d7ba <strtold+0x1c5a>
   3d6cb:	lea    -0x3(%rax),%ecx
   3d6ce:	add    %rbx,%rsi
   3d6d1:	movslq %ecx,%rdx
   3d6d4:	test   %ecx,%ecx
   3d6d6:	mov    0xa0(%rsp,%rdx,8),%rdi
   3d6de:	mov    %rdi,0xa0(%rsp,%rsi,8)
   3d6e6:	je     3d7ba <strtold+0x1c5a>
   3d6ec:	lea    -0x4(%rax),%esi
   3d6ef:	add    %rbx,%rdx
   3d6f2:	movslq %esi,%rcx
   3d6f5:	test   %esi,%esi
   3d6f7:	mov    0xa0(%rsp,%rcx,8),%rdi
   3d6ff:	mov    %rdi,0xa0(%rsp,%rdx,8)
   3d707:	je     3d7ba <strtold+0x1c5a>
   3d70d:	lea    -0x5(%rax),%esi
   3d710:	add    %rbx,%rcx
   3d713:	movslq %esi,%rdx
   3d716:	test   %esi,%esi
   3d718:	mov    0xa0(%rsp,%rdx,8),%rdi
   3d720:	mov    %rdi,0xa0(%rsp,%rcx,8)
   3d728:	je     3d7ba <strtold+0x1c5a>
   3d72e:	lea    -0x6(%rax),%esi
   3d731:	add    %rbx,%rdx
   3d734:	movslq %esi,%rcx
   3d737:	test   %esi,%esi
   3d739:	mov    0xa0(%rsp,%rcx,8),%rdi
   3d741:	mov    %rdi,0xa0(%rsp,%rdx,8)
   3d749:	je     3d7ba <strtold+0x1c5a>
   3d74b:	lea    -0x7(%rax),%esi
   3d74e:	add    %rbx,%rcx
   3d751:	movslq %esi,%rdx
   3d754:	test   %esi,%esi
   3d756:	mov    0xa0(%rsp,%rdx,8),%rdi
   3d75e:	mov    %rdi,0xa0(%rsp,%rcx,8)
   3d766:	je     3d7ba <strtold+0x1c5a>
   3d768:	lea    -0x8(%rax),%esi
   3d76b:	add    %rbx,%rdx
   3d76e:	movslq %esi,%rcx
   3d771:	test   %esi,%esi
   3d773:	mov    0xa0(%rsp,%rcx,8),%rdi
   3d77b:	mov    %rdi,0xa0(%rsp,%rdx,8)
   3d783:	je     3d7ba <strtold+0x1c5a>
   3d785:	lea    -0x9(%rax),%esi
   3d788:	add    %rbx,%rcx
   3d78b:	movslq %esi,%rdx
   3d78e:	test   %esi,%esi
   3d790:	mov    0xa0(%rsp,%rdx,8),%rdi
   3d798:	mov    %rdi,0xa0(%rsp,%rcx,8)
   3d7a0:	je     3d7ba <strtold+0x1c5a>
   3d7a2:	sub    $0xa,%eax
   3d7a5:	add    %rbx,%rdx
   3d7a8:	cltq   
   3d7aa:	mov    0xa0(%rsp,%rax,8),%rax
   3d7b2:	mov    %rax,0xa0(%rsp,%rdx,8)
   3d7ba:	test   %rbx,%rbx
   3d7bd:	js     3d7e5 <strtold+0x1c85>
   3d7bf:	lea    0x8(,%rbx,8),%rdx
   3d7c7:	xor    %esi,%esi
   3d7c9:	mov    %r14,%rdi
   3d7cc:	mov    %r8,0x30(%rsp)
   3d7d1:	mov    %r9,0x20(%rsp)
   3d7d6:	callq  8f200 <__bzero+0x40>
   3d7db:	mov    0x20(%rsp),%r9
   3d7e0:	mov    0x30(%rsp),%r8
   3d7e5:	cmp    $0x18,%ebp
   3d7e8:	movq   $0x0,0xf0(%rsp,%r15,8)
   3d7f4:	mov    0xa0(%rsp,%r15,8),%rcx
   3d7fc:	jle    3e94c <strtold+0x2dec>
   3d802:	mov    0x98(%rsp),%rsi
   3d80a:	lea    0x80(%rsp),%r12
   3d812:	xor    %ebx,%ebx
   3d814:	test   %r15d,%r15d
   3d817:	mov    %r15d,%edx
   3d81a:	js     3d94b <strtold+0x1deb>
   3d820:	movslq %r15d,%r15
   3d823:	cmpq   $0x0,0xa0(%rsp,%r15,8)
   3d82c:	jne    3d94b <strtold+0x1deb>
   3d832:	lea    -0x1(%rdx),%eax
   3d835:	cmp    $0xffffffff,%eax
   3d838:	je     3d985 <strtold+0x1e25>
   3d83e:	movslq %eax,%rcx
   3d841:	cmpq   $0x0,0xa0(%rsp,%rcx,8)
   3d84a:	jne    3d985 <strtold+0x1e25>
   3d850:	lea    -0x2(%rdx),%eax
   3d853:	cmp    $0xffffffff,%eax
   3d856:	je     3d985 <strtold+0x1e25>
   3d85c:	movslq %eax,%rcx
   3d85f:	cmpq   $0x0,0xa0(%rsp,%rcx,8)
   3d868:	jne    3d985 <strtold+0x1e25>
   3d86e:	lea    -0x3(%rdx),%eax
   3d871:	cmp    $0xffffffff,%eax
   3d874:	je     3d985 <strtold+0x1e25>
   3d87a:	movslq %eax,%rcx
   3d87d:	cmpq   $0x0,0xa0(%rsp,%rcx,8)
   3d886:	jne    3d985 <strtold+0x1e25>
   3d88c:	lea    -0x4(%rdx),%eax
   3d88f:	cmp    $0xffffffff,%eax
   3d892:	je     3d985 <strtold+0x1e25>
   3d898:	movslq %eax,%rcx
   3d89b:	cmpq   $0x0,0xa0(%rsp,%rcx,8)
   3d8a4:	jne    3d985 <strtold+0x1e25>
   3d8aa:	lea    -0x5(%rdx),%eax
   3d8ad:	cmp    $0xffffffff,%eax
   3d8b0:	je     3d985 <strtold+0x1e25>
   3d8b6:	movslq %eax,%rcx
   3d8b9:	cmpq   $0x0,0xa0(%rsp,%rcx,8)
   3d8c2:	jne    3d985 <strtold+0x1e25>
   3d8c8:	lea    -0x6(%rdx),%eax
   3d8cb:	cmp    $0xffffffff,%eax
   3d8ce:	je     3d985 <strtold+0x1e25>
   3d8d4:	movslq %eax,%rcx
   3d8d7:	cmpq   $0x0,0xa0(%rsp,%rcx,8)
   3d8e0:	jne    3d985 <strtold+0x1e25>
   3d8e6:	lea    -0x7(%rdx),%eax
   3d8e9:	cmp    $0xffffffff,%eax
   3d8ec:	je     3d985 <strtold+0x1e25>
   3d8f2:	movslq %eax,%rcx
   3d8f5:	cmpq   $0x0,0xa0(%rsp,%rcx,8)
   3d8fe:	jne    3d985 <strtold+0x1e25>
   3d904:	lea    -0x8(%rdx),%eax
   3d907:	cmp    $0xffffffff,%eax
   3d90a:	je     3d985 <strtold+0x1e25>
   3d90c:	movslq %eax,%rcx
   3d90f:	cmpq   $0x0,0xa0(%rsp,%rcx,8)
   3d918:	jne    3d985 <strtold+0x1e25>
   3d91a:	lea    -0x9(%rdx),%eax
   3d91d:	cmp    $0xffffffff,%eax
   3d920:	je     3d985 <strtold+0x1e25>
   3d922:	movslq %eax,%rcx
   3d925:	cmpq   $0x0,0xa0(%rsp,%rcx,8)
   3d92e:	jne    3d985 <strtold+0x1e25>
   3d930:	sub    $0xa,%edx
   3d933:	cmp    $0xffffffff,%edx
   3d936:	je     3d94b <strtold+0x1deb>
   3d938:	movslq %edx,%rax
   3d93b:	cmpq   $0x0,0xa0(%rsp,%rax,8)
   3d944:	jne    3d983 <strtold+0x1e23>
   3d946:	mov    $0xffffffff,%edx
   3d94b:	not    %edx
   3d94d:	mov    $0x3f,%r8d
   3d953:	sub    0x8(%rsp),%r8d
   3d958:	mov    %edx,%r9d
   3d95b:	sub    $0x1,%rsi
   3d95f:	shr    $0x1f,%r9d
   3d963:	or     0x28(%rsp),%r9b
   3d968:	mov    0x10(%rsp),%edx
   3d96c:	and    $0x1,%r9d
   3d970:	movslq %r8d,%r8
   3d973:	mov    %rbx,%rcx
   3d976:	mov    %r12,%rdi
   3d979:	callq  3be60 <strtold+0x300>
   3d97e:	jmpq   3c4cf <strtold+0x96f>
   3d983:	mov    %edx,%eax
   3d985:	mov    %eax,%edx
   3d987:	jmp    3d94b <strtold+0x1deb>
   3d989:	jne    3e891 <strtold+0x2d31>
   3d98f:	test   %r15d,%r15d
   3d992:	jle    3e8c5 <strtold+0x2d65>
   3d998:	lea    -0x1(%r15),%r12d
   3d99c:	mov    %r14,%rcx
   3d99f:	mov    %r8,0x20(%rsp)
   3d9a4:	mov    %r9,0x8(%rsp)
   3d9a9:	movslq %r12d,%rax
   3d9ac:	lea    0x8(,%rax,8),%rdx
   3d9b4:	movslq %r15d,%rax
   3d9b7:	shl    $0x3,%rax
   3d9bb:	sub    %rdx,%rcx
   3d9be:	lea    0x8(%rcx,%rax,1),%rdi
   3d9c3:	sub    %rdx,%rax
   3d9c6:	lea    (%r14,%rax,1),%rsi
   3d9ca:	callq  8efb0 <memcmp+0x440>
   3d9cf:	mov    0x8(%rsp),%r9
   3d9d4:	mov    0x20(%rsp),%r8
   3d9d9:	movq   $0x0,0xa0(%rsp)
   3d9e5:	mov    0xa0(%rsp,%r15,8),%rcx
   3d9ed:	movq   $0x0,0xf0(%rsp,%r15,8)
   3d9f9:	movl   $0x0,0x8(%rsp)
   3da01:	lea    -0x3(%r15),%edi
   3da05:	lea    0x1(%r15),%rax
   3da09:	mov    %r12d,0x7c(%rsp)
   3da0e:	mov    %r14,0x20(%rsp)
   3da13:	mov    %ebp,%r14d
   3da16:	mov    %r8,%rbp
   3da19:	mov    %edi,0x40(%rsp)
   3da1d:	lea    -0x4(%r15),%edi
   3da21:	mov    %rax,0x60(%rsp)
   3da26:	lea    -0x2(%r15),%eax
   3da2a:	mov    %edi,0x48(%rsp)
   3da2e:	lea    -0x5(%r15),%edi
   3da32:	mov    %eax,0x3c(%rsp)
   3da36:	movslq %eax,%r10
   3da39:	movslq %r12d,%rax
   3da3c:	mov    %edi,0x4c(%rsp)
   3da40:	lea    -0x6(%r15),%edi
   3da44:	mov    %rax,0x68(%rsp)
   3da49:	lea    -0xa(%r12),%eax
   3da4e:	mov    %r9,%r12
   3da51:	mov    %edi,0x50(%rsp)
   3da55:	lea    -0x7(%r15),%edi
   3da59:	cltq   
   3da5b:	mov    %edi,0x54(%rsp)
   3da5f:	lea    -0x8(%r15),%edi
   3da63:	mov    %rax,0x70(%rsp)
   3da68:	mov    %edi,0x58(%rsp)
   3da6c:	lea    -0x9(%r15),%edi
   3da70:	mov    %edi,0x5c(%rsp)
   3da74:	lea    -0xa(%r15),%edi
   3da78:	mov    %edi,0x78(%rsp)
   3da7c:	cmp    %r13,%rcx
   3da7f:	mov    $0xffffffffffffffff,%rbx
   3da86:	je     3dad9 <strtold+0x1f79>
   3da88:	mov    0x18(%rsp),%rax
   3da8d:	mov    %rcx,%rdx
   3da90:	mov    0xa0(%rsp,%rax,8),%rax
   3da98:	mov    %rax,0x30(%rsp)
   3da9d:	div    %r13
   3daa0:	mov    %rax,%rbx
   3daa3:	mov    %rdx,%rcx
   3daa6:	mov    %rbp,%rax
   3daa9:	mul    %rbx
   3daac:	jmp    3dabf <strtold+0x1f5f>
   3daae:	xchg   %ax,%ax
   3dab0:	xor    %esi,%esi
   3dab2:	cmp    %rbp,%rax
   3dab5:	setb   %sil
   3dab9:	sub    %rbp,%rax
   3dabc:	sub    %rsi,%rdx
   3dabf:	cmp    %rcx,%rdx
   3dac2:	ja     3dad0 <strtold+0x1f70>
   3dac4:	jne    3dad9 <strtold+0x1f79>
   3dac6:	cmp    0xa0(%rsp,%r12,8),%rax
   3dace:	jbe    3dad9 <strtold+0x1f79>
   3dad0:	sub    $0x1,%rbx
   3dad4:	add    %r13,%rcx
   3dad7:	jae    3dab0 <strtold+0x1f50>
   3dad9:	mov    0x60(%rsp),%rdx
   3dade:	mov    (%rsp),%rsi
   3dae2:	mov    %rbx,%rcx
   3dae5:	mov    0x20(%rsp),%rdi
   3daea:	mov    %r10,0x30(%rsp)
   3daef:	callq  48f50 <swapcontext+0x20d0>
   3daf4:	cmp    %rax,0xa0(%rsp,%r15,8)
   3dafc:	mov    0x30(%rsp),%r10
   3db01:	je     3db29 <strtold+0x1fc9>
   3db03:	mov    0x20(%rsp),%rdi
   3db08:	mov    (%rsp),%rdx
   3db0c:	mov    %r15,%rcx
   3db0f:	mov    %rdi,%rsi
   3db12:	callq  472b0 <swapcontext+0x430>
   3db17:	test   %rax,%rax
   3db1a:	mov    0x30(%rsp),%r10
   3db1f:	je     3e8ce <strtold+0x2d6e>
   3db25:	sub    $0x1,%rbx
   3db29:	mov    0x18(%rsp),%rax
   3db2e:	mov    0x7c(%rsp),%edx
   3db32:	mov    0xa0(%rsp,%rax,8),%rcx
   3db3a:	test   %edx,%edx
   3db3c:	mov    %rcx,0xa0(%rsp,%r15,8)
   3db44:	jle    3dc5e <strtold+0x20fe>
   3db4a:	mov    0xa0(%rsp,%r10,8),%rax
   3db52:	mov    0x68(%rsp),%rdi
   3db57:	mov    %rax,0xa0(%rsp,%rdi,8)
   3db5f:	mov    0x3c(%rsp),%eax
   3db63:	test   %eax,%eax
   3db65:	je     3dc5e <strtold+0x20fe>
   3db6b:	mov    0x40(%rsp),%edi
   3db6f:	movslq %edi,%rdx
   3db72:	test   %edi,%edi
   3db74:	mov    0xa0(%rsp,%rdx,8),%rax
   3db7c:	mov    %rax,0xa0(%rsp,%r10,8)
   3db84:	jle    3dc5e <strtold+0x20fe>
   3db8a:	mov    0x48(%rsp),%edi
   3db8e:	movslq %edi,%rax
   3db91:	test   %edi,%edi
   3db93:	mov    0xa0(%rsp,%rax,8),%rsi
   3db9b:	mov    %rsi,0xa0(%rsp,%rdx,8)
   3dba3:	jle    3dc5e <strtold+0x20fe>
   3dba9:	movslq 0x4c(%rsp),%rdx
   3dbae:	mov    0xa0(%rsp,%rdx,8),%rsi
   3dbb6:	test   %edx,%edx
   3dbb8:	mov    %rsi,0xa0(%rsp,%rax,8)
   3dbc0:	jle    3dc5e <strtold+0x20fe>
   3dbc6:	mov    0x50(%rsp),%edi
   3dbca:	movslq %edi,%rax
   3dbcd:	test   %edi,%edi
   3dbcf:	mov    0xa0(%rsp,%rax,8),%rsi
   3dbd7:	mov    %rsi,0xa0(%rsp,%rdx,8)
   3dbdf:	jle    3dc5e <strtold+0x20fe>
   3dbe1:	movslq 0x54(%rsp),%rdx
   3dbe6:	mov    0xa0(%rsp,%rdx,8),%rsi
   3dbee:	test   %edx,%edx
   3dbf0:	mov    %rsi,0xa0(%rsp,%rax,8)
   3dbf8:	jle    3dc5e <strtold+0x20fe>
   3dbfa:	mov    0x58(%rsp),%edi
   3dbfe:	movslq %edi,%rax
   3dc01:	test   %edi,%edi
   3dc03:	mov    0xa0(%rsp,%rax,8),%rsi
   3dc0b:	mov    %rsi,0xa0(%rsp,%rdx,8)
   3dc13:	jle    3dc5e <strtold+0x20fe>
   3dc15:	movslq 0x5c(%rsp),%rdx
   3dc1a:	mov    0xa0(%rsp,%rdx,8),%rsi
   3dc22:	test   %edx,%edx
   3dc24:	mov    %rsi,0xa0(%rsp,%rax,8)
   3dc2c:	jle    3dc5e <strtold+0x20fe>
   3dc2e:	mov    0x78(%rsp),%edi
   3dc32:	movslq %edi,%rax
   3dc35:	test   %edi,%edi
   3dc37:	mov    0xa0(%rsp,%rax,8),%rsi
   3dc3f:	mov    %rsi,0xa0(%rsp,%rdx,8)
   3dc47:	jle    3dc5e <strtold+0x20fe>
   3dc49:	mov    0x70(%rsp),%rdi
   3dc4e:	mov    0xa0(%rsp,%rdi,8),%rdx
   3dc56:	mov    %rdx,0xa0(%rsp,%rax,8)
   3dc5e:	test   %r14d,%r14d
   3dc61:	movq   $0x0,0xa0(%rsp)
   3dc6d:	jne    3dcd3 <strtold+0x2173>
   3dc6f:	test   %rbx,%rbx
   3dc72:	je     3dcea <strtold+0x218a>
   3dc74:	bsr    %rbx,%rax
   3dc78:	mov    0x98(%rsp),%rdi
   3dc80:	mov    $0x40,%r8d
   3dc86:	xor    $0x3f,%rax
   3dc8a:	movslq %eax,%rsi
   3dc8d:	sub    %eax,%r8d
   3dc90:	mov    %eax,%edx
   3dc92:	sub    %rsi,%rdi
   3dc95:	cmp    $0x18,%r8d
   3dc99:	mov    %rdi,%rsi
   3dc9c:	mov    %rdi,0x98(%rsp)
   3dca4:	jle    3e8ed <strtold+0x2d8d>
   3dcaa:	lea    0x18(%rax),%eax
   3dcad:	mov    $0x28,%ecx
   3dcb2:	lea    0x80(%rsp),%r12
   3dcba:	sub    %edx,%ecx
   3dcbc:	mov    %eax,0x8(%rsp)
   3dcc0:	mov    %rbx,%rax
   3dcc3:	shr    %cl,%rax
   3dcc6:	mov    %rax,0x80(%rsp)
   3dcce:	jmpq   3d814 <strtold+0x1cb4>
   3dcd3:	cmp    $0xffffffd9,%r14d
   3dcd7:	jge    3dd20 <strtold+0x21c0>
   3dcd9:	mov    %rbx,0x80(%rsp)
   3dce1:	add    $0x40,%r14d
   3dce5:	jmpq   3da7c <strtold+0x1f1c>
   3dcea:	subq   $0x40,0x98(%rsp)
   3dcf3:	cmp    $0x18,%r14d
   3dcf7:	mov    %rbx,0x80(%rsp)
   3dcff:	jle    3da7c <strtold+0x1f1c>
   3dd05:	lea    0x80(%rsp),%r12
   3dd0d:	mov    0x98(%rsp),%rsi
   3dd15:	jmpq   3d814 <strtold+0x1cb4>
   3dd1a:	nopw   0x0(%rax,%rax,1)
   3dd20:	mov    $0x18,%eax
   3dd25:	sub    %r14d,%eax
   3dd28:	mov    %eax,0x8(%rsp)
   3dd2c:	je     3dd05 <strtold+0x21a5>
   3dd2e:	lea    0x80(%rsp),%r12
   3dd36:	mov    %eax,%ecx
   3dd38:	mov    $0x1,%edx
   3dd3d:	mov    %eax,%r14d
   3dd40:	mov    %r12,%rsi
   3dd43:	mov    %r12,%rdi
   3dd46:	callq  47940 <swapcontext+0xac0>
   3dd4b:	mov    $0x40,%ecx
   3dd50:	mov    %rbx,%rax
   3dd53:	sub    %r14d,%ecx
   3dd56:	shr    %cl,%rax
   3dd59:	or     %rax,0x80(%rsp)
   3dd61:	jmp    3dd0d <strtold+0x21ad>
   3dd63:	cmp    $0x1,%rdx
   3dd67:	mov    0xa0(%rsp),%rcx
   3dd6f:	mov    0xf0(%rsp),%rsi
   3dd77:	jne    3e7c7 <strtold+0x2c67>
   3dd7d:	cmp    %rsi,%rcx
   3dd80:	jae    3e7c7 <strtold+0x2c67>
   3dd86:	xor    %r13d,%r13d
   3dd89:	xor    %r9d,%r9d
   3dd8c:	mov    $0x40,%r8d
   3dd92:	mov    %rcx,%rdx
   3dd95:	mov    %r9,%rax
   3dd98:	div    %rsi
   3dd9b:	test   %ebp,%ebp
   3dd9d:	mov    %rax,%rbx
   3dda0:	mov    %rdx,%rcx
   3dda3:	jne    3de1d <strtold+0x22bd>
   3dda5:	test   %rax,%rax
   3dda8:	je     3de32 <strtold+0x22d2>
   3ddae:	bsr    %rax,%r10
   3ddb2:	mov    0x98(%rsp),%r15
   3ddba:	mov    %r8d,%ebp
   3ddbd:	xor    $0x3f,%r10
   3ddc1:	movslq %r10d,%rax
   3ddc4:	sub    %r10d,%ebp
   3ddc7:	sub    %rax,%r15
   3ddca:	cmp    $0x18,%ebp
   3ddcd:	mov    %r15,%rax
   3ddd0:	mov    %r15,0x98(%rsp)
   3ddd8:	jle    3de3b <strtold+0x22db>
   3ddda:	mov    $0x28,%ecx
   3dddf:	mov    %rdx,%r14
   3dde2:	mov    %rbx,%rdx
   3dde5:	sub    %r10d,%ecx
   3dde8:	lea    0x18(%r10),%r13d
   3ddec:	lea    0x80(%rsp),%r12
   3ddf4:	shr    %cl,%rdx
   3ddf7:	mov    %rdx,0x80(%rsp)
   3ddff:	test   %r14,%r14
   3de02:	mov    $0x3f,%r8d
   3de08:	lea    -0x1(%rax),%rsi
   3de0c:	setne  %r9b
   3de10:	sub    %r13d,%r8d
   3de13:	or     0x28(%rsp),%r9b
   3de18:	jmpq   3d968 <strtold+0x1e08>
   3de1d:	cmp    $0xffffffd9,%ebp
   3de20:	jge    3de68 <strtold+0x2308>
   3de22:	mov    %rax,0x80(%rsp)
   3de2a:	add    $0x40,%ebp
   3de2d:	jmpq   3dd92 <strtold+0x2232>
   3de32:	subq   $0x40,0x98(%rsp)
   3de3b:	cmp    $0x18,%ebp
   3de3e:	mov    %rbx,0x80(%rsp)
   3de46:	jle    3dd92 <strtold+0x2232>
   3de4c:	lea    0x80(%rsp),%r12
   3de54:	mov    %rdx,%r14
   3de57:	mov    0x98(%rsp),%rax
   3de5f:	jmp    3ddff <strtold+0x229f>
   3de61:	nopl   0x0(%rax)
   3de68:	mov    $0x18,%r13d
   3de6e:	mov    %rdx,%r14
   3de71:	lea    0x80(%rsp),%r12
   3de79:	sub    %ebp,%r13d
   3de7c:	je     3de57 <strtold+0x22f7>
   3de7e:	mov    %r13d,%ecx
   3de81:	mov    $0x1,%edx
   3de86:	mov    %r12,%rsi
   3de89:	mov    %r12,%rdi
   3de8c:	callq  47940 <swapcontext+0xac0>
   3de91:	mov    $0x40,%ecx
   3de96:	mov    %rbx,%rax
   3de99:	sub    %r13d,%ecx
   3de9c:	shr    %cl,%rax
   3de9f:	or     %rax,0x80(%rsp)
   3dea7:	jmp    3de57 <strtold+0x22f7>
   3dea9:	lea    0x80(%rsp),%r12
   3deb1:	xor    %r8d,%r8d
   3deb4:	xor    %r9d,%r9d
   3deb7:	mov    %r14,%rdi
   3deba:	xor    %ecx,%ecx
   3debc:	mov    $0x40,%r10d
   3dec2:	neg    %rdi
   3dec5:	mov    %r9,%rsi
   3dec8:	cmp    %r15,%rsi
   3decb:	je     3df88 <strtold+0x2428>
   3ded1:	mov    %rsi,%rdx
   3ded4:	mov    %rbx,%rax
   3ded7:	div    %r15
   3deda:	mov    %rax,%r13
   3dedd:	mov    %rdx,%rsi
   3dee0:	mov    %r14,%rax
   3dee3:	mul    %r13
   3dee6:	nopw   %cs:0x0(%rax,%rax,1)
   3def0:	cmp    %rsi,%rdx
   3def3:	ja     3deff <strtold+0x239f>
   3def5:	test   %rax,%rax
   3def8:	je     3df0f <strtold+0x23af>
   3defa:	cmp    %rsi,%rdx
   3defd:	jne    3df0f <strtold+0x23af>
   3deff:	sub    $0x1,%r13
   3df03:	sub    %r14,%rax
   3df06:	sbb    $0x0,%rdx
   3df0a:	add    %r15,%rsi
   3df0d:	jae    3def0 <strtold+0x2390>
   3df0f:	mov    %rcx,%rbx
   3df12:	sub    %rax,%rbx
   3df15:	sbb    %rdx,%rsi
   3df18:	test   %ebp,%ebp
   3df1a:	jne    3dfad <strtold+0x244d>
   3df20:	test   %r13,%r13
   3df23:	je     3e028 <strtold+0x24c8>
   3df29:	bsr    %r13,%r9
   3df2d:	mov    0x98(%rsp),%r11
   3df35:	mov    %r10d,%ebp
   3df38:	xor    $0x3f,%r9
   3df3c:	movslq %r9d,%rax
   3df3f:	sub    %r9d,%ebp
   3df42:	mov    %r9d,%edx
   3df45:	sub    %rax,%r11
   3df48:	cmp    $0x18,%ebp
   3df4b:	mov    %r11,%rax
   3df4e:	mov    %r11,0x98(%rsp)
   3df56:	jle    3e031 <strtold+0x24d1>
   3df5c:	mov    $0x28,%ecx
   3df61:	mov    %r13,%rdi
   3df64:	mov    $0x27,%r8d
   3df6a:	sub    %edx,%ecx
   3df6c:	sub    %edx,%r8d
   3df6f:	mov    %rsi,%r9
   3df72:	shr    %cl,%rdi
   3df75:	movslq %r8d,%r8
   3df78:	mov    %rdi,%rcx
   3df7b:	mov    %rcx,0x80(%rsp)
   3df83:	jmpq   3d416 <strtold+0x18b6>
   3df88:	add    %rbx,%rsi
   3df8b:	jae    3e050 <strtold+0x24f0>
   3df91:	sub    %r14,%rsi
   3df94:	mov    %rcx,%rbx
   3df97:	add    %r14,%rbx
   3df9a:	adc    $0x0,%rsi
   3df9e:	test   %ebp,%ebp
   3dfa0:	je     3e06d <strtold+0x250d>
   3dfa6:	mov    $0xffffffffffffffff,%r13
   3dfad:	cmp    $0xffffffd9,%ebp
   3dfb0:	jge    3dfc2 <strtold+0x2462>
   3dfb2:	mov    %r13,0x80(%rsp)
   3dfba:	add    $0x40,%ebp
   3dfbd:	jmpq   3dec8 <strtold+0x2368>
   3dfc2:	mov    $0x18,%r8d
   3dfc8:	mov    %rsi,%r9
   3dfcb:	sub    %ebp,%r8d
   3dfce:	je     3e00b <strtold+0x24ab>
   3dfd0:	mov    %r8d,%ecx
   3dfd3:	mov    %rsi,0x8(%rsp)
   3dfd8:	mov    $0x1,%edx
   3dfdd:	mov    %r12,%rsi
   3dfe0:	mov    %r12,%rdi
   3dfe3:	mov    %r8d,(%rsp)
   3dfe7:	callq  47940 <swapcontext+0xac0>
   3dfec:	mov    (%rsp),%r8d
   3dff0:	mov    $0x40,%ecx
   3dff5:	mov    %r13,%rax
   3dff8:	mov    0x8(%rsp),%r9
   3dffd:	sub    %r8d,%ecx
   3e000:	shr    %cl,%rax
   3e003:	or     %rax,0x80(%rsp)
   3e00b:	mov    $0x3f,%eax
   3e010:	sub    %r8d,%eax
   3e013:	movslq %eax,%r8
   3e016:	mov    0x98(%rsp),%rax
   3e01e:	jmpq   3d416 <strtold+0x18b6>
   3e023:	nopl   0x0(%rax,%rax,1)
   3e028:	subq   $0x40,0x98(%rsp)
   3e031:	cmp    $0x18,%ebp
   3e034:	mov    %r13,0x80(%rsp)
   3e03c:	jle    3dec8 <strtold+0x2368>
   3e042:	mov    %rsi,%r9
   3e045:	jmp    3e00b <strtold+0x24ab>
   3e047:	nopw   0x0(%rax,%rax,1)
   3e050:	xor    %eax,%eax
   3e052:	test   %r14,%r14
   3e055:	mov    %r14,%rdx
   3e058:	setne  %al
   3e05b:	mov    $0xffffffffffffffff,%r13
   3e062:	sub    %rax,%rdx
   3e065:	mov    %rdi,%rax
   3e068:	jmpq   3def0 <strtold+0x2390>
   3e06d:	mov    %rsi,%r9
   3e070:	mov    0x98(%rsp),%rax
   3e078:	mov    $0x27,%r8d
   3e07e:	mov    $0xffffff,%ecx
   3e083:	mov    $0xffffffffffffffff,%r13
   3e08a:	jmpq   3df7b <strtold+0x241b>
   3e08f:	mov    0xa8(%rsp),%r9
   3e097:	mov    0xa0(%rsp),%rbx
   3e09f:	xor    %r8d,%r8d
   3e0a2:	lea    0x80(%rsp),%r12
   3e0aa:	jmpq   3deb7 <strtold+0x2357>
   3e0af:	mov    %r12d,%edx
   3e0b2:	mov    %rax,%r10
   3e0b5:	mov    %rax,%r13
   3e0b8:	xor    %ecx,%ecx
   3e0ba:	mov    $0x10,%r9d
   3e0c0:	jmpq   3c538 <strtold+0x9d8>
   3e0c5:	test   %r15,%r15
   3e0c8:	jne    3e779 <strtold+0x2c19>
   3e0ce:	cmpb   $0x30,0x0(%r13)
   3e0d3:	je     3e779 <strtold+0x2c19>
   3e0d9:	mov    $0x1,%eax
   3e0de:	movabs $0x5555555555555556,%rdx
   3e0e8:	sub    %rcx,%rax
   3e0eb:	lea    (%rax,%rax,4),%rsi
   3e0ef:	add    %rsi,%rsi
   3e0f2:	mov    %rsi,%rax
   3e0f5:	sar    $0x3f,%rsi
   3e0f9:	imul   %rdx
   3e0fc:	mov    %rdx,%rax
   3e0ff:	mov    %ecx,%edx
   3e101:	sub    %rsi,%rax
   3e104:	mov    $0x97,%esi
   3e109:	add    $0x19,%eax
   3e10c:	cmp    $0x97,%eax
   3e111:	cmovg  %esi,%eax
   3e114:	add    %ecx,%eax
   3e116:	test   %eax,%eax
   3e118:	jg     3ccaa <strtold+0x114a>
   3e11e:	lea    0x1568fb(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3e125:	lea    0x14e2a3(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3e12c:	lea    0x14e236(%rip),%rdi        # 18c369 <_libc_intl_domainname+0x140>
   3e133:	mov    $0x574,%edx
   3e138:	callq  2e0b0 <__assert_fail>
   3e13d:	nopl   (%rax)
   3e140:	mov    %r10,(%rsp)
   3e144:	sub    $0x8,%rsp
   3e148:	mov    %r13,%rdi
   3e14b:	lea    0x98(%rsp),%rcx
   3e153:	lea    0xa8(%rsp),%r14
   3e15b:	push   %rbx
   3e15c:	mov    0x30(%rsp),%r9
   3e161:	mov    %r15d,%esi
   3e164:	lea    0xa8(%rsp),%r8
   3e16c:	mov    %r14,%rdx
   3e16f:	callq  3bb80 <strtold+0x20>
   3e174:	mov    %rax,%r13
   3e177:	mov    0xa8(%rsp),%rax
   3e17f:	pop    %rdi
   3e180:	pop    %r8
   3e182:	test   %rax,%rax
   3e185:	mov    0x90(%rsp),%r9
   3e18d:	mov    (%rsp),%r10
   3e191:	jle    3e27e <strtold+0x271e>
   3e197:	lea    0xf0(%rsp),%rdi
   3e19f:	lea    0x143b1a(%rip),%r12        # 181cc0 <__libc_thread_freeres+0xdda0>
   3e1a6:	mov    %rbx,0x30(%rsp)
   3e1ab:	movl   $0x1,0x8(%rsp)
   3e1b3:	mov    %r13,0x18(%rsp)
   3e1b8:	mov    %r14,%rbx
   3e1bb:	mov    %rdi,(%rsp)
   3e1bf:	mov    %rdi,%rbp
   3e1c2:	mov    %r10,0x28(%rsp)
   3e1c7:	mov    %r9,%rdx
   3e1ca:	movslq 0x8(%rsp),%rcx
   3e1cf:	test   %rax,%rcx
   3e1d2:	je     3e3a8 <strtold+0x2848>
   3e1d8:	mov    0x8(%r12),%rdi
   3e1dd:	xor    %rcx,%rax
   3e1e0:	mov    %rax,0x98(%rsp)
   3e1e8:	mov    (%r12),%rax
   3e1ec:	lea    -0x1(%rdi),%r13
   3e1f0:	cmp    %rdx,%r13
   3e1f3:	jg     3e3b5 <strtold+0x2855>
   3e1f9:	lea    0x8(,%rax,8),%rcx
   3e201:	lea    0x143c38(%rip),%rax        # 181e40 <__libc_thread_freeres+0xdf20>
   3e208:	mov    %r13,%r8
   3e20b:	mov    %rbx,%rsi
   3e20e:	mov    %rbp,%rdi
   3e211:	add    %rax,%rcx
   3e214:	callq  47bb0 <swapcontext+0xd30>
   3e219:	mov    %r13,%rdx
   3e21c:	add    0x90(%rsp),%rdx
   3e224:	test   %rax,%rax
   3e227:	mov    %rdx,0x90(%rsp)
   3e22f:	jne    3e23d <strtold+0x26dd>
   3e231:	sub    $0x1,%rdx
   3e235:	mov    %rdx,0x90(%rsp)
   3e23d:	mov    0x98(%rsp),%rax
   3e245:	mov    %rbx,%rcx
   3e248:	shll   0x8(%rsp)
   3e24c:	add    $0x18,%r12
   3e250:	mov    %rbp,%rbx
   3e253:	mov    %rcx,%rbp
   3e256:	test   %rax,%rax
   3e259:	jne    3e1ca <strtold+0x266a>
   3e25f:	mov    %rbx,%r11
   3e262:	cmp    (%rsp),%r11
   3e266:	mov    0x18(%rsp),%r13
   3e26b:	mov    0x28(%rsp),%r10
   3e270:	mov    0x30(%rsp),%rbx
   3e275:	mov    %rdx,%r9
   3e278:	je     3e50c <strtold+0x29ac>
   3e27e:	lea    -0x1(%r9),%rcx
   3e282:	mov    %r9d,%edx
   3e285:	shl    $0x6,%edx
   3e288:	bsr    0xa0(%rsp,%rcx,8),%rax
   3e291:	xor    $0x3f,%rax
   3e295:	sub    %eax,%edx
   3e297:	cmp    $0x80,%edx
   3e29d:	mov    %edx,%ebp
   3e29f:	jg     3ca0a <strtold+0xeaa>
   3e2a5:	cmp    $0x18,%edx
   3e2a8:	jle    3e5bc <strtold+0x2a5c>
   3e2ae:	lea    -0x18(%rdx),%edi
   3e2b1:	mov    %edi,%eax
   3e2b3:	and    $0x3f,%edi
   3e2b6:	sar    $0x6,%eax
   3e2b9:	test   %edi,%edi
   3e2bb:	movslq %edi,%r8
   3e2be:	movslq %eax,%rsi
   3e2c1:	jne    3e566 <strtold+0x2a06>
   3e2c7:	mov    0xa0(%rsp,%rsi,8),%rax
   3e2cf:	lea    -0x1(%rsi),%rcx
   3e2d3:	mov    $0x3f,%r8d
   3e2d9:	mov    %rax,0x80(%rsp)
   3e2e1:	cmpq   $0x0,0xa0(%rsp)
   3e2ea:	jne    3e55f <strtold+0x29ff>
   3e2f0:	cmpq   $0x0,0xa8(%rsp)
   3e2f9:	jne    3e555 <strtold+0x29f5>
   3e2ff:	cmpq   $0x0,0xb0(%rsp)
   3e308:	jne    3e823 <strtold+0x2cc3>
   3e30e:	cmpq   $0x0,0xb8(%rsp)
   3e317:	jne    3e819 <strtold+0x2cb9>
   3e31d:	cmpq   $0x0,0xc0(%rsp)
   3e326:	jne    3e80f <strtold+0x2caf>
   3e32c:	cmpq   $0x0,0xc8(%rsp)
   3e335:	jne    3e805 <strtold+0x2ca5>
   3e33b:	cmpq   $0x0,0xd0(%rsp)
   3e344:	jne    3e502 <strtold+0x29a2>
   3e34a:	cmpq   $0x0,0xd8(%rsp)
   3e353:	jne    3e4f8 <strtold+0x2998>
   3e359:	cmpq   $0x1,0xe0(%rsp)
   3e362:	sbb    %eax,%eax
   3e364:	not    %eax
   3e366:	add    $0x9,%eax
   3e369:	cmp    %r15,%r10
   3e36c:	mov    $0x1,%r9d
   3e372:	ja     3e380 <strtold+0x2820>
   3e374:	cltq   
   3e376:	xor    %r9d,%r9d
   3e379:	cmp    %rax,%rcx
   3e37c:	setg   %r9b
   3e380:	sub    $0x1,%edx
   3e383:	mov    0xa0(%rsp,%rcx,8),%rcx
   3e38b:	lea    0x80(%rsp),%rdi
   3e393:	movslq %edx,%rsi
   3e396:	mov    0x10(%rsp),%edx
   3e39a:	callq  3be60 <strtold+0x300>
   3e39f:	jmpq   3c4cf <strtold+0x96f>
   3e3a4:	nopl   0x0(%rax)
   3e3a8:	shll   0x8(%rsp)
   3e3ac:	add    $0x18,%r12
   3e3b0:	jmpq   3e1ca <strtold+0x266a>
   3e3b5:	lea    0x8(,%rax,8),%rsi
   3e3bd:	lea    0x143a7c(%rip),%rax        # 181e40 <__libc_thread_freeres+0xdf20>
   3e3c4:	mov    %rdx,%r8
   3e3c7:	mov    %rbx,%rcx
   3e3ca:	mov    %r13,%rdx
   3e3cd:	mov    %rbp,%rdi
   3e3d0:	add    %rax,%rsi
   3e3d3:	callq  47bb0 <swapcontext+0xd30>
   3e3d8:	jmpq   3e219 <strtold+0x26b9>
   3e3dd:	mov    %r15,%rdx
   3e3e0:	sub    %rdi,%rdx
   3e3e3:	jmp    3e40c <strtold+0x28ac>
   3e3e5:	nopl   (%rax)
   3e3e8:	cmp    $0xffffffffffffffff,%rcx
   3e3ec:	jne    3e403 <strtold+0x28a3>
   3e3ee:	cmp    $0x30,%r12b
   3e3f2:	mov    %rbp,%rax
   3e3f5:	setne  %sil
   3e3f9:	sub    %rdi,%rax
   3e3fc:	test   %sil,%sil
   3e3ff:	cmovne %rax,%rcx
   3e403:	add    $0x1,%rbp
   3e407:	movsbq 0x0(%rbp),%r12
   3e40c:	lea    -0x30(%r12),%eax
   3e411:	lea    0x0(%rbp,%rdx,1),%r10
   3e416:	cmp    $0x9,%al
   3e418:	ja     3c710 <strtold+0xbb0>
   3e41e:	jmp    3e3e8 <strtold+0x2888>
   3e420:	mov    0x70(%r8),%rsi
   3e424:	mov    %rcx,%rbx
   3e427:	add    $0x1,%rbx
   3e42b:	movzbl (%rbx),%eax
   3e42e:	lea    -0x30(%rax),%edx
   3e431:	cmp    $0x9,%dl
   3e434:	jbe    3e427 <strtold+0x28c7>
   3e436:	movsbq %al,%rdx
   3e43a:	mov    (%rsi,%rdx,4),%edx
   3e43d:	sub    $0x61,%edx
   3e440:	cmp    $0x19,%dl
   3e443:	jbe    3e427 <strtold+0x28c7>
   3e445:	cmp    $0x5f,%al
   3e447:	je     3e427 <strtold+0x28c7>
   3e449:	cmp    $0x29,%al
   3e44b:	movss  0x157809(%rip),%xmm0        # 195c5c <in6addr_loopback+0xbcc>
   3e453:	jne    3d0a1 <strtold+0x1541>
   3e459:	lea    0xf0(%rsp),%rsi
   3e461:	lea    0x4(%r10),%rdi
   3e465:	xor    %ecx,%ecx
   3e467:	xor    %edx,%edx
   3e469:	movss  %xmm0,0x8(%rsp)
   3e46f:	callq  3b670 <__strtol_l+0x10>
   3e474:	cmp    %rbx,0xf0(%rsp)
   3e47c:	movss  0x8(%rsp),%xmm0
   3e482:	je     3e4db <strtold+0x297b>
   3e484:	lea    0x1(%rbx),%rcx
   3e488:	jmpq   3d0a1 <strtold+0x1541>
   3e48d:	mov    0x18(%rsp),%rax
   3e492:	movabs $0x6666666666666667,%rdx
   3e49c:	imul   %rdx
   3e49f:	mov    0x18(%rsp),%rax
   3e4a4:	sar    $0x3f,%rax
   3e4a8:	sar    $0x2,%rdx
   3e4ac:	sub    %rax,%rdx
   3e4af:	mov    0x18(%rsp),%rax
   3e4b4:	mov    %rdx,%r12
   3e4b7:	jmpq   3c7c6 <strtold+0xc66>
   3e4bc:	lea    0x15655d(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3e4c3:	lea    0x14df05(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3e4ca:	lea    0x151dbf(%rip),%rdi        # 190290 <_libc_intl_domainname+0x4067>
   3e4d1:	mov    $0x3ba,%edx
   3e4d6:	callq  2e0b0 <__assert_fail>
   3e4db:	and    $0x3fffff,%eax
   3e4e0:	or     $0x7fc00000,%eax
   3e4e5:	test   $0x7fffff,%eax
   3e4ea:	je     3e484 <strtold+0x2924>
   3e4ec:	mov    %eax,0x8(%rsp)
   3e4f0:	movss  0x8(%rsp),%xmm0
   3e4f6:	jmp    3e484 <strtold+0x2924>
   3e4f8:	mov    $0x7,%eax
   3e4fd:	jmpq   3e369 <strtold+0x2809>
   3e502:	mov    $0x6,%eax
   3e507:	jmpq   3e369 <strtold+0x2809>
   3e50c:	lea    0x0(,%rdx,8),%rdx
   3e514:	mov    %r11,%rsi
   3e517:	mov    %r14,%rdi
   3e51a:	mov    %r10,0x8(%rsp)
   3e51f:	mov    %r9,(%rsp)
   3e523:	callq  943f0 <memcpy+0x70>
   3e528:	mov    0x8(%rsp),%r10
   3e52d:	mov    (%rsp),%r9
   3e531:	jmpq   3e27e <strtold+0x271e>
   3e536:	lea    0x1564e3(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3e53d:	lea    0x14de8b(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3e544:	lea    0x14dde4(%rip),%rdi        # 18c32f <_libc_intl_domainname+0x106>
   3e54b:	mov    $0x559,%edx
   3e550:	callq  2e0b0 <__assert_fail>
   3e555:	mov    $0x1,%eax
   3e55a:	jmpq   3e369 <strtold+0x2809>
   3e55f:	xor    %eax,%eax
   3e561:	jmpq   3e369 <strtold+0x2809>
   3e566:	sub    $0x1,%r8
   3e56a:	cmp    %rsi,%rcx
   3e56d:	jle    3e649 <strtold+0x2ae9>
   3e573:	add    $0x1,%eax
   3e576:	mov    $0x40,%ecx
   3e57b:	mov    0xa0(%rsp,%rsi,8),%rbx
   3e583:	cltq   
   3e585:	sub    %edi,%ecx
   3e587:	mov    0xa0(%rsp,%rax,8),%r9
   3e58f:	sub    %rsi,%rax
   3e592:	mov    %r9,%r11
   3e595:	shl    %cl,%r11
   3e598:	mov    %edi,%ecx
   3e59a:	shr    %cl,%rbx
   3e59d:	mov    %rbx,%rcx
   3e5a0:	or     %r11,%rcx
   3e5a3:	test   %rax,%rax
   3e5a6:	mov    %rcx,0x80(%rsp)
   3e5ae:	jle    3e651 <strtold+0x2af1>
   3e5b4:	mov    %rsi,%rcx
   3e5b7:	jmpq   3e2e1 <strtold+0x2781>
   3e5bc:	cmp    %r15,%r10
   3e5bf:	jne    3e6f4 <strtold+0x2b94>
   3e5c5:	lea    -0x1(%rdx),%ebx
   3e5c8:	mov    %ebx,%edx
   3e5ca:	sar    $0x1f,%edx
   3e5cd:	shr    $0x1a,%edx
   3e5d0:	lea    (%rbx,%rdx,1),%eax
   3e5d3:	and    $0x3f,%eax
   3e5d6:	sub    %edx,%eax
   3e5d8:	cmp    $0x17,%eax
   3e5db:	je     3e663 <strtold+0x2b03>
   3e5e1:	cmp    $0x16,%eax
   3e5e4:	jle    3e6b9 <strtold+0x2b59>
   3e5ea:	test   %r9,%r9
   3e5ed:	jg     3e69a <strtold+0x2b3a>
   3e5f3:	lea    -0x17(%rax),%ecx
   3e5f6:	lea    0x80(%rsp),%r12
   3e5fe:	mov    $0x1,%eax
   3e603:	sub    %r9,%rax
   3e606:	mov    %r9,%rdx
   3e609:	mov    %r14,%rsi
   3e60c:	lea    (%r12,%rax,8),%rdi
   3e610:	callq  47a50 <swapcontext+0xbd0>
   3e615:	mov    0x90(%rsp),%rdx
   3e61d:	neg    %rdx
   3e620:	test   %rdx,%rdx
   3e623:	mov    %rax,0x80(%rsp,%rdx,8)
   3e62b:	jg     3e68c <strtold+0x2b2c>
   3e62d:	mov    0x10(%rsp),%edx
   3e631:	movslq %ebx,%rsi
   3e634:	xor    %r9d,%r9d
   3e637:	xor    %r8d,%r8d
   3e63a:	xor    %ecx,%ecx
   3e63c:	mov    %r12,%rdi
   3e63f:	callq  3be60 <strtold+0x300>
   3e644:	jmpq   3c4cf <strtold+0x96f>
   3e649:	mov    0xa0(%rsp,%rsi,8),%r9
   3e651:	mov    %edi,%ecx
   3e653:	shr    %cl,%r9
   3e656:	mov    %r9,0x80(%rsp)
   3e65e:	jmpq   3e5b4 <strtold+0x2a54>
   3e663:	mov    $0x1,%ebp
   3e668:	lea    0x80(%rsp),%r12
   3e670:	lea    0x0(,%r9,8),%rdx
   3e678:	sub    %r9,%rbp
   3e67b:	mov    %r14,%rsi
   3e67e:	lea    (%r12,%rbp,8),%rdi
   3e682:	callq  943f0 <memcpy+0x70>
   3e687:	test   %rbp,%rbp
   3e68a:	jle    3e62d <strtold+0x2acd>
   3e68c:	movq   $0x0,0x80(%rsp)
   3e698:	jmp    3e62d <strtold+0x2acd>
   3e69a:	lea    0x15637f(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3e6a1:	lea    0x14dd27(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3e6a8:	lea    0x151df1(%rip),%rdi        # 1904a0 <_libc_intl_domainname+0x4277>
   3e6af:	mov    $0x523,%edx
   3e6b4:	callq  2e0b0 <__assert_fail>
   3e6b9:	mov    $0x1,%ebp
   3e6be:	mov    $0x17,%ecx
   3e6c3:	lea    0x80(%rsp),%r12
   3e6cb:	sub    %eax,%ecx
   3e6cd:	mov    %rbp,%rax
   3e6d0:	mov    %r9,%rdx
   3e6d3:	sub    %r9,%rax
   3e6d6:	mov    %r14,%rsi
   3e6d9:	lea    (%r12,%rax,8),%rdi
   3e6dd:	callq  47940 <swapcontext+0xac0>
   3e6e2:	sub    0x90(%rsp),%rbp
   3e6ea:	test   %rbp,%rbp
   3e6ed:	jg     3e68c <strtold+0x2b2c>
   3e6ef:	jmpq   3e62d <strtold+0x2acd>
   3e6f4:	lea    0x80(%rsp),%r12
   3e6fc:	lea    0x0(,%r9,8),%rdx
   3e704:	mov    %r14,%rsi
   3e707:	mov    %r10,(%rsp)
   3e70b:	mov    %r12,%rdi
   3e70e:	callq  943f0 <memcpy+0x70>
   3e713:	mov    (%rsp),%r10
   3e717:	jmpq   3cc68 <strtold+0x1108>
   3e71c:	lea    0x1562fd(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3e723:	lea    0x14dca5(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3e72a:	lea    0x14dbc5(%rip),%rdi        # 18c2f6 <_libc_intl_domainname+0xcd>
   3e731:	mov    $0x24b,%edx
   3e736:	callq  2e0b0 <__assert_fail>
   3e73b:	lea    0x1562de(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3e742:	lea    0x14dc86(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3e749:	lea    0x14dbc4(%rip),%rdi        # 18c314 <_libc_intl_domainname+0xeb>
   3e750:	mov    $0x405,%edx
   3e755:	callq  2e0b0 <__assert_fail>
   3e75a:	lea    0x1562bf(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3e761:	lea    0x14dc67(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3e768:	lea    0x151d59(%rip),%rdi        # 1904c8 <_libc_intl_domainname+0x429f>
   3e76f:	mov    $0x54f,%edx
   3e774:	callq  2e0b0 <__assert_fail>
   3e779:	lea    0x1562a0(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3e780:	lea    0x14dc48(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3e787:	lea    0x14dbbd(%rip),%rdi        # 18c34b <_libc_intl_domainname+0x122>
   3e78e:	mov    $0x55f,%edx
   3e793:	callq  2e0b0 <__assert_fail>
   3e798:	mov    %rbx,%r9
   3e79b:	lea    0x80(%rsp),%r12
   3e7a3:	jmpq   3d3f2 <strtold+0x1892>
   3e7a8:	sub    $0x40,%r12
   3e7ac:	mov    %rbx,%r9
   3e7af:	xor    %r8d,%r8d
   3e7b2:	mov    %r12,0x98(%rsp)
   3e7ba:	lea    0x80(%rsp),%r12
   3e7c2:	jmpq   3d3f5 <strtold+0x1895>
   3e7c7:	lea    0x156252(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3e7ce:	lea    0x14dbfa(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3e7d5:	lea    0x14dba2(%rip),%rdi        # 18c37e <_libc_intl_domainname+0x155>
   3e7dc:	mov    $0x5d8,%edx
   3e7e1:	callq  2e0b0 <__assert_fail>
   3e7e6:	lea    0x156233(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3e7ed:	lea    0x14dbdb(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3e7f4:	lea    0x151a55(%rip),%rdi        # 190250 <_libc_intl_domainname+0x4027>
   3e7fb:	mov    $0x3b2,%edx
   3e800:	callq  2e0b0 <__assert_fail>
   3e805:	mov    $0x5,%eax
   3e80a:	jmpq   3e369 <strtold+0x2809>
   3e80f:	mov    $0x4,%eax
   3e814:	jmpq   3e369 <strtold+0x2809>
   3e819:	mov    $0x3,%eax
   3e81e:	jmpq   3e369 <strtold+0x2809>
   3e823:	mov    $0x2,%eax
   3e828:	jmpq   3e369 <strtold+0x2809>
   3e82d:	lea    0x1561ec(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3e834:	lea    0x14db94(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3e83b:	lea    0x15193e(%rip),%rdi        # 190180 <_libc_intl_domainname+0x3f57>
   3e842:	mov    $0x392,%edx
   3e847:	callq  2e0b0 <__assert_fail>
   3e84c:	xor    %ebx,%ebx
   3e84e:	jmpq   3deb7 <strtold+0x2357>
   3e853:	lea    0x1561c6(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3e85a:	lea    0x14db6e(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3e861:	lea    0x151960(%rip),%rdi        # 1901c8 <_libc_intl_domainname+0x3f9f>
   3e868:	mov    $0x39a,%edx
   3e86d:	callq  2e0b0 <__assert_fail>
   3e872:	lea    0x1561a7(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3e879:	lea    0x14db4f(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3e880:	lea    0x151b91(%rip),%rdi        # 190418 <_libc_intl_domainname+0x41ef>
   3e887:	mov    $0x469,%edx
   3e88c:	callq  2e0b0 <__assert_fail>
   3e891:	lea    0x156188(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3e898:	lea    0x14db30(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3e89f:	lea    0x14daf9(%rip),%rdi        # 18c39f <_libc_intl_domainname+0x176>
   3e8a6:	mov    $0x6ab,%edx
   3e8ab:	callq  2e0b0 <__assert_fail>
   3e8b0:	sub    %rax,0x98(%rsp)
   3e8b8:	movl   $0x0,0x8(%rsp)
   3e8c0:	jmpq   3d67c <strtold+0x1b1c>
   3e8c5:	lea    -0x1(%r15),%r12d
   3e8c9:	jmpq   3d9d9 <strtold+0x1e79>
   3e8ce:	lea    0x15614b(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3e8d5:	lea    0x14daf3(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3e8dc:	lea    0x14dacf(%rip),%rdi        # 18c3b2 <_libc_intl_domainname+0x189>
   3e8e3:	mov    $0x6d5,%edx
   3e8e8:	callq  2e0b0 <__assert_fail>
   3e8ed:	mov    %r8d,%r14d
   3e8f0:	jmpq   3dcf3 <strtold+0x2193>
   3e8f5:	lea    0x156124(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3e8fc:	lea    0x14dacc(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3e903:	lea    0x1519c6(%rip),%rdi        # 1902d0 <_libc_intl_domainname+0x40a7>
   3e90a:	mov    $0x3c6,%edx
   3e90f:	callq  2e0b0 <__assert_fail>
   3e914:	lea    0x156105(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3e91b:	lea    0x14daad(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3e922:	lea    0x14d9fc(%rip),%rdi        # 18c325 <_libc_intl_domainname+0xfc>
   3e929:	mov    $0x454,%edx
   3e92e:	callq  2e0b0 <__assert_fail>
   3e933:	mov    (%rsp),%rdi
   3e937:	lea    0x0(,%r15,8),%rdx
   3e93f:	mov    %r14,%rsi
   3e942:	callq  943f0 <memcpy+0x70>
   3e947:	jmpq   3d2d2 <strtold+0x1772>
   3e94c:	lea    -0x1(%r15),%r12d
   3e950:	jmpq   3da01 <strtold+0x1ea1>
   3e955:	lea    0x1560c4(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3e95c:	lea    0x14da6c(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3e963:	lea    0x14da2a(%rip),%rdi        # 18c394 <_libc_intl_domainname+0x16b>
   3e96a:	mov    $0x686,%edx
   3e96f:	callq  2e0b0 <__assert_fail>
   3e974:	mov    $0x18,%eax
   3e979:	sub    %ebp,%eax
   3e97b:	mov    %eax,0x8(%rsp)
   3e97f:	je     3d675 <strtold+0x1b15>
   3e985:	lea    0x80(%rsp),%r12
   3e98d:	mov    $0x1,%edx
   3e992:	mov    %eax,%ecx
   3e994:	mov    %r8,0x30(%rsp)
   3e999:	mov    %r9,0x20(%rsp)
   3e99e:	mov    %r12,%rsi
   3e9a1:	mov    %r12,%rdi
   3e9a4:	callq  47940 <swapcontext+0xac0>
   3e9a9:	mov    0x90(%rsp),%rdx
   3e9b1:	mov    0x30(%rsp),%r8
   3e9b6:	mov    0x20(%rsp),%r9
   3e9bb:	jmpq   3d675 <strtold+0x1b15>
   3e9c0:	lea    0x156059(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3e9c7:	lea    0x14da01(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3e9ce:	lea    0x1519a3(%rip),%rdi        # 190378 <_libc_intl_domainname+0x414f>
   3e9d5:	mov    $0x43c,%edx
   3e9da:	callq  2e0b0 <__assert_fail>
   3e9df:	lea    0x15603a(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3e9e6:	lea    0x14d9e2(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3e9ed:	lea    0x15181c(%rip),%rdi        # 190210 <_libc_intl_domainname+0x3fe7>
   3e9f4:	mov    $0x3a6,%edx
   3e9f9:	callq  2e0b0 <__assert_fail>
   3e9fe:	lea    0x15601b(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3ea05:	lea    0x14d9c3(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3ea0c:	lea    0x1518fd(%rip),%rdi        # 190310 <_libc_intl_domainname+0x40e7>
   3ea13:	mov    $0x438,%edx
   3ea18:	callq  2e0b0 <__assert_fail>
   3ea1d:	lea    0x155ffc(%rip),%rcx        # 194a20 <_nl_default_dirname+0x20>
   3ea24:	lea    0x14d9a4(%rip),%rsi        # 18c3cf <_libc_intl_domainname+0x1a6>
   3ea2b:	lea    0x15171e(%rip),%rdi        # 190150 <_libc_intl_domainname+0x3f27>
   3ea32:	mov    $0x373,%edx
   3ea37:	callq  2e0b0 <__assert_fail>
   3ea3c:	nopl   0x0(%rax)
