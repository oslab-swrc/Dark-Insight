// TC_OUT __fork,0xcc910,0xcc928,0x0(0x3c5708),0x28(0x0(0x3c5708))
// TC_OUT __fork,0xcc910,0xcc939,0x0(0x3c5708),0x28(0x0(0x3c5708))
00000000000cc8f0 <__fork>:
   cc8f0:	push   %rbp
   cc8f1:	mov    %rsp,%rbp
   cc8f4:	push   %r15
   cc8f6:	push   %r14
   cc8f8:	push   %r13
   cc8fa:	push   %r12
   cc8fc:	push   %rbx
   cc8fd:	sub    $0x8,%rsp
   cc901:	mov    %fs:0x18,%r14d
   cc90a:	nopw   0x0(%rax,%rax,1)
   cc910:	mov    0x2f8df1(%rip),%r12        # 3c5708 <__fork_handlers>
   cc917:	test   %r12,%r12
   cc91a:	je     cc990 <__fork+0xa0>
   cc91c:	lock orl $0x0,(%rsp)
   cc921:	mov    0x28(%r12),%eax
   cc926:	test   %eax,%eax
   cc928:	je     cc910 <__fork+0x20>
   cc92a:	mov    0x2f8dd7(%rip),%rdx        # 3c5708 <__fork_handlers>
   cc931:	lea    0x1(%rax),%ecx
   cc934:	lock cmpxchg %ecx,0x28(%rdx)
   cc939:	jne    cc910 <__fork+0x20>
   cc93b:	xor    %r15d,%r15d
   cc93e:	mov    $0x20,%r13d
   cc944:	jmp    cc959 <__fork+0x69>
   cc946:	nopw   %cs:0x0(%rax,%rax,1)
   cc950:	lock incl 0x28(%r12)
   cc956:	mov    %rax,%r15
   cc959:	mov    0x8(%r12),%rax
   cc95e:	test   %rax,%rax
   cc961:	je     cc965 <__fork+0x75>
   cc963:	callq  *%rax
   cc965:	sub    %r13,%rsp
   cc968:	lea    0xf(%rsp),%rax
   cc96d:	and    $0xfffffffffffffff0,%rax
   cc971:	mov    %r12,(%rax)
   cc974:	mov    (%r12),%r12
   cc978:	mov    %rax,%rbx
   cc97b:	mov    %r15,0x8(%rax)
   cc97f:	test   %r12,%r12
   cc982:	jne    cc950 <__fork+0x60>
   cc984:	jmp    cc992 <__fork+0xa2>
   cc986:	nopw   %cs:0x0(%rax,%rax,1)
   cc990:	xor    %ebx,%ebx
   cc992:	test   %r14d,%r14d
   cc995:	jne    ccb90 <__fork+0x2a0>
   cc99b:	mov    %fs:0x2d0,%r12d
   cc9a4:	mov    %fs:0x2d4,%r8d
   cc9ad:	mov    %r8d,%eax
   cc9b0:	neg    %eax
   cc9b2:	mov    %eax,%fs:0x2d4
   cc9ba:	mov    %fs:0x10,%r9
   cc9c3:	xor    %edx,%edx
   cc9c5:	lea    0x2d0(%r9),%r10
   cc9cc:	xor    %esi,%esi
   cc9ce:	mov    $0x1200011,%edi
   cc9d3:	mov    $0x38,%eax
   cc9d8:	syscall 
   cc9da:	cmp    $0xfffffffffffff000,%rax
   cc9e0:	ja     ccae5 <__fork+0x1f5>
   cc9e6:	test   %eax,%eax
   cc9e8:	mov    %eax,%r13d
   cc9eb:	jne    ccaf7 <__fork+0x207>
   cc9f1:	mov    %fs:0x2d0,%eax
   cc9f9:	cmp    %eax,%r12d
   cc9fc:	je     ccc61 <__fork+0x371>
   cca02:	mov    0x2f8cef(%rip),%rax        # 3c56f8 <__fork_generation_pointer>
   cca09:	test   %rax,%rax
   cca0c:	je     cca12 <__fork+0x122>
   cca0e:	addq   $0x4,(%rax)
   cca12:	mov    %fs:0x2d0,%eax
   cca1a:	mov    %eax,%fs:0x2d4
   cca22:	rdtsc  
   cca24:	shl    $0x20,%rdx
   cca28:	mov    %eax,%eax
   cca2a:	or     %rdx,%rax
   cca2d:	mov    %rax,%fs:0x620
   cca36:	mov    0x2f8cb4(%rip),%edx        # 3c56f0 <__libc_pthread_functions_init>
   cca3c:	mov    0x2f3395(%rip),%r15        # 3bfdd8 <_DYNAMIC+0x278>
   cca43:	test   %edx,%edx
   cca45:	mov    %rax,0x968(%r15)
   cca4c:	jne    ccc1a <__fork+0x32a>
   cca52:	test   %r14d,%r14d
   cca55:	jne    ccbc0 <__fork+0x2d0>
   cca5b:	test   %rbx,%rbx
   cca5e:	movq   $0x0,0x918(%r15)
   cca69:	movq   $0x0,0x908(%r15)
   cca74:	movq   $0x0,0x910(%r15)
   cca7f:	movq   $0x0,0x920(%r15)
   cca8a:	movq   $0x0,0x928(%r15)
   cca95:	movl   $0x1,0x918(%r15)
   ccaa0:	je     ccac9 <__fork+0x1d9>
   ccaa2:	nopw   0x0(%rax,%rax,1)
   ccaa8:	mov    (%rbx),%rax
   ccaab:	mov    0x18(%rax),%rdx
   ccaaf:	test   %rdx,%rdx
   ccab2:	je     ccab9 <__fork+0x1c9>
   ccab4:	callq  *%rdx
   ccab6:	mov    (%rbx),%rax
   ccab9:	mov    0x8(%rbx),%rbx
   ccabd:	movl   $0x1,0x28(%rax)
   ccac4:	test   %rbx,%rbx
   ccac7:	jne    ccaa8 <__fork+0x1b8>
   ccac9:	movl   $0x0,0x2f6ced(%rip)        # 3c37c0 <__fork_lock>
   ccad3:	lea    -0x28(%rbp),%rsp
   ccad7:	mov    %r13d,%eax
   ccada:	pop    %rbx
   ccadb:	pop    %r12
   ccadd:	pop    %r13
   ccadf:	pop    %r14
   ccae1:	pop    %r15
   ccae3:	pop    %rbp
   ccae4:	retq   
   ccae5:	mov    0x2f337c(%rip),%rdx        # 3bfe68 <_DYNAMIC+0x308>
   ccaec:	neg    %eax
   ccaee:	mov    $0xffffffff,%r13d
   ccaf4:	mov    %eax,%fs:(%rdx)
   ccaf7:	mov    %fs:0x2d0,%eax
   ccaff:	cmp    %eax,%r12d
   ccb02:	jne    ccc42 <__fork+0x352>
   ccb08:	mov    %r8d,%fs:0x2d4
   ccb11:	test   %r14d,%r14d
   ccb14:	jne    ccb9f <__fork+0x2af>
   ccb1a:	test   %rbx,%rbx
   ccb1d:	je     ccad3 <__fork+0x1e3>
   ccb1f:	mov    $0xca,%r12d
   ccb25:	jmp    ccb39 <__fork+0x249>
   ccb27:	nopw   0x0(%rax,%rax,1)
   ccb30:	mov    0x8(%rbx),%rbx
   ccb34:	test   %rbx,%rbx
   ccb37:	je     ccad3 <__fork+0x1e3>
   ccb39:	mov    (%rbx),%rdi
   ccb3c:	mov    0x10(%rdi),%rax
   ccb40:	test   %rax,%rax
   ccb43:	je     ccb4a <__fork+0x25a>
   ccb45:	callq  *%rax
   ccb47:	mov    (%rbx),%rdi
   ccb4a:	lock decl 0x28(%rdi)
   ccb4e:	sete   %al
   ccb51:	test   %al,%al
   ccb53:	je     ccb30 <__fork+0x240>
   ccb55:	mov    0x2c(%rdi),%eax
   ccb58:	test   %eax,%eax
   ccb5a:	je     ccb30 <__fork+0x240>
   ccb5c:	xor    %r10d,%r10d
   ccb5f:	mov    $0x1,%edx
   ccb64:	mov    $0x81,%esi
   ccb69:	add    $0x28,%rdi
   ccb6d:	mov    %r12d,%eax
   ccb70:	syscall 
   ccb72:	cmp    $0xfffffffffffff000,%rax
   ccb78:	jbe    ccb30 <__fork+0x240>
   ccb7a:	cmp    $0xffffffea,%eax
   ccb7d:	je     ccb30 <__fork+0x240>
   ccb7f:	cmp    $0xfffffff2,%eax
   ccb82:	je     ccb30 <__fork+0x240>
   ccb84:	lea    0xc227d(%rip),%rdi        # 18ee08 <__PRETTY_FUNCTION__.6109+0x90>
   ccb8b:	callq  79280 <__libc_fatal>
   ccb90:	callq  7f370 <_IO_list_lock>
   ccb95:	callq  85bf0 <__malloc_fork_lock_parent>
   ccb9a:	jmpq   cc99b <__fork+0xab>
   ccb9f:	callq  85c90 <__malloc_fork_unlock_parent>
   ccba4:	callq  7f3d0 <_IO_list_unlock>
   ccba9:	test   %rbx,%rbx
   ccbac:	jne    ccb1f <__fork+0x22f>
   ccbb2:	jmpq   ccad3 <__fork+0x1e3>
   ccbb7:	nopw   0x0(%rax,%rax,1)
   ccbc0:	callq  85d20 <__malloc_fork_unlock_child>
   ccbc5:	callq  7f330 <_IO_iter_begin>
   ccbca:	mov    %rax,%r12
   ccbcd:	jmp    ccbdb <__fork+0x2eb>
   ccbcf:	nop
   ccbd0:	mov    %r12,%rdi
   ccbd3:	callq  7f350 <_IO_iter_next>
   ccbd8:	mov    %rax,%r12
   ccbdb:	callq  7f340 <_IO_iter_end>
   ccbe0:	cmp    %rax,%r12
   ccbe3:	je     ccc38 <__fork+0x348>
   ccbe5:	mov    %r12,%rdi
   ccbe8:	callq  7f360 <_IO_iter_file>
   ccbed:	mov    (%rax),%eax
   ccbef:	test   $0x80,%ah
   ccbf2:	jne    ccbd0 <__fork+0x2e0>
   ccbf4:	mov    %r12,%rdi
   ccbf7:	callq  7f360 <_IO_iter_file>
   ccbfc:	mov    0x88(%rax),%rax
   ccc03:	movl   $0x0,(%rax)
   ccc09:	movl   $0x0,0x4(%rax)
   ccc10:	movq   $0x0,0x8(%rax)
   ccc18:	jmp    ccbd0 <__fork+0x2e0>
   ccc1a:	mov    0x2f8ac7(%rip),%rax        # 3c56e8 <__libc_pthread_functions+0x1a8>
   ccc21:	mov    %r9,%rdi
   ccc24:	ror    $0x11,%rax
   ccc28:	xor    %fs:0x30,%rax
   ccc31:	callq  *%rax
   ccc33:	jmpq   cca52 <__fork+0x162>
   ccc38:	callq  7f420 <_IO_list_resetlock>
   ccc3d:	jmpq   cca5b <__fork+0x16b>
   ccc42:	lea    0xc21f7(%rip),%rcx        # 18ee40 <__PRETTY_FUNCTION__.12097>
   ccc49:	lea    0xbe255(%rip),%rsi        # 18aea5 <__func__.11632+0x3e1>
   ccc50:	lea    0xc2181(%rip),%rdi        # 18edd8 <__PRETTY_FUNCTION__.6109+0x60>
   ccc57:	mov    $0xea,%edx
   ccc5c:	callq  2dea0 <__assert_fail>
   ccc61:	lea    0xc21d8(%rip),%rcx        # 18ee40 <__PRETTY_FUNCTION__.12097>
   ccc68:	lea    0xbe236(%rip),%rsi        # 18aea5 <__func__.11632+0x3e1>
   ccc6f:	lea    0xc213a(%rip),%rdi        # 18edb0 <__PRETTY_FUNCTION__.6109+0x38>
   ccc76:	mov    $0x9c,%edx
   ccc7b:	callq  2dea0 <__assert_fail>
