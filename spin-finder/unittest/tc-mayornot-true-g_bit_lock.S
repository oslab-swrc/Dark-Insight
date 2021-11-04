// TC_OUT g_bit_lock,0x1ff78,0x1ff7d,0x0(%rbx)
// TC_OUT g_bit_lock,0x1ff90,0x1ff94,0x0(%rbx)
// TC_OUT g_bit_lock,0x1ff90,0x1ffbc,0x0(%rbx)
000000000001ff30 <g_bit_lock>:
   1ff30:	mov    %rdi,%rax
   1ff33:	movabs $0x2e8ba2e8ba2e8ba3,%rdx
   1ff3d:	push   %r13
   1ff3f:	mul    %rdx
   1ff42:	push   %r12
   1ff44:	push   %rbp
   1ff45:	push   %rbx
   1ff46:	mov    $0x1,%ebp
   1ff4b:	mov    %esi,%ecx
   1ff4d:	mov    %rdi,%rbx
   1ff50:	mov    %esi,%r12d
   1ff53:	shl    %cl,%ebp
   1ff55:	sub    $0x8,%rsp
   1ff59:	shr    %rdx
   1ff5c:	lea    (%rdx,%rdx,4),%rax
   1ff60:	lea    (%rdx,%rax,2),%rax
   1ff64:	mov    %edi,%edx
   1ff66:	sub    %eax,%edx
   1ff68:	lea    0x2edd51(%rip),%rax        # 30dcc0 <g_thread_use_default_impl+0x38>
   1ff6f:	lea    (%rax,%rdx,4),%r13
   1ff73:	nopl   0x0(%rax,%rax,1)
   1ff78:	lock bts %r12d,(%rbx)
   1ff7d:	jb     1ff90 <g_bit_lock+0x60>
   1ff7f:	add    $0x8,%rsp
   1ff83:	pop    %rbx
   1ff84:	pop    %rbp
   1ff85:	pop    %r12
   1ff87:	pop    %r13
   1ff89:	retq   
   1ff8a:	nopw   0x0(%rax,%rax,1)
   1ff90:	mov    (%rbx),%eax
   1ff92:	test   %ebp,%eax
   1ff94:	je     1ff78 <g_bit_lock+0x48>
   1ff96:	lock addl $0x1,0x0(%r13)
   1ff9c:	xor    %r8d,%r8d
   1ff9f:	mov    $0x80,%edx
   1ffa4:	mov    $0xca,%edi
   1ffa9:	movslq %eax,%rcx
   1ffac:	mov    %rbx,%rsi
   1ffaf:	xor    %eax,%eax
   1ffb1:	callq  1a050 <syscall@plt>
   1ffb6:	lock subl $0x1,0x0(%r13)
   1ffbc:	jmp    1ff78 <g_bit_lock+0x48>
   1ffbe:	xchg   %ax,%ax
