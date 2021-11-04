// TC_OUT
00000000000001b0 <__nptl_deallocate_tsd.part.5>:
     1b0:	push   %r15
     1b2:	push   %r14
     1b4:	mov    $0x4,%r14d
     1ba:	push   %r13
     1bc:	push   %r12
     1be:	push   %rbp
     1bf:	push   %rbx
     1c0:	sub    $0x8,%rsp
     1c4:	movb   $0x0,%fs:0x610
     1cd:	mov    $0x0,%r13d
     1d3:	xor    %r12d,%r12d
     1d6:	nopw   %cs:0x0(%rax,%rax,1)
     1e0:	mov    %fs:0x510(,%r12,8),%rax
     1e9:	test   %rax,%rax
     1ec:	je     240 <__nptl_deallocate_tsd.part.5+0x90>
     1ee:	lea    0x8(%rax),%rbx
     1f2:	lea    0x208(%rax),%r15
     1f9:	mov    %r13,%rbp
     1fc:	jmp    20d <__nptl_deallocate_tsd.part.5+0x5d>
     1fe:	xchg   %ax,%ax
     200:	add    $0x10,%rbx
     204:	add    $0x10,%rbp
     208:	cmp    %r15,%rbx
     20b:	je     240 <__nptl_deallocate_tsd.part.5+0x90>
     20d:	mov    (%rbx),%rdi
     210:	test   %rdi,%rdi
     213:	je     200 <__nptl_deallocate_tsd.part.5+0x50>
     215:	mov    -0x8(%rbp),%rax
     219:	cmp    %rax,-0x8(%rbx)
     21d:	movq   $0x0,(%rbx)
     224:	jne    200 <__nptl_deallocate_tsd.part.5+0x50>
     226:	mov    0x0(%rbp),%rdx
     22a:	test   %rdx,%rdx
     22d:	je     200 <__nptl_deallocate_tsd.part.5+0x50>
     22f:	add    $0x10,%rbx
     233:	add    $0x10,%rbp
     237:	callq  *%rdx
     239:	cmp    %r15,%rbx
     23c:	jne    20d <__nptl_deallocate_tsd.part.5+0x5d>
     23e:	xchg   %ax,%ax
     240:	add    $0x1,%r12
     244:	add    $0x200,%r13
     24b:	cmp    $0x20,%r12
     24f:	jne    1e0 <__nptl_deallocate_tsd.part.5+0x30>
     251:	xor    %eax,%eax
     253:	mov    %fs:0x610,%al
     25b:	test   %al,%al
     25d:	je     2a4 <__nptl_deallocate_tsd.part.5+0xf4>
     25f:	sub    $0x1,%r14
     263:	jne    1c4 <__nptl_deallocate_tsd.part.5+0x14>
     269:	mov    %fs:0x10,%rax
     272:	lea    0x318(%rax),%rdi
     279:	movq   $0x0,0x310(%rax)
     284:	movq   $0x0,0x508(%rax)
     28f:	and    $0xfffffffffffffff8,%rdi
     293:	sub    %edi,%eax
     295:	lea    0x510(%rax),%ecx
     29b:	mov    %r14,%rax
     29e:	shr    $0x3,%ecx
     2a1:	rep stos %rax,%es:(%rdi)
     2a4:	mov    $0x1,%ebx
     2a9:	nopl   0x0(%rax)
     2b0:	mov    %fs:0x510(,%rbx,8),%rdi
     2b9:	test   %rdi,%rdi
     2bc:	je     2d0 <__nptl_deallocate_tsd.part.5+0x120>
     2be:	callq  2c3 <__nptl_deallocate_tsd.part.5+0x113>
     2c3:	movq   $0x0,%fs:0x510(,%rbx,8)
     2d0:	add    $0x1,%rbx
     2d4:	cmp    $0x20,%rbx
     2d8:	jne    2b0 <__nptl_deallocate_tsd.part.5+0x100>
     2da:	movb   $0x0,%fs:0x610
     2e3:	add    $0x8,%rsp
     2e7:	pop    %rbx
     2e8:	pop    %rbp
     2e9:	pop    %r12
     2eb:	pop    %r13
     2ed:	pop    %r14
     2ef:	pop    %r15
     2f1:	retq   
     2f2:	nopl   0x0(%rax)
     2f6:	nopw   %cs:0x0(%rax,%rax,1)
