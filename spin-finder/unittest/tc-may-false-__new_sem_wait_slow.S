000000000000f350 <__new_sem_wait_slow>:
    f350:	push   %r13
    f352:	push   %r12
    f354:	movabs $0x100000000,%rax
    f35e:	push   %rbp
    f35f:	push   %rbx
    f360:	mov    %rsi,%r12
    f363:	mov    %rdi,%rbx
    f366:	sub    $0x38,%rsp
    f36a:	lock xadd %rax,(%rdi)
    f36f:	lea    -0x126(%rip),%rsi        # f250 <__sem_wait_cleanup>
    f376:	movabs $0xfffffffeffffffff,%rbp
    f380:	lea    0x10(%rsp),%r13
    f385:	mov    %rdi,%rdx
    f388:	mov    %rax,0x8(%rsp)
    f38d:	mov    %r13,%rdi
    f390:	callq  f670 <_pthread_cleanup_push>
    f395:	mov    0x8(%rsp),%rax
    f39a:	nopw   0x0(%rax,%rax,1)
    f3a0:	test   %eax,%eax
    f3a2:	jne    f3c5 <__new_sem_wait_slow+0x75>
    f3a4:	mov    %r12,%rsi
    f3a7:	mov    %rbx,%rdi
    f3aa:	callq  f260 <do_futex_wait>
    f3af:	cmp    $0x4,%eax
    f3b2:	je     f410 <__new_sem_wait_slow+0xc0>
    f3b4:	cmp    $0x6e,%eax
    f3b7:	je     f410 <__new_sem_wait_slow+0xc0>
    f3b9:	mov    (%rbx),%rax
    f3bc:	test   %eax,%eax
    f3be:	mov    %rax,0x8(%rsp)
    f3c3:	je     f3a4 <__new_sem_wait_slow+0x54>
    f3c5:	lea    (%rax,%rbp,1),%rdx
    f3c9:	mov    0x8(%rsp),%rax
    f3ce:	lock cmpxchg %rdx,(%rbx)
    f3d3:	jne    f400 <__new_sem_wait_slow+0xb0>
    f3d5:	xor    %ebx,%ebx
    f3d7:	nopw   0x0(%rax,%rax,1)
    f3e0:	mov    %r13,%rdi
    f3e3:	xor    %esi,%esi
    f3e5:	callq  f690 <_pthread_cleanup_pop>
    f3ea:	add    $0x38,%rsp
    f3ee:	mov    %ebx,%eax
    f3f0:	pop    %rbx
    f3f1:	pop    %rbp
    f3f2:	pop    %r12
    f3f4:	pop    %r13
    f3f6:	retq   
    f3f7:	nopw   0x0(%rax,%rax,1)
    f400:	mov    %rax,0x8(%rsp)
    f405:	jmp    f3a0 <__new_sem_wait_slow+0x50>
    f407:	nopw   0x0(%rax,%rax,1)
    f410:	mov    0x209b51(%rip),%rdx        # 218f68 <_DYNAMIC+0x238>
    f417:	mov    %eax,%fs:(%rdx)
    f41a:	movabs $0xffffffff00000000,%rax
    f424:	lock add %rax,(%rbx)
    f428:	mov    $0xffffffff,%ebx
    f42d:	jmp    f3e0 <__new_sem_wait_slow+0x90>
    f42f:	nop
