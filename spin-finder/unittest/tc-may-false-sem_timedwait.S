
000000000000f430 <sem_timedwait>:
    f430:	cmpq   $0x3b9ac9ff,0x8(%rsi)
    f438:	ja     f480 <sem_timedwait+0x50>
    f43a:	sub    $0x18,%rsp
    f43e:	mov    (%rdi),%rax
    f441:	test   %eax,%eax
    f443:	mov    %rax,0x8(%rsp)
    f448:	je     f46d <sem_timedwait+0x3d>
    f44a:	lea    -0x1(%rax),%rdx
    f44e:	lock cmpxchg %rdx,(%rdi)
    f453:	mov    %rax,%rdx
    f456:	mov    $0x0,%eax
    f45b:	jne    f468 <sem_timedwait+0x38>
    f45d:	add    $0x18,%rsp
    f461:	retq   
    f462:	nopw   0x0(%rax,%rax,1)
    f468:	mov    %rdx,0x8(%rsp)
    f46d:	callq  f350 <__new_sem_wait_slow>
    f472:	add    $0x18,%rsp
    f476:	retq   
    f477:	nopw   0x0(%rax,%rax,1)
    f480:	mov    0x209ae1(%rip),%rax        # 218f68 <_DYNAMIC+0x238>
    f487:	movl   $0x16,%fs:(%rax)
    f48e:	mov    $0xffffffff,%eax
    f493:	retq   
    f494:	nopw   %cs:0x0(%rax,%rax,1)
    f49e:	xchg   %ax,%ax
