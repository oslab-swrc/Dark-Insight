000000000000fce0 <__lll_robust_timedlock_wait>:
    fce0:	cmpq   $0x0,(%rdx)
    fce4:	js     fd4d <__lll_robust_timedlock_wait+0x6d>
    fce6:	push   %r9
    fce8:	mov    %rdx,%r10
    fceb:	mov    $0xffffffff,%r9d
    fcf1:	xor    $0x189,%esi
    fcf7:	test   $0x40000000,%eax
    fcfc:	jne    fd3a <__lll_robust_timedlock_wait+0x5a>
    fcfe:	mov    %eax,%edx
    fd00:	or     $0x80000000,%edx
    fd06:	cmp    %eax,%edx
    fd08:	je     fd17 <__lll_robust_timedlock_wait+0x37>
    fd0a:	lock cmpxchg %edx,(%rdi)
    fd0e:	mov    $0x0,%rcx
    fd15:	jne    fd22 <__lll_robust_timedlock_wait+0x42>
    fd17:	mov    $0xca,%eax
    fd1c:	syscall 
    fd1e:	mov    %eax,%ecx
    fd20:	mov    (%rdi),%eax
    fd22:	test   %eax,%eax
    fd24:	jne    fd3d <__lll_robust_timedlock_wait+0x5d>
    fd26:	mov    %fs:0x2d0,%edx
    fd2e:	or     $0x80000000,%edx
    fd34:	lock cmpxchg %edx,(%rdi)
    fd38:	jne    fd3d <__lll_robust_timedlock_wait+0x5d>
    fd3a:	pop    %r9
    fd3c:	retq   
    fd3d:	cmp    $0xffffff92,%ecx
    fd40:	je     fd47 <__lll_robust_timedlock_wait+0x67>
    fd42:	cmp    $0xffffffea,%ecx
    fd45:	jne    fcf7 <__lll_robust_timedlock_wait+0x17>
    fd47:	mov    %ecx,%eax
    fd49:	neg    %eax
    fd4b:	jmp    fd3a <__lll_robust_timedlock_wait+0x5a>
    fd4d:	mov    $0x6e,%eax
    fd52:	retq   
    fd53:	nopw   %cs:0x0(%rax,%rax,1)
    fd5d:	nopl   (%rax)
