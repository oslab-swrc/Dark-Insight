000000000000fc90 <__lll_robust_lock_wait>:
    fc90:	push   %r10
    fc92:	push   %rdx
    fc93:	xor    %r10,%r10
    fc96:	xor    $0x80,%esi
    fc9c:	mov    %eax,%edx
    fc9e:	or     $0x80000000,%edx
    fca4:	test   $0x40000000,%eax
    fca9:	jne    fcd6 <__lll_robust_lock_wait+0x46>
    fcab:	cmp    %edx,%eax
    fcad:	je     fcb5 <__lll_robust_lock_wait+0x25>
    fcaf:	lock cmpxchg %edx,(%rdi)
    fcb3:	jne    fcbe <__lll_robust_lock_wait+0x2e>
    fcb5:	mov    $0xca,%eax
    fcba:	syscall 
    fcbc:	mov    (%rdi),%eax
    fcbe:	test   %eax,%eax
    fcc0:	jne    fc9c <__lll_robust_lock_wait+0xc>
    fcc2:	mov    %fs:0x2d0,%edx
    fcca:	or     $0x80000000,%edx
    fcd0:	lock cmpxchg %edx,(%rdi)
    fcd4:	jne    fc9c <__lll_robust_lock_wait+0xc>
    fcd6:	pop    %rdx
    fcd7:	pop    %r10
    fcd9:	retq   
    fcda:	nopw   0x0(%rax,%rax,1)
