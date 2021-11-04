000000000000fb70 <__lll_timedlock_wait>:
    fb70:	cmpq   $0x0,(%rdx)
    fb74:	js     fbb5 <__lll_timedlock_wait+0x45>
    fb76:	push   %r9
    fb78:	mov    %rdx,%r10
    fb7b:	mov    $0xffffffff,%r9d
    fb81:	xor    $0x189,%esi
    fb87:	mov    $0x2,%edx
    fb8c:	cmp    %edx,%eax
    fb8e:	jne    fb9c <__lll_timedlock_wait+0x2c>
    fb90:	mov    $0xca,%eax
    fb95:	mov    $0x2,%edx
    fb9a:	syscall 
    fb9c:	xchg   %edx,(%rdi)
    fb9e:	test   %edx,%edx
    fba0:	je     fbb0 <__lll_timedlock_wait+0x40>
    fba2:	cmp    $0xffffff92,%eax
    fba5:	je     fbac <__lll_timedlock_wait+0x3c>
    fba7:	cmp    $0xffffffea,%eax
    fbaa:	jne    fb90 <__lll_timedlock_wait+0x20>
    fbac:	mov    %eax,%edx
    fbae:	neg    %edx
    fbb0:	mov    %edx,%eax
    fbb2:	pop    %r9
    fbb4:	retq   
    fbb5:	mov    $0x6e,%eax
    fbba:	retq   
    fbbb:	nopl   0x0(%rax,%rax,1)
