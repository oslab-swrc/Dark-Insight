000000000000fb40 <__lll_lock_wait>:
    fb40:	push   %r10
    fb42:	push   %rdx
    fb43:	xor    %r10,%r10
    fb46:	mov    $0x2,%edx
    fb4b:	xor    $0x80,%esi
    fb51:	cmp    %edx,%eax
    fb53:	jne    fb5d <__lll_lock_wait+0x1d>
    fb55:	nop
    fb56:	mov    $0xca,%eax
    fb5b:	syscall 
    fb5d:	mov    %edx,%eax
    fb5f:	xchg   %eax,(%rdi)
    fb61:	test   %eax,%eax
    fb63:	jne    fb55 <__lll_lock_wait+0x15>
    fb65:	pop    %rdx
    fb66:	pop    %r10
    fb68:	retq   
    fb69:	nopl   0x0(%rax)

