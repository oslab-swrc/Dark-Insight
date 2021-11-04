// TC_OUT
000000000000d9f0 <pthread_barrier_wait>:
    d9f0:	xor    %eax,%eax
    d9f2:	mov    $0x1,%esi
    d9f7:	lock cmpxchg %esi,0x4(%rdi)
    d9fc:	jne    da77 <pthread_barrier_wait+0x87>
    d9fe:	decl   0x8(%rdi)
    da01:	je     da42 <pthread_barrier_wait+0x52>
    da03:	mov    (%rdi),%edx
    da05:	lock decl 0x4(%rdi)
    da09:	jne    daa6 <pthread_barrier_wait+0xb6>
    da0f:	mov    0x10(%rdi),%esi
    da12:	xor    %r10,%r10
    da15:	mov    $0xca,%eax
    da1a:	syscall 
    da1c:	cmp    %edx,(%rdi)
    da1e:	je     da15 <pthread_barrier_wait+0x25>
    da20:	mov    $0x1,%edx
    da25:	mov    0xc(%rdi),%eax
    da28:	lock xadd %edx,0x8(%rdi)
    da2d:	sub    $0x1,%eax
    da30:	cmp    %eax,%edx
    da32:	jne,pt da3f <pthread_barrier_wait+0x4f>
    da35:	lock decl 0x4(%rdi)
    da39:	jne    dac1 <pthread_barrier_wait+0xd1>
    da3f:	xor    %eax,%eax
    da41:	retq   
    da42:	incl   (%rdi)
    da44:	mov    $0x7fffffff,%edx
    da49:	mov    $0x1,%esi
    da4e:	or     0x10(%rdi),%esi
    da51:	mov    $0xca,%eax
    da56:	syscall 
    da58:	mov    $0x1,%edx
    da5d:	mov    0xc(%rdi),%eax
    da60:	lock xadd %edx,0x8(%rdi)
    da65:	sub    $0x1,%eax
    da68:	cmp    %eax,%edx
    da6a:	jne,pt da73 <pthread_barrier_wait+0x83>
    da6d:	lock decl 0x4(%rdi)
    da71:	jne    da92 <pthread_barrier_wait+0xa2>
    da73:	or     $0xffffffff,%eax
    da76:	retq   
    da77:	mov    0x10(%rdi),%esi
    da7a:	add    $0x4,%rdi
    da7e:	xor    $0x80,%esi
    da84:	callq  fb40 <__lll_lock_wait>
    da89:	sub    $0x4,%rdi
    da8d:	jmpq   d9fe <pthread_barrier_wait+0xe>
    da92:	mov    0x10(%rdi),%esi
    da95:	add    $0x4,%rdi
    da99:	xor    $0x80,%esi
    da9f:	callq  fbe0 <__lll_unlock_wake>
    daa4:	jmp    da73 <pthread_barrier_wait+0x83>
    daa6:	mov    0x10(%rdi),%esi
    daa9:	add    $0x4,%rdi
    daad:	xor    $0x80,%esi
    dab3:	callq  fbe0 <__lll_unlock_wake>
    dab8:	sub    $0x4,%rdi
    dabc:	jmpq   da0f <pthread_barrier_wait+0x1f>
    dac1:	mov    0x10(%rdi),%esi
    dac4:	add    $0x4,%rdi
    dac8:	xor    $0x80,%esi
    dace:	callq  fbe0 <__lll_unlock_wake>
    dad3:	jmpq   da3f <pthread_barrier_wait+0x4f>
    dad8:	nopl   0x0(%rax,%rax,1)
