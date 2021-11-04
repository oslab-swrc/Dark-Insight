// TC_OUT pthread_join,0x88e0,0x88f6,0x2d0(%rbx)
0000000000008830 <pthread_join>:
    8830:	test   %rdi,%rdi
    8833:	je     8948 <pthread_join+0x118>
    8839:	mov    0x2d0(%rdi),%eax
    883f:	test   %eax,%eax
    8841:	js     8948 <pthread_join+0x118>
    8847:	cmp    %rdi,0x628(%rdi)
    884e:	mov    $0x16,%eax
    8853:	je     8940 <pthread_join+0x110>
    8859:	push   %r15
    885b:	push   %r14
    885d:	push   %r13
    885f:	push   %r12
    8861:	mov    %rsi,%r12
    8864:	push   %rbp
    8865:	push   %rbx
    8866:	mov    %rdi,%rbx
    8869:	mov    %fs:0x10,%r15
    8872:	sub    $0x38,%rsp
    8876:	nop
    8877:	lea    0x628(%rdi),%r14
    887e:	lea    0x10(%rsp),%r13
    8883:	lea    -0x7a(%rip),%rsi        # 8810 <cleanup>
    888a:	mov    %r14,%rdx
    888d:	mov    %r13,%rdi
    8890:	callq  f670 <_pthread_cleanup_push>
    8895:	callq  fa50 <__pthread_enable_asynccancel>
    889a:	cmp    %r15,%rbx
    889d:	mov    %eax,0xc(%rsp)
    88a1:	je     895d <pthread_join+0x12d>
    88a7:	cmp    %rbx,0x628(%r15)
    88ae:	je     8950 <pthread_join+0x120>
    88b4:	xor    %eax,%eax
    88b6:	lock cmpxchg %r15,(%r14)
    88bb:	jne    8990 <pthread_join+0x160>
    88c1:	movslq 0x2d0(%rbx),%rdx
    88c8:	test   %edx,%edx
    88ca:	je     88f8 <pthread_join+0xc8>
    88cc:	lea    0x2d0(%rbx),%r9
    88d3:	mov    $0xca,%r8d
    88d9:	nopl   0x0(%rax)
    88e0:	xor    %r10d,%r10d
    88e3:	xor    %esi,%esi
    88e5:	mov    %r9,%rdi
    88e8:	mov    %r8d,%eax
    88eb:	syscall 
    88ed:	movslq 0x2d0(%rbx),%rdx
    88f4:	test   %edx,%edx
    88f6:	jne    88e0 <pthread_join+0xb0>
    88f8:	mov    0xc(%rsp),%edi
    88fc:	callq  fab0 <__pthread_disable_asynccancel>
    8901:	xor    %esi,%esi
    8903:	mov    %r13,%rdi
    8906:	callq  f690 <_pthread_cleanup_pop>
    890b:	test   %r12,%r12
    890e:	movl   $0xffffffff,0x2d0(%rbx)
    8918:	je     8925 <pthread_join+0xf5>
    891a:	mov    0x630(%rbx),%rax
    8921:	mov    %rax,(%r12)
    8925:	mov    %rbx,%rdi
    8928:	xor    %ebp,%ebp
    892a:	callq  73f0 <__free_tcb>
    892f:	nop
    8930:	add    $0x38,%rsp
    8934:	mov    %ebp,%eax
    8936:	pop    %rbx
    8937:	pop    %rbp
    8938:	pop    %r12
    893a:	pop    %r13
    893c:	pop    %r14
    893e:	pop    %r15
    8940:	repz retq 
    8942:	nopw   0x0(%rax,%rax,1)
    8948:	mov    $0x3,%eax
    894d:	retq   
    894e:	xchg   %ax,%ax
    8950:	testb  $0x3c,0x308(%rbx)
    8957:	jne    88b4 <pthread_join+0x84>
    895d:	mov    0x308(%r15),%eax
    8964:	mov    $0x23,%ebp
    8969:	and    $0xffffffb9,%eax
    896c:	cmp    $0x8,%eax
    896f:	je     88b4 <pthread_join+0x84>
    8975:	mov    0xc(%rsp),%edi
    8979:	callq  fab0 <__pthread_disable_asynccancel>
    897e:	xor    %esi,%esi
    8980:	mov    %r13,%rdi
    8983:	callq  f690 <_pthread_cleanup_pop>
    8988:	jmp    892f <pthread_join+0xff>
    898a:	nopw   0x0(%rax,%rax,1)
    8990:	mov    $0x16,%ebp
    8995:	jmp    8975 <pthread_join+0x145>
    8997:	nopw   0x0(%rax,%rax,1)
