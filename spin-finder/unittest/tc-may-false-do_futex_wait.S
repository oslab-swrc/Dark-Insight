
000000000000f260 <do_futex_wait>:
    f260:	push   %r12
    f262:	push   %rbp
    f263:	mov    %rsi,%r12
    f266:	push   %rbx
    f267:	mov    %rdi,%rbx
    f26a:	sub    $0x20,%rsp
    f26e:	test   %rsi,%rsi
    f271:	mov    0x8(%rdi),%ebp
    f274:	je     f330 <do_futex_wait+0xd0>
    f27a:	xor    %esi,%esi
    f27c:	mov    %rsp,%rdi
    f27f:	callq  5700 <__gettimeofday@plt>
    f284:	imul   $0xfffffc18,0x8(%rsp),%eax
    f28c:	mov    (%r12),%rdx
    f290:	sub    (%rsp),%edx
    f293:	add    0x8(%r12),%eax
    f298:	js     f320 <do_futex_wait+0xc0>
    f29e:	test   %edx,%edx
    f2a0:	jns    f2b0 <do_futex_wait+0x50>
    f2a2:	add    $0x20,%rsp
    f2a6:	mov    $0x6e,%eax
    f2ab:	pop    %rbx
    f2ac:	pop    %rbp
    f2ad:	pop    %r12
    f2af:	retq   
    f2b0:	movslq %edx,%rdx
    f2b3:	cltq   
    f2b5:	mov    %rdx,0x10(%rsp)
    f2ba:	mov    %rax,0x18(%rsp)
    f2bf:	callq  fa50 <__pthread_enable_asynccancel>
    f2c4:	lea    0x10(%rsp),%r10
    f2c9:	mov    %eax,%r8d
    f2cc:	mov    %ebp,%esi
    f2ce:	mov    $0xca,%ecx
    f2d3:	xor    %edx,%edx
    f2d5:	xor    $0x80,%sil
    f2d9:	mov    %rbx,%rdi
    f2dc:	mov    %ecx,%eax
    f2de:	movslq %esi,%rsi
    f2e1:	syscall 
    f2e3:	cmp    $0xfffffffffffff001,%rax
    f2e9:	mov    %rax,%rbx
    f2ec:	mov    $0x0,%eax
    f2f1:	cmovb  %eax,%ebx
    f2f4:	mov    %r8d,%edi
    f2f7:	callq  fab0 <__pthread_disable_asynccancel>
    f2fc:	cmp    $0xfffffff5,%ebx
    f2ff:	je     f30c <do_futex_wait+0xac>
    f301:	jle    f340 <do_futex_wait+0xe0>
    f303:	cmp    $0xfffffffc,%ebx
    f306:	je     f30c <do_futex_wait+0xac>
    f308:	test   %ebx,%ebx
    f30a:	jne    f345 <do_futex_wait+0xe5>
    f30c:	add    $0x20,%rsp
    f310:	mov    %ebx,%eax
    f312:	neg    %eax
    f314:	pop    %rbx
    f315:	pop    %rbp
    f316:	pop    %r12
    f318:	retq   
    f319:	nopl   0x0(%rax)
    f320:	add    $0x3b9aca00,%eax
    f325:	sub    $0x1,%edx
    f328:	jmpq   f29e <do_futex_wait+0x3e>
    f32d:	nopl   (%rax)
    f330:	callq  fa50 <__pthread_enable_asynccancel>
    f335:	xor    %r10d,%r10d
    f338:	mov    %eax,%r8d
    f33b:	jmp    f2cc <do_futex_wait+0x6c>
    f33d:	nopl   (%rax)
    f340:	cmp    $0xffffff92,%ebx
    f343:	je     f30c <do_futex_wait+0xac>
    f345:	callq  5600 <abort@plt>
    f34a:	nopw   0x0(%rax,%rax,1)
