0000000000010840 <waitpid>:
   10840:	mov    0x20cbda(%rip),%eax        # 21d420 <__pthread_multiple_threads>
   10846:	test   %eax,%eax
   10848:	jne    10880 <waitpid+0x40>
   1084a:	xor    %r10d,%r10d
   1084d:	movslq %edx,%rdx
   10850:	movslq %edi,%rdi
   10853:	mov    $0x3d,%eax
   10858:	syscall 
   1085a:	cmp    $0xfffffffffffff000,%rax
   10860:	ja     10868 <waitpid+0x28>
   10862:	retq   
   10863:	nopl   0x0(%rax,%rax,1)
   10868:	mov    0x2086f9(%rip),%rdx        # 218f68 <_DYNAMIC+0x238>
   1086f:	neg    %eax
   10871:	mov    %eax,%fs:(%rdx)
   10874:	mov    $0xffffffff,%eax
   10879:	retq   
   1087a:	nopw   0x0(%rax,%rax,1)
   10880:	push   %r12
   10882:	push   %rbp
   10883:	mov    %edx,%r12d
   10886:	push   %rbx
   10887:	mov    %rsi,%rbp
   1088a:	mov    %edi,%ebx
   1088c:	sub    $0x10,%rsp
   10890:	callq  fa50 <__pthread_enable_asynccancel>
   10895:	xor    %r10d,%r10d
   10898:	mov    %eax,%r8d
   1089b:	movslq %r12d,%rdx
   1089e:	mov    %rbp,%rsi
   108a1:	movslq %ebx,%rdi
   108a4:	mov    $0x3d,%eax
   108a9:	syscall 
   108ab:	cmp    $0xfffffffffffff000,%rax
   108b1:	ja     108cc <waitpid+0x8c>
   108b3:	mov    %r8d,%edi
   108b6:	mov    %eax,0xc(%rsp)
   108ba:	callq  fab0 <__pthread_disable_asynccancel>
   108bf:	mov    0xc(%rsp),%eax
   108c3:	add    $0x10,%rsp
   108c7:	pop    %rbx
   108c8:	pop    %rbp
   108c9:	pop    %r12
   108cb:	retq   
   108cc:	mov    %eax,%edx
   108ce:	mov    0x208693(%rip),%rax        # 218f68 <_DYNAMIC+0x238>
   108d5:	neg    %edx
   108d7:	mov    %edx,%fs:(%rax)
   108da:	mov    $0xffffffff,%eax
   108df:	jmp    108b3 <waitpid+0x73>
   108e1:	nopw   %cs:0x0(%rax,%rax,1)
   108eb:	nopl   0x0(%rax,%rax,1)

