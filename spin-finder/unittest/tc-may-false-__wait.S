0000000000010790 <__wait>:
   10790:	mov    0x20cc8a(%rip),%eax        # 21d420 <__pthread_multiple_threads>
   10796:	test   %eax,%eax
   10798:	jne    107d8 <__wait+0x48>
   1079a:	mov    %rdi,%rsi
   1079d:	xor    %r10d,%r10d
   107a0:	xor    %edx,%edx
   107a2:	mov    $0xffffffffffffffff,%rdi
   107a9:	mov    $0x3d,%eax
   107ae:	syscall 
   107b0:	cmp    $0xfffffffffffff000,%rax
   107b6:	ja     107c0 <__wait+0x30>
   107b8:	retq   
   107b9:	nopl   0x0(%rax)
   107c0:	mov    0x2087a1(%rip),%rdx        # 218f68 <_DYNAMIC+0x238>
   107c7:	neg    %eax
   107c9:	mov    %eax,%fs:(%rdx)
   107cc:	mov    $0xffffffff,%eax
   107d1:	retq   
   107d2:	nopw   0x0(%rax,%rax,1)
   107d8:	push   %rbx
   107d9:	mov    %rdi,%rbx
   107dc:	sub    $0x10,%rsp
   107e0:	callq  fa50 <__pthread_enable_asynccancel>
   107e5:	xor    %r10d,%r10d
   107e8:	mov    %eax,%r8d
   107eb:	xor    %edx,%edx
   107ed:	mov    %rbx,%rsi
   107f0:	mov    $0xffffffffffffffff,%rdi
   107f7:	mov    $0x3d,%eax
   107fc:	syscall 
   107fe:	cmp    $0xfffffffffffff000,%rax
   10804:	ja     1081c <__wait+0x8c>
   10806:	mov    %r8d,%edi
   10809:	mov    %eax,0xc(%rsp)
   1080d:	callq  fab0 <__pthread_disable_asynccancel>
   10812:	mov    0xc(%rsp),%eax
   10816:	add    $0x10,%rsp
   1081a:	pop    %rbx
   1081b:	retq   
   1081c:	mov    %eax,%edx
   1081e:	mov    0x208743(%rip),%rax        # 218f68 <_DYNAMIC+0x238>
   10825:	neg    %edx
   10827:	mov    %edx,%fs:(%rax)
   1082a:	mov    $0xffffffff,%eax
   1082f:	jmp    10806 <__wait+0x76>
   10831:	nopw   %cs:0x0(%rax,%rax,1)
   1083b:	nopl   0x0(%rax,%rax,1)
