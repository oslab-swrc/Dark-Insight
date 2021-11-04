// TC_OUT
000000000005c520 <_IO_vfscanf>:
   5c520:	push   %rbp
   5c521:	mov    %rsp,%rbp
   5c524:	push   %r15
   5c526:	push   %r14
   5c528:	push   %r13
   5c52a:	push   %r12
   5c52c:	mov    %rdi,%r15
   5c52f:	push   %rbx
   5c530:	mov    %rsi,%rbx
   5c533:	sub    $0x6a8,%rsp
   5c53a:	mov    0x36386f(%rip),%rax        # 3bfdb0 <_DYNAMIC+0x250>
   5c541:	mov    %rdx,-0x650(%rbp)
   5c548:	mov    %rcx,-0x618(%rbp)
   5c54f:	mov    %fs:(%rax),%rax
   5c553:	mov    %rax,-0x5f8(%rbp)
   5c55a:	mov    (%rax),%rax
   5c55d:	movq   $0x400,-0x438(%rbp)
   5c568:	mov    %rax,-0x648(%rbp)
   5c56f:	lea    -0x450(%rbp),%rax
   5c576:	mov    %rax,-0x610(%rbp)
   5c57d:	add    $0x20,%rax
   5c581:	mov    %rax,-0x440(%rbp)
   5c588:	mov    (%rdx),%rax
   5c58b:	mov    %rax,-0x5a8(%rbp)
   5c592:	mov    0x8(%rdx),%rax
   5c596:	mov    %rax,-0x5a0(%rbp)
   5c59d:	mov    0x10(%rdx),%rax
   5c5a1:	mov    %rax,-0x598(%rbp)
   5c5a8:	mov    0xc0(%rdi),%eax
   5c5ae:	test   %eax,%eax
   5c5b0:	jne    5c840 <_IO_vfscanf+0x320>
   5c5b6:	movl   $0xffffffff,0xc0(%rdi)
   5c5c0:	mov    (%r15),%eax
   5c5c3:	test   $0x4,%al
   5c5c5:	jne    5e6d1 <_IO_vfscanf+0x21b1>
   5c5cb:	test   %rbx,%rbx
   5c5ce:	je     5f6b5 <_IO_vfscanf+0x3195>
   5c5d4:	mov    -0x5f8(%rbp),%rsi
   5c5db:	mov    0x8(%rsi),%rdx
   5c5df:	mov    0x36910b(%rip),%esi        # 3c56f0 <__libc_pthread_functions_init>
   5c5e5:	mov    0x40(%rdx),%rdi
   5c5e9:	mov    %esi,-0x5f0(%rbp)
   5c5ef:	mov    %rdi,-0x670(%rbp)
   5c5f6:	mov    0x48(%rdx),%rdi
   5c5fa:	mov    $0x0,%edx
   5c5ff:	cmpb   $0x0,(%rdi)
   5c602:	cmovne %rdi,%rdx
   5c606:	test   %esi,%esi
   5c608:	mov    %rdx,-0x620(%rbp)
   5c60f:	jne    5ca90 <_IO_vfscanf+0x570>
   5c615:	mov    0x36394c(%rip),%rdx        # 3bff68 <_DYNAMIC+0x408>
   5c61c:	mov    %r15,-0x588(%rbp)
   5c623:	mov    %rdx,-0x590(%rbp)
   5c62a:	and    $0x8000,%eax
   5c62f:	je     5c860 <_IO_vfscanf+0x340>
   5c635:	lea    -0x520(%rbp),%rax
   5c63c:	xor    %r13d,%r13d
   5c63f:	xor    %r11d,%r11d
   5c642:	mov    %r13d,-0x600(%rbp)
   5c649:	movq   $0x0,-0x5e0(%rbp)
   5c654:	xor    %r10d,%r10d
   5c657:	mov    %rax,-0x630(%rbp)
   5c65e:	add    $0xbb,%rax
   5c664:	movl   $0x0,-0x5e4(%rbp)
   5c66e:	movl   $0x0,-0x5e8(%rbp)
   5c678:	movq   $0x0,-0x658(%rbp)
   5c683:	mov    %r11,%r14
   5c686:	movq   $0x0,-0x608(%rbp)
   5c691:	movq   $0x0,-0x640(%rbp)
   5c69c:	mov    %r15,%r13
   5c69f:	movq   $0x0,-0x668(%rbp)
   5c6aa:	movq   $0x0,-0x660(%rbp)
   5c6b5:	mov    %rax,-0x680(%rbp)
   5c6bc:	movzbl (%rbx),%r12d
   5c6c0:	test   %r12b,%r12b
   5c6c3:	je     5e616 <_IO_vfscanf+0x20f6>
   5c6c9:	test   $0x80,%r12b
   5c6cd:	jne    5c790 <_IO_vfscanf+0x270>
   5c6d3:	cmp    $0x25,%r12b
   5c6d7:	lea    0x1(%rbx),%r15
   5c6db:	je     5c8c0 <_IO_vfscanf+0x3a0>
   5c6e1:	mov    -0x5f8(%rbp),%rdi
   5c6e8:	movzbl %r12b,%eax
   5c6ec:	mov    0x68(%rdi),%rdx
   5c6f0:	testb  $0x20,0x1(%rdx,%rax,2)
   5c6f5:	jne    5c828 <_IO_vfscanf+0x308>
   5c6fb:	cmp    $0xffffffff,%r10d
   5c6ff:	je     5cbb0 <_IO_vfscanf+0x690>
   5c705:	mov    0x8(%r13),%rax
   5c709:	cmp    0x10(%r13),%rax
   5c70d:	jae    5e5fd <_IO_vfscanf+0x20dd>
   5c713:	lea    0x1(%rax),%rdx
   5c717:	mov    %rdx,0x8(%r13)
   5c71b:	movzbl (%rax),%eax
   5c71e:	mov    -0x600(%rbp),%esi
   5c724:	add    $0x1,%r14
   5c728:	test   %esi,%esi
   5c72a:	je     5c770 <_IO_vfscanf+0x250>
   5c72c:	mov    -0x5f8(%rbp),%rsi
   5c733:	movslq %eax,%rcx
   5c736:	mov    0x68(%rsi),%rdx
   5c73a:	testb  $0x20,0x1(%rdx,%rcx,2)
   5c73f:	je     5c770 <_IO_vfscanf+0x250>
   5c741:	nopl   0x0(%rax)
   5c748:	mov    0x8(%r13),%rax
   5c74c:	cmp    0x10(%r13),%rax
   5c750:	jae    5cea0 <_IO_vfscanf+0x980>
   5c756:	lea    0x1(%rax),%rcx
   5c75a:	add    $0x1,%r14
   5c75e:	mov    %rcx,0x8(%r13)
   5c762:	movzbl (%rax),%eax
   5c765:	movslq %eax,%rcx
   5c768:	testb  $0x20,0x1(%rdx,%rcx,2)
   5c76d:	jne    5c748 <_IO_vfscanf+0x228>
   5c76f:	nop
   5c770:	movzbl %r12b,%r10d
   5c774:	cmp    %r10d,%eax
   5c777:	jne    5e6a8 <_IO_vfscanf+0x2188>
   5c77d:	movl   $0x0,-0x600(%rbp)
   5c787:	jmpq   5c832 <_IO_vfscanf+0x312>
   5c78c:	nopl   0x0(%rax)
   5c790:	mov    %rbx,%rdi
   5c793:	mov    %r10d,-0x5ec(%rbp)
   5c79a:	callq  8cfc0 <strlen>
   5c79f:	lea    -0x5e0(%rbp),%rdx
   5c7a6:	mov    %rax,%rsi
   5c7a9:	mov    %rbx,%rdi
   5c7ac:	callq  ac3e0 <__mbrlen>
   5c7b1:	test   %eax,%eax
   5c7b3:	mov    -0x5ec(%rbp),%r10d
   5c7ba:	jle    5cbf0 <_IO_vfscanf+0x6d0>
   5c7c0:	cmp    $0xffffffff,%r10d
   5c7c4:	je     5c988 <_IO_vfscanf+0x468>
   5c7ca:	sub    $0x1,%eax
   5c7cd:	mov    %rbx,%r15
   5c7d0:	lea    0x1(%rbx,%rax,1),%r12
   5c7d5:	jmp    5c806 <_IO_vfscanf+0x2e6>
   5c7d7:	nopw   0x0(%rax,%rax,1)
   5c7e0:	lea    0x1(%rax),%rdx
   5c7e4:	mov    %rdx,0x8(%r13)
   5c7e8:	movzbl (%rax),%eax
   5c7eb:	add    $0x1,%r15
   5c7ef:	movzbl -0x1(%r15),%r10d
   5c7f4:	add    $0x1,%r14
   5c7f8:	cmp    %eax,%r10d
   5c7fb:	jne    5e6ee <_IO_vfscanf+0x21ce>
   5c801:	cmp    %r12,%r15
   5c804:	je     5c832 <_IO_vfscanf+0x312>
   5c806:	mov    0x8(%r13),%rax
   5c80a:	cmp    0x10(%r13),%rax
   5c80e:	jb     5c7e0 <_IO_vfscanf+0x2c0>
   5c810:	mov    %r13,%rdi
   5c813:	callq  7d720 <__uflow>
   5c818:	cmp    $0xffffffff,%eax
   5c81b:	jne    5c7eb <_IO_vfscanf+0x2cb>
   5c81d:	mov    %r13,%r15
   5c820:	jmpq   5c99b <_IO_vfscanf+0x47b>
   5c825:	nopl   (%rax)
   5c828:	movl   $0x1,-0x600(%rbp)
   5c832:	mov    %r15,%rbx
   5c835:	jmpq   5c6bc <_IO_vfscanf+0x19c>
   5c83a:	nopw   0x0(%rax,%rax,1)
   5c840:	cmp    $0xffffffff,%eax
   5c843:	je     5c5c0 <_IO_vfscanf+0xa0>
   5c849:	movl   $0xffffffff,-0x5e8(%rbp)
   5c853:	jmpq   5ca50 <_IO_vfscanf+0x530>
   5c858:	nopl   0x0(%rax,%rax,1)
   5c860:	mov    0x88(%r15),%rdx
   5c867:	mov    %fs:0x10,%r8
   5c870:	cmp    0x8(%rdx),%r8
   5c874:	je     5c8b2 <_IO_vfscanf+0x392>
   5c876:	mov    $0x1,%esi
   5c87b:	cmpl   $0x0,0x368e7e(%rip)        # 3c5700 <__libc_multiple_threads>
   5c882:	je     5c88c <_IO_vfscanf+0x36c>
   5c884:	lock cmpxchg %esi,(%rdx)
   5c888:	jne    5c891 <_IO_vfscanf+0x371>
   5c88a:	jmp    5c8a7 <_IO_vfscanf+0x387>
   5c88c:	cmpxchg %esi,(%rdx)
   5c88f:	je     5c8a7 <_IO_vfscanf+0x387>
   5c891:	lea    (%rdx),%rdi
   5c894:	sub    $0x80,%rsp
   5c89b:	callq  115f40 <__lll_lock_wait_private>
   5c8a0:	add    $0x80,%rsp
   5c8a7:	mov    0x88(%r15),%rdx
   5c8ae:	mov    %r8,0x8(%rdx)
   5c8b2:	addl   $0x1,0x4(%rdx)
   5c8b6:	jmpq   5c635 <_IO_vfscanf+0x115>
   5c8bb:	nopl   0x0(%rax,%rax,1)
   5c8c0:	mov    -0x440(%rbp),%rax
   5c8c7:	mov    %rax,-0x450(%rbp)
   5c8ce:	add    -0x438(%rbp),%rax
   5c8d5:	mov    %rax,-0x448(%rbp)
   5c8dc:	movzbl 0x1(%rbx),%eax
   5c8e0:	sub    $0x30,%eax
   5c8e3:	cmp    $0x9,%eax
   5c8e6:	ja     5cac0 <_IO_vfscanf+0x5a0>
   5c8ec:	mov    %eax,%esi
   5c8ee:	mov    %eax,-0x638(%rbp)
   5c8f4:	movzbl 0x2(%rbx),%eax
   5c8f8:	lea    0x2(%rbx),%r15
   5c8fc:	lea    -0x30(%rax),%edx
   5c8ff:	mov    %eax,%ebx
   5c901:	cmp    $0x9,%edx
   5c904:	ja     5c92f <_IO_vfscanf+0x40f>
   5c906:	mov    %esi,%edx
   5c908:	nopl   0x0(%rax,%rax,1)
   5c910:	lea    (%rdx,%rdx,4),%edx
   5c913:	add    $0x1,%r15
   5c917:	lea    -0x30(%rax,%rdx,2),%edx
   5c91b:	movzbl (%r15),%eax
   5c91f:	lea    -0x30(%rax),%ecx
   5c922:	mov    %eax,%ebx
   5c924:	cmp    $0x9,%ecx
   5c927:	jbe    5c910 <_IO_vfscanf+0x3f0>
   5c929:	mov    %edx,-0x638(%rbp)
   5c92f:	cmp    $0x24,%bl
   5c932:	je     5cd48 <_IO_vfscanf+0x828>
   5c938:	mov    -0x638(%rbp),%r12d
   5c93f:	movl   $0x0,-0x5ec(%rbp)
   5c949:	movl   $0x0,-0x638(%rbp)
   5c953:	test   %r12d,%r12d
   5c956:	mov    $0xffffffff,%eax
   5c95b:	cmove  %eax,%r12d
   5c95f:	lea    -0x4c(%rbx),%eax
   5c962:	lea    0x1(%r15),%rdx
   5c966:	cmp    $0x2e,%al
   5c968:	ja     5cf77 <_IO_vfscanf+0xa57>
   5c96e:	lea    0x126ea7(%rip),%rcx        # 18381c <jump_table+0x5c>
   5c975:	movzbl %al,%eax
   5c978:	movslq (%rcx,%rax,4),%rax
   5c97c:	add    %rcx,%rax
   5c97f:	jmpq   *%rax
   5c981:	nopl   0x0(%rax)
   5c988:	mov    0x3634d9(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5c98f:	mov    -0x5e4(%rbp),%esi
   5c995:	mov    %r13,%r15
   5c998:	mov    %esi,%fs:(%rax)
   5c99b:	mov    -0x5e8(%rbp),%eax
   5c9a1:	mov    $0x1,%r13d
   5c9a7:	test   %eax,%eax
   5c9a9:	jne    5c9b8 <_IO_vfscanf+0x498>
   5c9ab:	movl   $0xffffffff,-0x5e8(%rbp)
   5c9b5:	nopl   (%rax)
   5c9b8:	testl  $0x8000,(%r15)
   5c9bf:	jne    5ca00 <_IO_vfscanf+0x4e0>
   5c9c1:	mov    0x88(%r15),%rdx
   5c9c8:	subl   $0x1,0x4(%rdx)
   5c9cc:	jne    5ca00 <_IO_vfscanf+0x4e0>
   5c9ce:	movq   $0x0,0x8(%rdx)
   5c9d6:	cmpl   $0x0,0x368d23(%rip)        # 3c5700 <__libc_multiple_threads>
   5c9dd:	je     5c9e6 <_IO_vfscanf+0x4c6>
   5c9df:	lock decl (%rdx)
   5c9e2:	jne    5c9ea <_IO_vfscanf+0x4ca>
   5c9e4:	jmp    5ca00 <_IO_vfscanf+0x4e0>
   5c9e6:	decl   (%rdx)
   5c9e8:	je     5ca00 <_IO_vfscanf+0x4e0>
   5c9ea:	lea    (%rdx),%rdi
   5c9ed:	sub    $0x80,%rsp
   5c9f4:	callq  115f70 <__lll_unlock_wake_private>
   5c9f9:	add    $0x80,%rsp
   5ca00:	mov    -0x5f0(%rbp),%eax
   5ca06:	test   %eax,%eax
   5ca08:	jne    5ca68 <_IO_vfscanf+0x548>
   5ca0a:	mov    -0x610(%rbp),%rax
   5ca11:	mov    -0x440(%rbp),%rdi
   5ca18:	add    $0x20,%rax
   5ca1c:	cmp    %rax,%rdi
   5ca1f:	je     5ca26 <_IO_vfscanf+0x506>
   5ca21:	callq  1f9c0 <*ABS*+0x911b0@plt+0x40>
   5ca26:	mov    -0x618(%rbp),%rax
   5ca2d:	test   %rax,%rax
   5ca30:	je     5ca35 <_IO_vfscanf+0x515>
   5ca32:	or     %r13d,(%rax)
   5ca35:	cmpl   $0xffffffff,-0x5e8(%rbp)
   5ca3c:	je     5ced8 <_IO_vfscanf+0x9b8>
   5ca42:	cmpq   $0x0,-0x608(%rbp)
   5ca4a:	jne    5cf38 <_IO_vfscanf+0xa18>
   5ca50:	mov    -0x5e8(%rbp),%eax
   5ca56:	lea    -0x28(%rbp),%rsp
   5ca5a:	pop    %rbx
   5ca5b:	pop    %r12
   5ca5d:	pop    %r13
   5ca5f:	pop    %r14
   5ca61:	pop    %r15
   5ca63:	pop    %rbp
   5ca64:	retq   
   5ca65:	nopl   (%rax)
   5ca68:	mov    0x368c49(%rip),%rax        # 3c56b8 <__libc_pthread_functions+0x178>
   5ca6f:	lea    -0x590(%rbp),%rdi
   5ca76:	xor    %esi,%esi
   5ca78:	ror    $0x11,%rax
   5ca7c:	xor    %fs:0x30,%rax
   5ca85:	callq  *%rax
   5ca87:	jmp    5ca0a <_IO_vfscanf+0x4ea>
   5ca89:	nopl   0x0(%rax)
   5ca90:	mov    0x368c19(%rip),%rax        # 3c56b0 <__libc_pthread_functions+0x170>
   5ca97:	lea    -0x590(%rbp),%rdi
   5ca9e:	mov    %r15,%rdx
   5caa1:	ror    $0x11,%rax
   5caa5:	xor    %fs:0x30,%rax
   5caae:	mov    0x3634b3(%rip),%rsi        # 3bff68 <_DYNAMIC+0x408>
   5cab5:	callq  *%rax
   5cab7:	mov    (%r15),%eax
   5caba:	jmpq   5c62a <_IO_vfscanf+0x10a>
   5cabf:	nop
   5cac0:	movl   $0x0,-0x638(%rbp)
   5caca:	xor    %ecx,%ecx
   5cacc:	cmpq   $0x0,-0x620(%rbp)
   5cad4:	movabs $0x400000009,%rdx
   5cade:	je     5cb33 <_IO_vfscanf+0x613>
   5cae0:	movzbl (%r15),%ebx
   5cae4:	lea    -0x27(%rbx),%eax
   5cae7:	cmp    $0x22,%al
   5cae9:	jbe    5cb68 <_IO_vfscanf+0x648>
   5caeb:	movzbl %bl,%eax
   5caee:	mov    %ecx,-0x5ec(%rbp)
   5caf4:	mov    $0xffffffff,%r12d
   5cafa:	sub    $0x30,%eax
   5cafd:	cmp    $0x9,%eax
   5cb00:	ja     5c95f <_IO_vfscanf+0x43f>
   5cb06:	xor    %r12d,%r12d
   5cb09:	nopl   0x0(%rax)
   5cb10:	lea    (%r12,%r12,4),%edx
   5cb14:	add    $0x1,%r15
   5cb18:	lea    (%rax,%rdx,2),%r12d
   5cb1c:	movzbl (%r15),%eax
   5cb20:	mov    %eax,%ebx
   5cb22:	sub    $0x30,%eax
   5cb25:	cmp    $0x9,%eax
   5cb28:	jbe    5cb10 <_IO_vfscanf+0x5f0>
   5cb2a:	jmpq   5c953 <_IO_vfscanf+0x433>
   5cb2f:	nop
   5cb30:	or     $0x8,%ecx
   5cb33:	movzbl (%r15),%ebx
   5cb37:	lea    -0x27(%rbx),%eax
   5cb3a:	cmp    $0x22,%al
   5cb3c:	ja     5caeb <_IO_vfscanf+0x5cb>
   5cb3e:	bt     %rax,%rdx
   5cb42:	jae    5caeb <_IO_vfscanf+0x5cb>
   5cb44:	add    $0x1,%r15
   5cb48:	cmp    $0x2a,%bl
   5cb4b:	je     5cb30 <_IO_vfscanf+0x610>
   5cb4d:	mov    %ecx,%eax
   5cb4f:	or     $0x4,%ah
   5cb52:	cmp    $0x49,%bl
   5cb55:	movzbl (%r15),%ebx
   5cb59:	cmove  %eax,%ecx
   5cb5c:	lea    -0x27(%rbx),%eax
   5cb5f:	cmp    $0x22,%al
   5cb61:	ja     5caeb <_IO_vfscanf+0x5cb>
   5cb63:	jmp    5cb3e <_IO_vfscanf+0x61e>
   5cb65:	nopl   (%rax)
   5cb68:	bt     %rax,%rdx
   5cb6c:	jae    5caeb <_IO_vfscanf+0x5cb>
   5cb72:	add    $0x1,%r15
   5cb76:	cmp    $0x2a,%bl
   5cb79:	je     5cb90 <_IO_vfscanf+0x670>
   5cb7b:	cmp    $0x49,%bl
   5cb7e:	je     5cba0 <_IO_vfscanf+0x680>
   5cb80:	mov    %ecx,%eax
   5cb82:	or     $0x80,%al
   5cb84:	cmp    $0x27,%bl
   5cb87:	cmove  %eax,%ecx
   5cb8a:	jmpq   5cae0 <_IO_vfscanf+0x5c0>
   5cb8f:	nop
   5cb90:	or     $0x8,%ecx
   5cb93:	jmpq   5cae0 <_IO_vfscanf+0x5c0>
   5cb98:	nopl   0x0(%rax,%rax,1)
   5cba0:	or     $0x4,%ch
   5cba3:	jmpq   5cae0 <_IO_vfscanf+0x5c0>
   5cba8:	nopl   0x0(%rax,%rax,1)
   5cbb0:	mov    0x3632b1(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5cbb7:	mov    -0x5e4(%rbp),%esi
   5cbbd:	mov    %r13,%r15
   5cbc0:	mov    %esi,%fs:(%rax)
   5cbc3:	mov    -0x5e8(%rbp),%r14d
   5cbca:	mov    $0x1,%r13d
   5cbd0:	test   %r14d,%r14d
   5cbd3:	jne    5c9b8 <_IO_vfscanf+0x498>
   5cbd9:	movl   $0xffffffff,-0x5e8(%rbp)
   5cbe3:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5cbe8:	nopl   0x0(%rax,%rax,1)
   5cbf0:	movzbl (%rbx),%r12d
   5cbf4:	jmpq   5c6d3 <_IO_vfscanf+0x1b3>
   5cbf9:	nopl   0x0(%rax)
   5cc00:	orl    $0x1,-0x5ec(%rbp)
   5cc07:	movzbl 0x1(%r15),%ebx
   5cc0c:	test   %bl,%bl
   5cc0e:	je     5e5ef <_IO_vfscanf+0x20cf>
   5cc14:	mov    -0x600(%rbp),%ecx
   5cc1a:	lea    0x1(%rdx),%r15
   5cc1e:	test   %ecx,%ecx
   5cc20:	jne    5cc2d <_IO_vfscanf+0x70d>
   5cc22:	lea    -0x43(%rbx),%eax
   5cc25:	cmp    $0x2b,%al
   5cc27:	jbe    5cdbc <_IO_vfscanf+0x89c>
   5cc2d:	mov    0x363234(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5cc34:	mov    %r12d,-0x600(%rbp)
   5cc3b:	mov    $0xffffffff,%r8d
   5cc41:	mov    %bl,-0x678(%rbp)
   5cc47:	mov    -0x5e4(%rbp),%r12d
   5cc4e:	mov    -0x5f8(%rbp),%rbx
   5cc55:	mov    %fs:(%rax),%esi
   5cc58:	mov    %rax,%r9
   5cc5b:	mov    %rax,-0x628(%rbp)
   5cc62:	movl   $0x0,%fs:(%rax)
   5cc69:	mov    %r10d,%eax
   5cc6c:	jmp    5cc9b <_IO_vfscanf+0x77b>
   5cc6e:	xchg   %ax,%ax
   5cc70:	mov    0x8(%r13),%rax
   5cc74:	cmp    0x10(%r13),%rax
   5cc78:	jae    5ce20 <_IO_vfscanf+0x900>
   5cc7e:	lea    0x1(%rax),%rcx
   5cc82:	add    $0x1,%r14
   5cc86:	mov    %rcx,0x8(%r13)
   5cc8a:	movzbl (%rax),%eax
   5cc8d:	mov    0x68(%rbx),%rdi
   5cc91:	movslq %eax,%rcx
   5cc94:	testb  $0x20,0x1(%rdi,%rcx,2)
   5cc99:	je     5ccbe <_IO_vfscanf+0x79e>
   5cc9b:	cmp    $0xffffffff,%eax
   5cc9e:	jne    5cc70 <_IO_vfscanf+0x750>
   5cca0:	mov    %fs:(%r9),%eax
   5cca4:	cmp    $0x4,%eax
   5cca7:	je     5ce77 <_IO_vfscanf+0x957>
   5ccad:	mov    0x68(%rbx),%rdi
   5ccb1:	mov    %r8d,%eax
   5ccb4:	movslq %eax,%rcx
   5ccb7:	testb  $0x20,0x1(%rdi,%rcx,2)
   5ccbc:	jne    5cc9b <_IO_vfscanf+0x77b>
   5ccbe:	mov    %eax,%r10d
   5ccc1:	mov    -0x628(%rbp),%rax
   5ccc8:	mov    %r12d,-0x5e4(%rbp)
   5cccf:	cmp    $0xffffffff,%r10d
   5ccd3:	mov    -0x600(%rbp),%r12d
   5ccda:	movzbl -0x678(%rbp),%ebx
   5cce1:	mov    %esi,%fs:(%rax)
   5cce4:	je     5cf58 <_IO_vfscanf+0xa38>
   5ccea:	lea    -0x1(%r14),%r8
   5ccee:	movzbl %r10b,%esi
   5ccf2:	mov    %r13,%rdi
   5ccf5:	sub    $0x25,%ebx
   5ccf8:	mov    %rdx,-0x688(%rbp)
   5ccff:	mov    %r10d,-0x600(%rbp)
   5cd06:	mov    %r8,-0x678(%rbp)
   5cd0d:	callq  7e5a0 <_IO_sputbackc>
   5cd12:	cmp    $0x53,%bl
   5cd15:	ja     5e17e <_IO_vfscanf+0x1c5e>
   5cd1b:	lea    0x126bb6(%rip),%rcx        # 1838d8 <jump_table+0x118>
   5cd22:	movzbl %bl,%ebx
   5cd25:	mov    -0x600(%rbp),%r10d
   5cd2c:	mov    -0x678(%rbp),%r8
   5cd33:	mov    -0x688(%rbp),%rdx
   5cd3a:	movslq (%rcx,%rbx,4),%rax
   5cd3e:	add    %rcx,%rax
   5cd41:	jmpq   *%rax
   5cd43:	nopl   0x0(%rax,%rax,1)
   5cd48:	add    $0x1,%r15
   5cd4c:	jmpq   5caca <_IO_vfscanf+0x5aa>
   5cd51:	movzbl 0x1(%r15),%ebx
   5cd56:	cmp    $0x6c,%bl
   5cd59:	je     5de3c <_IO_vfscanf+0x191c>
   5cd5f:	orl    $0x1,-0x5ec(%rbp)
   5cd66:	jmpq   5cc0c <_IO_vfscanf+0x6ec>
   5cd6b:	movzbl 0x1(%r15),%ebx
   5cd70:	cmp    $0x68,%bl
   5cd73:	je     5de69 <_IO_vfscanf+0x1949>
   5cd79:	orl    $0x4,-0x5ec(%rbp)
   5cd80:	jmpq   5cc0c <_IO_vfscanf+0x6ec>
   5cd85:	movzbl 0x1(%r15),%eax
   5cd8a:	mov    %eax,%ecx
   5cd8c:	and    $0xfffffff7,%ecx
   5cd8f:	cmp    $0x53,%cl
   5cd92:	je     5de8f <_IO_vfscanf+0x196f>
   5cd98:	cmp    $0x73,%al
   5cd9a:	je     5de8f <_IO_vfscanf+0x196f>
   5cda0:	mov    %rdx,%rax
   5cda3:	mov    %r15,%rdx
   5cda6:	mov    %rax,%r15
   5cda9:	mov    -0x600(%rbp),%eax
   5cdaf:	test   %eax,%eax
   5cdb1:	jne    5cc2d <_IO_vfscanf+0x70d>
   5cdb7:	mov    $0x1e,%eax
   5cdbc:	movabs $0x80101000001,%rcx
   5cdc6:	bt     %rax,%rcx
   5cdca:	jae    5cc2d <_IO_vfscanf+0x70d>
   5cdd0:	sub    $0x43,%ebx
   5cdd3:	cmp    $0x2b,%bl
   5cdd6:	ja     5de81 <_IO_vfscanf+0x1961>
   5cddc:	lea    0x126c45(%rip),%rcx        # 183a28 <jump_table+0x268>
   5cde3:	movzbl %bl,%ebx
   5cde6:	movslq (%rcx,%rbx,4),%rax
   5cdea:	add    %rcx,%rax
   5cded:	jmpq   *%rax
   5cdef:	orl    $0x3,-0x5ec(%rbp)
   5cdf6:	movzbl 0x1(%r15),%ebx
   5cdfb:	jmpq   5cc0c <_IO_vfscanf+0x6ec>
   5ce00:	movzbl 0x1(%r15),%ebx
   5ce05:	cmp    $0x6c,%bl
   5ce08:	je     5de51 <_IO_vfscanf+0x1931>
   5ce0e:	orl    $0x2000,-0x5ec(%rbp)
   5ce18:	jmpq   5cc0c <_IO_vfscanf+0x6ec>
   5ce1d:	nopl   (%rax)
   5ce20:	mov    %r13,%rdi
   5ce23:	mov    %r9,-0x698(%rbp)
   5ce2a:	mov    %esi,-0x690(%rbp)
   5ce30:	mov    %rdx,-0x688(%rbp)
   5ce37:	mov    %r8d,-0x5e4(%rbp)
   5ce3e:	callq  7d720 <__uflow>
   5ce43:	cmp    $0xffffffff,%eax
   5ce46:	mov    -0x5e4(%rbp),%r8d
   5ce4d:	mov    -0x688(%rbp),%rdx
   5ce54:	mov    -0x690(%rbp),%esi
   5ce5a:	mov    -0x698(%rbp),%r9
   5ce61:	jne    63716 <_IO_vfscanf+0x71f6>
   5ce67:	mov    %fs:(%r9),%r12d
   5ce6b:	mov    %r12d,%eax
   5ce6e:	cmp    $0x4,%eax
   5ce71:	jne    5ccad <_IO_vfscanf+0x78d>
   5ce77:	mov    -0x5e8(%rbp),%edx
   5ce7d:	mov    %r13,%r15
   5ce80:	mov    $0x1,%r13d
   5ce86:	test   %edx,%edx
   5ce88:	jne    5c9b8 <_IO_vfscanf+0x498>
   5ce8e:	movl   $0xffffffff,-0x5e8(%rbp)
   5ce98:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5ce9d:	nopl   (%rax)
   5cea0:	mov    %r13,%rdi
   5cea3:	callq  7d720 <__uflow>
   5cea8:	cmp    $0xffffffff,%eax
   5ceab:	jne    63dc8 <_IO_vfscanf+0x78a8>
   5ceb1:	mov    -0x5e8(%rbp),%edi
   5ceb7:	mov    %r13,%r15
   5ceba:	mov    -0x600(%rbp),%r13d
   5cec1:	test   %edi,%edi
   5cec3:	cmovne %edi,%eax
   5cec6:	mov    %eax,-0x5e8(%rbp)
   5cecc:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5ced1:	nopl   0x0(%rax)
   5ced8:	cmpq   $0x0,-0x660(%rbp)
   5cee0:	mov    -0x660(%rbp),%r12
   5cee7:	je     5c849 <_IO_vfscanf+0x329>
   5ceed:	nopl   (%rax)
   5cef0:	xor    %ebx,%ebx
   5cef2:	cmpq   $0x0,(%r12)
   5cef7:	je     5cf23 <_IO_vfscanf+0xa03>
   5cef9:	nopl   0x0(%rax)
   5cf00:	mov    0x10(%r12,%rbx,8),%rax
   5cf05:	mov    (%rax),%rdi
   5cf08:	callq  1f9c0 <*ABS*+0x911b0@plt+0x40>
   5cf0d:	mov    0x10(%r12,%rbx,8),%rax
   5cf12:	add    $0x1,%rbx
   5cf16:	cmp    %rbx,(%r12)
   5cf1a:	movq   $0x0,(%rax)
   5cf21:	ja     5cf00 <_IO_vfscanf+0x9e0>
   5cf23:	mov    0x8(%r12),%r12
   5cf28:	test   %r12,%r12
   5cf2b:	jne    5cef0 <_IO_vfscanf+0x9d0>
   5cf2d:	jmpq   5c849 <_IO_vfscanf+0x329>
   5cf32:	nopw   0x0(%rax,%rax,1)
   5cf38:	mov    -0x608(%rbp),%rbx
   5cf3f:	mov    (%rbx),%rdi
   5cf42:	callq  1f9c0 <*ABS*+0x911b0@plt+0x40>
   5cf47:	movq   $0x0,(%rbx)
   5cf4e:	jmpq   5ca50 <_IO_vfscanf+0x530>
   5cf53:	nopl   0x0(%rax,%rax,1)
   5cf58:	sub    $0x25,%ebx
   5cf5b:	cmp    $0x53,%bl
   5cf5e:	ja     5e18c <_IO_vfscanf+0x1c6c>
   5cf64:	lea    0x126b6d(%rip),%rcx        # 183ad8 <jump_table+0x318>
   5cf6b:	movzbl %bl,%ebx
   5cf6e:	movslq (%rcx,%rbx,4),%rax
   5cf72:	add    %rcx,%rax
   5cf75:	jmpq   *%rax
   5cf77:	mov    %r15,%rdx
   5cf7a:	jmpq   5cc0c <_IO_vfscanf+0x6ec>
   5cf7f:	mov    -0x628(%rbp),%rdx
   5cf86:	mov    %r13,%r15
   5cf89:	mov    -0x5e4(%rbp),%eax
   5cf8f:	mov    %eax,%fs:(%rdx)
   5cf92:	mov    -0x5e8(%rbp),%r8d
   5cf99:	mov    $0x1,%r13d
   5cf9f:	test   %r8d,%r8d
   5cfa2:	jne    5c9b8 <_IO_vfscanf+0x498>
   5cfa8:	movl   $0xffffffff,-0x5e8(%rbp)
   5cfb2:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5cfb7:	mov    %r8,%r14
   5cfba:	mov    -0x5ec(%rbp),%esi
   5cfc0:	mov    %esi,%eax
   5cfc2:	and    $0x8,%eax
   5cfc5:	mov    %eax,-0x600(%rbp)
   5cfcb:	jne    5d08a <_IO_vfscanf+0xb6a>
   5cfd1:	mov    %esi,%eax
   5cfd3:	test   $0x21,%ah
   5cfd6:	je     5f5a8 <_IO_vfscanf+0x3088>
   5cfdc:	mov    -0x638(%rbp),%eax
   5cfe2:	test   %eax,%eax
   5cfe4:	jne    5fc48 <_IO_vfscanf+0x3728>
   5cfea:	mov    -0x5a8(%rbp),%edx
   5cff0:	cmp    $0x2f,%edx
   5cff3:	ja     620fb <_IO_vfscanf+0x5bdb>
   5cff9:	mov    %edx,%eax
   5cffb:	add    -0x598(%rbp),%rax
   5d002:	add    $0x8,%edx
   5d005:	mov    %edx,-0x5a8(%rbp)
   5d00b:	mov    (%rax),%rax
   5d00e:	mov    %rax,-0x608(%rbp)
   5d015:	mov    %rax,%rbx
   5d018:	test   %rbx,%rbx
   5d01b:	mov    %r10d,-0x628(%rbp)
   5d022:	je     620a0 <_IO_vfscanf+0x5b80>
   5d028:	mov    $0x190,%edi
   5d02d:	callq  1f998 <*ABS*+0x911b0@plt+0x18>
   5d032:	test   %rax,%rax
   5d035:	mov    %rax,(%rbx)
   5d038:	je     61200 <_IO_vfscanf+0x4ce0>
   5d03e:	mov    -0x660(%rbp),%rdi
   5d045:	mov    -0x628(%rbp),%r10d
   5d04c:	test   %rdi,%rdi
   5d04f:	je     609ef <_IO_vfscanf+0x44cf>
   5d055:	mov    (%rdi),%rdx
   5d058:	cmp    $0x20,%rdx
   5d05c:	je     609ef <_IO_vfscanf+0x44cf>
   5d062:	lea    0x1(%rdx),%rcx
   5d066:	mov    %rdi,%rsi
   5d069:	mov    -0x608(%rbp),%rdi
   5d070:	mov    %rcx,(%rsi)
   5d073:	mov    %rax,-0x640(%rbp)
   5d07a:	movq   $0x64,-0x658(%rbp)
   5d085:	mov    %rdi,0x10(%rsi,%rdx,8)
   5d08a:	cmp    $0xffffffff,%r10d
   5d08e:	je     5f2ce <_IO_vfscanf+0x2dae>
   5d094:	mov    0x8(%r13),%rax
   5d098:	cmp    0x10(%r13),%rax
   5d09c:	jae    60a24 <_IO_vfscanf+0x4504>
   5d0a2:	lea    0x1(%rax),%rdx
   5d0a6:	mov    %rdx,0x8(%r13)
   5d0aa:	movzbl (%rax),%r10d
   5d0ae:	mov    -0x630(%rbp),%rax
   5d0b5:	mov    -0x5f8(%rbp),%rdi
   5d0bc:	add    $0x1,%r14
   5d0c0:	movq   $0x0,(%rax)
   5d0c7:	mov    0x68(%rdi),%rdx
   5d0cb:	movslq %r10d,%rax
   5d0ce:	testb  $0x20,0x1(%rdx,%rax,2)
   5d0d3:	jne    5edc8 <_IO_vfscanf+0x28a8>
   5d0d9:	mov    -0x5ec(%rbp),%eax
   5d0df:	mov    %r15,-0x638(%rbp)
   5d0e6:	mov    -0x630(%rbp),%r15
   5d0ed:	mov    %r12d,-0x678(%rbp)
   5d0f4:	mov    %r10d,%r12d
   5d0f7:	and    $0x2100,%eax
   5d0fc:	mov    %eax,-0x688(%rbp)
   5d102:	lea    -0x570(%rbp),%rax
   5d109:	mov    %rax,-0x628(%rbp)
   5d110:	mov    -0x600(%rbp),%eax
   5d116:	mov    $0x0,%ebx
   5d11b:	mov    %r12b,-0x570(%rbp)
   5d122:	test   %eax,%eax
   5d124:	cmove  -0x640(%rbp),%rbx
   5d12c:	mov    %r13,%rax
   5d12f:	mov    %r12d,%r13d
   5d132:	mov    %rax,%r12
   5d135:	nopl   (%rax)
   5d138:	mov    -0x628(%rbp),%rsi
   5d13f:	mov    %r15,%rcx
   5d142:	mov    $0x1,%edx
   5d147:	mov    %rbx,%rdi
   5d14a:	callq  ac400 <__mbrtowc>
   5d14f:	cmp    $0xfffffffffffffffe,%rax
   5d153:	jne    5ed14 <_IO_vfscanf+0x27f4>
   5d159:	mov    0x8(%r12),%rax
   5d15e:	cmp    0x10(%r12),%rax
   5d163:	jae    5e7a6 <_IO_vfscanf+0x2286>
   5d169:	lea    0x1(%rax),%rdx
   5d16d:	mov    %rdx,0x8(%r12)
   5d172:	movzbl (%rax),%r13d
   5d176:	add    $0x1,%r14
   5d17a:	mov    %r13b,-0x570(%rbp)
   5d181:	jmp    5d138 <_IO_vfscanf+0xc18>
   5d183:	mov    %r8,%r14
   5d186:	mov    -0x5ec(%rbp),%edi
   5d18c:	cmp    $0xffffffff,%r12d
   5d190:	mov    $0x1,%eax
   5d195:	cmove  %eax,%r12d
   5d199:	mov    %edi,%eax
   5d19b:	and    $0x8,%eax
   5d19e:	mov    %eax,-0x600(%rbp)
   5d1a4:	jne    5d274 <_IO_vfscanf+0xd54>
   5d1aa:	mov    %edi,%eax
   5d1ac:	test   $0x21,%ah
   5d1af:	je     5f54e <_IO_vfscanf+0x302e>
   5d1b5:	mov    -0x638(%rbp),%ebx
   5d1bb:	test   %ebx,%ebx
   5d1bd:	jne    5fca0 <_IO_vfscanf+0x3780>
   5d1c3:	mov    -0x5a8(%rbp),%edx
   5d1c9:	cmp    $0x2f,%edx
   5d1cc:	ja     63741 <_IO_vfscanf+0x7221>
   5d1d2:	mov    %edx,%eax
   5d1d4:	add    -0x598(%rbp),%rax
   5d1db:	add    $0x8,%edx
   5d1de:	mov    %edx,-0x5a8(%rbp)
   5d1e4:	mov    (%rax),%rax
   5d1e7:	mov    %rax,-0x608(%rbp)
   5d1ee:	mov    %rax,%rbx
   5d1f1:	test   %rbx,%rbx
   5d1f4:	mov    %r10d,-0x628(%rbp)
   5d1fb:	je     63733 <_IO_vfscanf+0x7213>
   5d201:	cmp    $0x400,%r12d
   5d208:	mov    $0x400,%eax
   5d20d:	cmovle %r12d,%eax
   5d211:	cltq   
   5d213:	lea    0x0(,%rax,4),%rdi
   5d21b:	mov    %rax,-0x658(%rbp)
   5d222:	callq  1f998 <*ABS*+0x911b0@plt+0x18>
   5d227:	test   %rax,%rax
   5d22a:	mov    %rax,(%rbx)
   5d22d:	je     61683 <_IO_vfscanf+0x5163>
   5d233:	mov    -0x660(%rbp),%rdi
   5d23a:	mov    -0x628(%rbp),%r10d
   5d241:	test   %rdi,%rdi
   5d244:	je     6101e <_IO_vfscanf+0x4afe>
   5d24a:	mov    (%rdi),%rdx
   5d24d:	cmp    $0x20,%rdx
   5d251:	je     6101e <_IO_vfscanf+0x4afe>
   5d257:	lea    0x1(%rdx),%rcx
   5d25b:	mov    %rdi,%rsi
   5d25e:	mov    -0x608(%rbp),%rdi
   5d265:	mov    %rcx,(%rsi)
   5d268:	mov    %rax,-0x640(%rbp)
   5d26f:	mov    %rdi,0x10(%rsi,%rdx,8)
   5d274:	cmp    $0xffffffff,%r10d
   5d278:	je     5f306 <_IO_vfscanf+0x2de6>
   5d27e:	mov    0x8(%r13),%rax
   5d282:	cmp    0x10(%r13),%rax
   5d286:	jae    609d3 <_IO_vfscanf+0x44b3>
   5d28c:	lea    0x1(%rax),%rdx
   5d290:	mov    %rdx,0x8(%r13)
   5d294:	movzbl (%rax),%r10d
   5d298:	mov    -0x630(%rbp),%rax
   5d29f:	add    $0x1,%r14
   5d2a3:	movq   $0x0,-0x638(%rbp)
   5d2ae:	mov    %r15,-0x678(%rbp)
   5d2b5:	mov    %r10d,%ebx
   5d2b8:	movq   $0x0,(%rax)
   5d2bf:	mov    -0x5ec(%rbp),%eax
   5d2c5:	and    $0x2100,%eax
   5d2ca:	mov    %eax,-0x5ec(%rbp)
   5d2d0:	lea    -0x1(%r12),%eax
   5d2d5:	mov    %eax,-0x628(%rbp)
   5d2db:	movslq %r12d,%rax
   5d2de:	lea    -0x570(%rbp),%r12
   5d2e5:	mov    %rax,-0x688(%rbp)
   5d2ec:	mov    -0x600(%rbp),%r10d
   5d2f3:	mov    %bl,-0x570(%rbp)
   5d2f9:	test   %r10d,%r10d
   5d2fc:	jne    5d334 <_IO_vfscanf+0xe14>
   5d2fe:	mov    -0x5ec(%rbp),%r9d
   5d305:	test   %r9d,%r9d
   5d308:	je     5d334 <_IO_vfscanf+0xe14>
   5d30a:	mov    -0x608(%rbp),%rax
   5d311:	mov    (%rax),%rdi
   5d314:	mov    -0x658(%rbp),%rax
   5d31b:	lea    0x0(,%rax,4),%rdx
   5d323:	lea    (%rdi,%rdx,1),%rax
   5d327:	cmp    %rax,-0x640(%rbp)
   5d32e:	je     61142 <_IO_vfscanf+0x4c22>
   5d334:	mov    -0x600(%rbp),%r8d
   5d33b:	mov    $0x0,%r15d
   5d341:	mov    %r13,%rax
   5d344:	mov    %ebx,%r13d
   5d347:	mov    %rax,%rbx
   5d34a:	test   %r8d,%r8d
   5d34d:	cmove  -0x640(%rbp),%r15
   5d355:	nopl   (%rax)
   5d358:	mov    -0x630(%rbp),%rcx
   5d35f:	mov    $0x1,%edx
   5d364:	mov    %r12,%rsi
   5d367:	mov    %r15,%rdi
   5d36a:	callq  ac400 <__mbrtowc>
   5d36f:	cmp    $0xfffffffffffffffe,%rax
   5d373:	jne    5ee70 <_IO_vfscanf+0x2950>
   5d379:	mov    0x8(%rbx),%rax
   5d37d:	cmp    0x10(%rbx),%rax
   5d381:	jae    5e776 <_IO_vfscanf+0x2256>
   5d387:	lea    0x1(%rax),%rdx
   5d38b:	mov    %rdx,0x8(%rbx)
   5d38f:	movzbl (%rax),%r13d
   5d393:	add    $0x1,%r14
   5d397:	mov    %r13b,-0x570(%rbp)
   5d39e:	jmp    5d358 <_IO_vfscanf+0xe38>
   5d3a0:	mov    %r8,%r14
   5d3a3:	mov    -0x5ec(%rbp),%ebx
   5d3a9:	mov    %ebx,%eax
   5d3ab:	and    $0x1,%eax
   5d3ae:	mov    %eax,-0x600(%rbp)
   5d3b4:	jne    5d186 <_IO_vfscanf+0xc66>
   5d3ba:	cmp    $0xffffffff,%r12d
   5d3be:	mov    $0x1,%eax
   5d3c3:	cmove  %eax,%r12d
   5d3c7:	mov    %ebx,%eax
   5d3c9:	and    $0x8,%ebx
   5d3cc:	jne    5d499 <_IO_vfscanf+0xf79>
   5d3d2:	test   $0x21,%ah
   5d3d5:	je     60bd8 <_IO_vfscanf+0x46b8>
   5d3db:	mov    -0x638(%rbp),%eax
   5d3e1:	test   %eax,%eax
   5d3e3:	jne    6155c <_IO_vfscanf+0x503c>
   5d3e9:	mov    -0x5a8(%rbp),%edx
   5d3ef:	cmp    $0x2f,%edx
   5d3f2:	ja     62fbe <_IO_vfscanf+0x6a9e>
   5d3f8:	mov    %edx,%eax
   5d3fa:	add    -0x598(%rbp),%rax
   5d401:	add    $0x8,%edx
   5d404:	mov    %edx,-0x5a8(%rbp)
   5d40a:	mov    (%rax),%rax
   5d40d:	mov    %rax,-0x608(%rbp)
   5d414:	cmpq   $0x0,-0x608(%rbp)
   5d41c:	mov    %r10d,-0x628(%rbp)
   5d423:	je     62fb0 <_IO_vfscanf+0x6a90>
   5d429:	cmp    $0x400,%r12d
   5d430:	mov    $0x400,%eax
   5d435:	cmovle %r12d,%eax
   5d439:	movslq %eax,%rdi
   5d43c:	mov    %rdi,-0x658(%rbp)
   5d443:	callq  1f998 <*ABS*+0x911b0@plt+0x18>
   5d448:	mov    -0x608(%rbp),%rsi
   5d44f:	test   %rax,%rax
   5d452:	mov    %rax,(%rsi)
   5d455:	je     61eb3 <_IO_vfscanf+0x5993>
   5d45b:	mov    -0x660(%rbp),%rsi
   5d462:	mov    -0x628(%rbp),%r10d
   5d469:	test   %rsi,%rsi
   5d46c:	je     61b11 <_IO_vfscanf+0x55f1>
   5d472:	mov    (%rsi),%rdx
   5d475:	cmp    $0x20,%rdx
   5d479:	lea    0x1(%rdx),%rcx
   5d47d:	je     61b11 <_IO_vfscanf+0x55f1>
   5d483:	mov    -0x608(%rbp),%rdi
   5d48a:	mov    %rcx,(%rsi)
   5d48d:	mov    %rax,-0x668(%rbp)
   5d494:	mov    %rdi,0x10(%rsi,%rdx,8)
   5d499:	cmp    $0xffffffff,%r10d
   5d49d:	je     6093e <_IO_vfscanf+0x441e>
   5d4a3:	mov    0x8(%r13),%rax
   5d4a7:	cmp    0x10(%r13),%rax
   5d4ab:	jae    617ea <_IO_vfscanf+0x52ca>
   5d4b1:	lea    0x1(%rax),%rdx
   5d4b5:	mov    %rdx,0x8(%r13)
   5d4b9:	movzbl (%rax),%r10d
   5d4bd:	test   %ebx,%ebx
   5d4bf:	lea    0x1(%r14),%rax
   5d4c3:	je     5facd <_IO_vfscanf+0x35ad>
   5d4c9:	cmp    $0x1,%r12d
   5d4cd:	jle    63692 <_IO_vfscanf+0x7172>
   5d4d3:	lea    -0x2(%r12),%edx
   5d4d8:	lea    0x2(%r14,%rdx,1),%rbx
   5d4dd:	mov    %rax,%r14
   5d4e0:	jmp    5d4fa <_IO_vfscanf+0xfda>
   5d4e2:	lea    0x1(%rax),%rdx
   5d4e6:	mov    %rdx,0x8(%r13)
   5d4ea:	movzbl (%rax),%eax
   5d4ed:	add    $0x1,%r14
   5d4f1:	cmp    %rbx,%r14
   5d4f4:	je     6165f <_IO_vfscanf+0x513f>
   5d4fa:	mov    0x8(%r13),%rax
   5d4fe:	cmp    0x10(%r13),%rax
   5d502:	jb     5d4e2 <_IO_vfscanf+0xfc2>
   5d504:	mov    %r13,%rdi
   5d507:	callq  7d720 <__uflow>
   5d50c:	cmp    $0xffffffff,%eax
   5d50f:	jne    5d4ed <_IO_vfscanf+0xfcd>
   5d511:	mov    %eax,%r10d
   5d514:	mov    0x36294d(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5d51b:	mov    %fs:(%rax),%eax
   5d51e:	mov    %eax,-0x5e4(%rbp)
   5d524:	jmpq   5c832 <_IO_vfscanf+0x312>
   5d529:	mov    %r8,%r14
   5d52c:	mov    -0x5ec(%rbp),%esi
   5d532:	mov    %esi,%eax
   5d534:	and    $0x8,%eax
   5d537:	mov    %eax,-0x600(%rbp)
   5d53d:	jne    5c77d <_IO_vfscanf+0x25d>
   5d543:	mov    %esi,%eax
   5d545:	test   $0x1,%al
   5d547:	je     5f865 <_IO_vfscanf+0x3345>
   5d54d:	mov    -0x638(%rbp),%eax
   5d553:	test   %eax,%eax
   5d555:	jne    60f19 <_IO_vfscanf+0x49f9>
   5d55b:	mov    -0x5a8(%rbp),%edx
   5d561:	cmp    $0x2f,%edx
   5d564:	ja     639d0 <_IO_vfscanf+0x74b0>
   5d56a:	mov    %edx,%eax
   5d56c:	add    -0x598(%rbp),%rax
   5d573:	add    $0x8,%edx
   5d576:	mov    %edx,-0x5a8(%rbp)
   5d57c:	mov    (%rax),%rax
   5d57f:	mov    %r14,(%rax)
   5d582:	jmpq   5c832 <_IO_vfscanf+0x312>
   5d587:	mov    %r8,%r14
   5d58a:	mov    -0x5ec(%rbp),%esi
   5d590:	mov    %esi,%eax
   5d592:	and    $0x1,%eax
   5d595:	mov    %eax,-0x600(%rbp)
   5d59b:	mov    %esi,%eax
   5d59d:	je     5f068 <_IO_vfscanf+0x2b48>
   5d5a3:	and    $0x8,%eax
   5d5a6:	mov    %eax,-0x678(%rbp)
   5d5ac:	jne    5d67d <_IO_vfscanf+0x115d>
   5d5b2:	mov    %esi,%eax
   5d5b4:	test   $0x21,%ah
   5d5b7:	je     60e71 <_IO_vfscanf+0x4951>
   5d5bd:	mov    -0x638(%rbp),%eax
   5d5c3:	test   %eax,%eax
   5d5c5:	jne    610dd <_IO_vfscanf+0x4bbd>
   5d5cb:	mov    -0x5a8(%rbp),%ecx
   5d5d1:	cmp    $0x2f,%ecx
   5d5d4:	ja     63195 <_IO_vfscanf+0x6c75>
   5d5da:	mov    %ecx,%eax
   5d5dc:	add    -0x598(%rbp),%rax
   5d5e3:	add    $0x8,%ecx
   5d5e6:	mov    %ecx,-0x5a8(%rbp)
   5d5ec:	mov    (%rax),%rax
   5d5ef:	mov    %rax,-0x608(%rbp)
   5d5f6:	mov    %rax,%rbx
   5d5f9:	test   %rbx,%rbx
   5d5fc:	mov    %r10d,-0x638(%rbp)
   5d603:	mov    %rdx,-0x628(%rbp)
   5d60a:	je     63187 <_IO_vfscanf+0x6c67>
   5d610:	mov    $0x190,%edi
   5d615:	callq  1f998 <*ABS*+0x911b0@plt+0x18>
   5d61a:	test   %rax,%rax
   5d61d:	mov    %rax,(%rbx)
   5d620:	je     61e7d <_IO_vfscanf+0x595d>
   5d626:	mov    -0x660(%rbp),%rsi
   5d62d:	mov    -0x628(%rbp),%rdx
   5d634:	mov    -0x638(%rbp),%r10d
   5d63b:	test   %rsi,%rsi
   5d63e:	je     61e48 <_IO_vfscanf+0x5928>
   5d644:	mov    (%rsi),%rcx
   5d647:	cmp    $0x20,%rcx
   5d64b:	lea    0x1(%rcx),%rsi
   5d64f:	je     61e48 <_IO_vfscanf+0x5928>
   5d655:	mov    -0x660(%rbp),%rdi
   5d65c:	mov    %rax,-0x640(%rbp)
   5d663:	movq   $0x64,-0x658(%rbp)
   5d66e:	mov    %rsi,(%rdi)
   5d671:	mov    -0x608(%rbp),%rsi
   5d678:	mov    %rsi,0x10(%rdi,%rcx,8)
   5d67d:	cmpb   $0x5e,0x1(%rdx)
   5d681:	movb   $0x0,-0x638(%rbp)
   5d688:	je     5f75d <_IO_vfscanf+0x323d>
   5d68e:	test   %r12d,%r12d
   5d691:	mov    $0x7fffffff,%eax
   5d696:	mov    $0x1,%edx
   5d69b:	cmovs  %eax,%r12d
   5d69f:	mov    -0x610(%rbp),%rax
   5d6a6:	mov    $0x100,%esi
   5d6ab:	mov    %r10d,-0x628(%rbp)
   5d6b2:	lea    0x10(%rax),%rdi
   5d6b6:	callq  8b060 <__libc_scratch_buffer_set_array_size>
   5d6bb:	test   %al,%al
   5d6bd:	je     610c0 <_IO_vfscanf+0x4ba0>
   5d6c3:	mov    -0x440(%rbp),%rax
   5d6ca:	lea    0x8(%rax),%rdi
   5d6ce:	movq   $0x0,(%rax)
   5d6d5:	movq   $0x0,0xf8(%rax)
   5d6e0:	and    $0xfffffffffffffff8,%rdi
   5d6e4:	sub    %rdi,%rax
   5d6e7:	lea    0x100(%rax),%ecx
   5d6ed:	xor    %eax,%eax
   5d6ef:	shr    $0x3,%ecx
   5d6f2:	rep stos %rax,%es:(%rdi)
   5d6f5:	movzbl (%r15),%eax
   5d6f9:	mov    -0x628(%rbp),%r10d
   5d700:	cmp    $0x5d,%al
   5d702:	je     5f354 <_IO_vfscanf+0x2e34>
   5d708:	cmp    $0x2d,%al
   5d70a:	jne    5d723 <_IO_vfscanf+0x1203>
   5d70c:	jmpq   5f354 <_IO_vfscanf+0x2e34>
   5d711:	nopl   0x0(%rax)
   5d718:	mov    -0x440(%rbp),%rdx
   5d71f:	movb   $0x1,(%rdx,%rax,1)
   5d723:	add    $0x1,%r15
   5d727:	movzbl -0x1(%r15),%eax
   5d72c:	test   %al,%al
   5d72e:	je     5f1a6 <_IO_vfscanf+0x2c86>
   5d734:	cmp    $0x5d,%al
   5d736:	je     5e848 <_IO_vfscanf+0x2328>
   5d73c:	cmp    $0x2d,%al
   5d73e:	jne    5d718 <_IO_vfscanf+0x11f8>
   5d740:	movzbl (%r15),%ecx
   5d744:	cmp    $0x5d,%cl
   5d747:	je     5d718 <_IO_vfscanf+0x11f8>
   5d749:	test   %cl,%cl
   5d74b:	je     5d718 <_IO_vfscanf+0x11f8>
   5d74d:	movzbl -0x2(%r15),%edx
   5d752:	cmp    %cl,%dl
   5d754:	ja     5d718 <_IO_vfscanf+0x11f8>
   5d756:	jae    5d723 <_IO_vfscanf+0x1203>
   5d758:	nopl   0x0(%rax,%rax,1)
   5d760:	mov    -0x440(%rbp),%rcx
   5d767:	movzbl %dl,%eax
   5d76a:	add    $0x1,%edx
   5d76d:	movb   $0x1,(%rcx,%rax,1)
   5d771:	cmp    %dl,(%r15)
   5d774:	ja     5d760 <_IO_vfscanf+0x1240>
   5d776:	jmp    5d723 <_IO_vfscanf+0x1203>
   5d778:	mov    %r14,%r8
   5d77b:	movl   $0x10,-0x600(%rbp)
   5d785:	cmp    $0xffffffff,%r10d
   5d789:	je     5e743 <_IO_vfscanf+0x2223>
   5d78f:	mov    0x8(%r13),%rax
   5d793:	cmp    0x10(%r13),%rax
   5d797:	jae    5f2a4 <_IO_vfscanf+0x2d84>
   5d79d:	lea    0x1(%rax),%rdx
   5d7a1:	mov    %rdx,0x8(%r13)
   5d7a5:	movzbl (%rax),%r10d
   5d7a9:	lea    -0x2b(%r10),%eax
   5d7ad:	lea    0x1(%r8),%r14
   5d7b1:	and    $0xfffffffd,%eax
   5d7b4:	jne    5d804 <_IO_vfscanf+0x12e4>
   5d7b6:	mov    -0x450(%rbp),%rax
   5d7bd:	mov    -0x448(%rbp),%rbx
   5d7c4:	cmp    %rax,%rbx
   5d7c7:	je     5f6eb <_IO_vfscanf+0x31cb>
   5d7cd:	lea    0x1(%rax),%rdx
   5d7d1:	mov    %rdx,-0x450(%rbp)
   5d7d8:	mov    %r10b,(%rax)
   5d7db:	xor    %eax,%eax
   5d7dd:	test   %r12d,%r12d
   5d7e0:	setg   %al
   5d7e3:	sub    %eax,%r12d
   5d7e6:	mov    0x8(%r13),%rax
   5d7ea:	cmp    0x10(%r13),%rax
   5d7ee:	jae    5e5a8 <_IO_vfscanf+0x2088>
   5d7f4:	lea    0x1(%rax),%rdx
   5d7f8:	mov    %rdx,0x8(%r13)
   5d7fc:	movzbl (%rax),%r10d
   5d800:	lea    0x2(%r8),%r14
   5d804:	test   %r12d,%r12d
   5d807:	je     5e5da <_IO_vfscanf+0x20ba>
   5d80d:	cmp    $0x30,%r10d
   5d811:	jne    5e5da <_IO_vfscanf+0x20ba>
   5d817:	xor    %eax,%eax
   5d819:	test   %r12d,%r12d
   5d81c:	mov    -0x448(%rbp),%rbx
   5d823:	setg   %al
   5d826:	sub    %eax,%r12d
   5d829:	mov    -0x450(%rbp),%rax
   5d830:	cmp    %rax,%rbx
   5d833:	je     5f76d <_IO_vfscanf+0x324d>
   5d839:	lea    0x1(%rax),%rdx
   5d83d:	mov    %rdx,-0x450(%rbp)
   5d844:	movb   $0x30,(%rax)
   5d847:	mov    0x8(%r13),%rax
   5d84b:	cmp    0x10(%r13),%rax
   5d84f:	jae    5ff4d <_IO_vfscanf+0x3a2d>
   5d855:	lea    0x1(%rax),%rdx
   5d859:	mov    %rdx,0x8(%r13)
   5d85d:	movzbl (%rax),%r10d
   5d861:	add    $0x1,%r14
   5d865:	test   %r12d,%r12d
   5d868:	je     5d883 <_IO_vfscanf+0x1363>
   5d86a:	mov    -0x5f8(%rbp),%rsi
   5d871:	movzbl %r10b,%eax
   5d875:	mov    0x70(%rsi),%rdx
   5d879:	cmpl   $0x78,(%rdx,%rax,4)
   5d87d:	je     5f920 <_IO_vfscanf+0x3400>
   5d883:	mov    -0x600(%rbp),%ecx
   5d889:	test   %ecx,%ecx
   5d88b:	je     5e734 <_IO_vfscanf+0x2214>
   5d891:	cmpl   $0xa,-0x600(%rbp)
   5d898:	jne    5d8b4 <_IO_vfscanf+0x1394>
   5d89a:	testl  $0x400,-0x5ec(%rbp)
   5d8a4:	jne    60080 <_IO_vfscanf+0x3b60>
   5d8aa:	movl   $0xa,-0x600(%rbp)
   5d8b4:	mov    -0x5ec(%rbp),%eax
   5d8ba:	mov    %r15,-0x6a0(%rbp)
   5d8c1:	mov    %r10d,%ebx
   5d8c4:	mov    %r12d,%r15d
   5d8c7:	and    $0x80,%eax
   5d8cc:	mov    %eax,-0x690(%rbp)
   5d8d2:	mov    -0x610(%rbp),%rax
   5d8d9:	add    $0x10,%rax
   5d8dd:	mov    %rax,-0x698(%rbp)
   5d8e4:	nopl   0x0(%rax)
   5d8e8:	cmp    $0xffffffff,%ebx
   5d8eb:	je     5d91a <_IO_vfscanf+0x13fa>
   5d8ed:	test   %r15d,%r15d
   5d8f0:	je     5d91a <_IO_vfscanf+0x13fa>
   5d8f2:	cmpl   $0x10,-0x600(%rbp)
   5d8f9:	je     5e1a0 <_IO_vfscanf+0x1c80>
   5d8ff:	lea    -0x30(%rbx),%eax
   5d902:	cmp    $0x9,%eax
   5d905:	ja     5e218 <_IO_vfscanf+0x1cf8>
   5d90b:	lea    -0x2f(%rbx),%eax
   5d90e:	cmp    -0x600(%rbp),%eax
   5d914:	jle    5e1b9 <_IO_vfscanf+0x1c99>
   5d91a:	mov    %r15d,%r12d
   5d91d:	mov    %ebx,%r10d
   5d920:	mov    -0x6a0(%rbp),%r15
   5d927:	mov    -0x450(%rbp),%rbx
   5d92e:	test   %rbx,%rbx
   5d931:	je     5f6c8 <_IO_vfscanf+0x31a8>
   5d937:	mov    -0x440(%rbp),%rax
   5d93e:	cmp    %rax,%rbx
   5d941:	je     5e7d6 <_IO_vfscanf+0x22b6>
   5d947:	mov    %rbx,%rdx
   5d94a:	sub    %rax,%rdx
   5d94d:	cmp    $0x1,%rdx
   5d951:	je     5f000 <_IO_vfscanf+0x2ae0>
   5d957:	cmp    $0xffffffff,%r10d
   5d95b:	je     5e9f0 <_IO_vfscanf+0x24d0>
   5d961:	movzbl %r10b,%esi
   5d965:	mov    %r13,%rdi
   5d968:	mov    %r10d,-0x628(%rbp)
   5d96f:	callq  7e5a0 <_IO_sputbackc>
   5d974:	mov    -0x628(%rbp),%r10d
   5d97b:	sub    $0x1,%r14
   5d97f:	mov    -0x450(%rbp),%rbx
   5d986:	cmp    -0x448(%rbp),%rbx
   5d98d:	je     5ff38 <_IO_vfscanf+0x3a18>
   5d993:	lea    0x1(%rbx),%rax
   5d997:	mov    %rax,-0x450(%rbp)
   5d99e:	movb   $0x0,(%rbx)
   5d9a1:	cmpq   $0x0,-0x450(%rbp)
   5d9a9:	je     5f96f <_IO_vfscanf+0x344f>
   5d9af:	mov    -0x5ec(%rbp),%ecx
   5d9b5:	mov    %r10d,-0x628(%rbp)
   5d9bc:	lea    -0x5c8(%rbp),%rsi
   5d9c3:	mov    -0x600(%rbp),%edx
   5d9c9:	mov    -0x440(%rbp),%rdi
   5d9d0:	mov    %ecx,%ebx
   5d9d2:	and    $0x80,%ecx
   5d9d8:	and    $0x40,%ebx
   5d9db:	je     5e723 <_IO_vfscanf+0x2203>
   5d9e1:	callq  3b7c0 <__strtol_internal>
   5d9e6:	mov    -0x628(%rbp),%r10d
   5d9ed:	mov    -0x440(%rbp),%rsi
   5d9f4:	cmp    %rsi,-0x5c8(%rbp)
   5d9fb:	je     5f992 <_IO_vfscanf+0x3472>
   5da01:	mov    -0x5ec(%rbp),%edi
   5da07:	mov    %edi,%esi
   5da09:	and    $0x8,%esi
   5da0c:	mov    %esi,-0x600(%rbp)
   5da12:	jne    5c77d <_IO_vfscanf+0x25d>
   5da18:	test   %ebx,%ebx
   5da1a:	je     5ef92 <_IO_vfscanf+0x2a72>
   5da20:	mov    %edi,%esi
   5da22:	and    $0x1,%esi
   5da25:	je     5f8b7 <_IO_vfscanf+0x3397>
   5da2b:	mov    -0x638(%rbp),%esi
   5da31:	test   %esi,%esi
   5da33:	jne    60cc5 <_IO_vfscanf+0x47a5>
   5da39:	mov    -0x5a8(%rbp),%ecx
   5da3f:	cmp    $0x2f,%ecx
   5da42:	ja     635bd <_IO_vfscanf+0x709d>
   5da48:	mov    %ecx,%edx
   5da4a:	add    -0x598(%rbp),%rdx
   5da51:	add    $0x8,%ecx
   5da54:	mov    %ecx,-0x5a8(%rbp)
   5da5a:	mov    (%rdx),%rdx
   5da5d:	mov    %rax,(%rdx)
   5da60:	addl   $0x1,-0x5e8(%rbp)
   5da67:	jmpq   5c832 <_IO_vfscanf+0x312>
   5da6c:	mov    %r8,%r14
   5da6f:	orl    $0x40,-0x5ec(%rbp)
   5da76:	mov    %r14,%r8
   5da79:	movl   $0x0,-0x600(%rbp)
   5da83:	jmpq   5d785 <_IO_vfscanf+0x1265>
   5da88:	mov    %r8,%r14
   5da8b:	orl    $0x40,-0x5ec(%rbp)
   5da92:	mov    %r14,%r8
   5da95:	movl   $0xa,-0x600(%rbp)
   5da9f:	jmpq   5d785 <_IO_vfscanf+0x1265>
   5daa4:	cmp    $0xffffffff,%r10d
   5daa8:	je     5fabe <_IO_vfscanf+0x359e>
   5daae:	mov    0x8(%r13),%rax
   5dab2:	cmp    0x10(%r13),%rax
   5dab6:	jae    61667 <_IO_vfscanf+0x5147>
   5dabc:	lea    0x1(%rax),%rdx
   5dac0:	add    $0x1,%r14
   5dac4:	test   %r12d,%r12d
   5dac7:	mov    %rdx,0x8(%r13)
   5dacb:	movzbl (%rax),%r10d
   5dacf:	jle    5dad5 <_IO_vfscanf+0x15b5>
   5dad1:	sub    $0x1,%r12d
   5dad5:	lea    -0x2b(%r10),%eax
   5dad9:	and    $0xfffffffd,%eax
   5dadc:	jne    5f1b4 <_IO_vfscanf+0x2c94>
   5dae2:	cmp    $0x2d,%r10d
   5dae6:	sete   -0x6a0(%rbp)
   5daed:	test   %r12d,%r12d
   5daf0:	je     61e2a <_IO_vfscanf+0x590a>
   5daf6:	mov    0x8(%r13),%rax
   5dafa:	cmp    0x10(%r13),%rax
   5dafe:	jae    61e08 <_IO_vfscanf+0x58e8>
   5db04:	lea    0x1(%rax),%rdx
   5db08:	mov    %rdx,0x8(%r13)
   5db0c:	movzbl (%rax),%r10d
   5db10:	xor    %eax,%eax
   5db12:	add    $0x1,%r14
   5db16:	test   %r12d,%r12d
   5db19:	setg   %al
   5db1c:	sub    %eax,%r12d
   5db1f:	mov    -0x5f8(%rbp),%rsi
   5db26:	movzbl %r10b,%eax
   5db2a:	mov    0x70(%rsi),%rdx
   5db2e:	mov    (%rdx,%rax,4),%eax
   5db31:	cmp    $0x6e,%eax
   5db34:	je     5f9a0 <_IO_vfscanf+0x3480>
   5db3a:	cmp    $0x69,%eax
   5db3d:	je     5fcf0 <_IO_vfscanf+0x37d0>
   5db43:	test   %r12d,%r12d
   5db46:	je     5fb34 <_IO_vfscanf+0x3614>
   5db4c:	cmp    $0x30,%r10d
   5db50:	jne    5fb34 <_IO_vfscanf+0x3614>
   5db56:	mov    -0x450(%rbp),%rax
   5db5d:	cmp    -0x448(%rbp),%rax
   5db64:	je     61922 <_IO_vfscanf+0x5402>
   5db6a:	lea    0x1(%rax),%rdx
   5db6e:	mov    %rdx,-0x450(%rbp)
   5db75:	movb   $0x30,(%rax)
   5db78:	mov    0x8(%r13),%rax
   5db7c:	cmp    0x10(%r13),%rax
   5db80:	jae    63285 <_IO_vfscanf+0x6d65>
   5db86:	lea    0x1(%rax),%rdx
   5db8a:	mov    %rdx,0x8(%r13)
   5db8e:	movzbl (%rax),%r10d
   5db92:	add    $0x1,%r14
   5db96:	xor    %eax,%eax
   5db98:	test   %r12d,%r12d
   5db9b:	setg   %al
   5db9e:	sub    %eax,%r12d
   5dba1:	je     5dbbc <_IO_vfscanf+0x169c>
   5dba3:	mov    -0x5f8(%rbp),%rsi
   5dbaa:	movzbl %r10b,%eax
   5dbae:	mov    0x70(%rsi),%rdx
   5dbb2:	cmpl   $0x78,(%rdx,%rax,4)
   5dbb6:	je     61990 <_IO_vfscanf+0x5470>
   5dbbc:	movl   $0x65,-0x6a4(%rbp)
   5dbc6:	movb   $0x65,-0x688(%rbp)
   5dbcd:	mov    $0x1,%edx
   5dbd2:	mov    -0x5ec(%rbp),%esi
   5dbd8:	mov    %r15,-0x698(%rbp)
   5dbdf:	mov    %r12d,%r15d
   5dbe2:	movb   $0x0,-0x690(%rbp)
   5dbe9:	movb   $0x0,-0x678(%rbp)
   5dbf0:	mov    %r10d,%r12d
   5dbf3:	mov    %dl,-0x628(%rbp)
   5dbf9:	mov    %esi,%eax
   5dbfb:	and    $0x800,%eax
   5dc00:	mov    %eax,-0x600(%rbp)
   5dc06:	mov    %esi,%eax
   5dc08:	and    $0x80,%eax
   5dc0d:	mov    %eax,-0x6b8(%rbp)
   5dc13:	mov    -0x610(%rbp),%rax
   5dc1a:	setne  -0x6c8(%rbp)
   5dc21:	add    $0x10,%rax
   5dc25:	mov    %rax,-0x6b0(%rbp)
   5dc2c:	jmp    5dc82 <_IO_vfscanf+0x1762>
   5dc2e:	cmp    -0x448(%rbp),%rbx
   5dc35:	je     60ed0 <_IO_vfscanf+0x49b0>
   5dc3b:	lea    0x1(%rbx),%rax
   5dc3f:	mov    %rax,-0x450(%rbp)
   5dc46:	mov    %r12b,(%rbx)
   5dc49:	test   %r15d,%r15d
   5dc4c:	je     61130 <_IO_vfscanf+0x4c10>
   5dc52:	movb   $0x1,-0x628(%rbp)
   5dc59:	mov    0x8(%r13),%rax
   5dc5d:	cmp    0x10(%r13),%rax
   5dc61:	jae    5f7c3 <_IO_vfscanf+0x32a3>
   5dc67:	lea    0x1(%rax),%rcx
   5dc6b:	mov    %rcx,0x8(%r13)
   5dc6f:	movzbl (%rax),%r12d
   5dc73:	xor    %eax,%eax
   5dc75:	add    $0x1,%r14
   5dc79:	test   %r15d,%r15d
   5dc7c:	setg   %al
   5dc7f:	sub    %eax,%r15d
   5dc82:	mov    -0x450(%rbp),%rbx
   5dc89:	test   %rbx,%rbx
   5dc8c:	je     5f7f9 <_IO_vfscanf+0x32d9>
   5dc92:	lea    -0x30(%r12),%eax
   5dc97:	cmp    $0x9,%eax
   5dc9a:	jbe    5dc2e <_IO_vfscanf+0x170e>
   5dc9c:	cmpb   $0x0,-0x690(%rbp)
   5dca3:	je     5ea64 <_IO_vfscanf+0x2544>
   5dca9:	movzbl -0x688(%rbp),%eax
   5dcb0:	cmp    -0x1(%rbx),%al
   5dcb3:	je     60974 <_IO_vfscanf+0x4454>
   5dcb9:	test   %r15d,%r15d
   5dcbc:	mov    $0x7fffffff,%ecx
   5dcc1:	mov    -0x670(%rbp),%rax
   5dcc8:	cmovg  %r15d,%ecx
   5dccc:	cmpb   $0x0,-0x678(%rbp)
   5dcd3:	jne    5f1c0 <_IO_vfscanf+0x2ca0>
   5dcd9:	movzbl (%rax),%edi
   5dcdc:	cmp    %edi,%r12d
   5dcdf:	mov    %edi,%eax
   5dce1:	mov    %edi,%esi
   5dce3:	jne    637e7 <_IO_vfscanf+0x72c7>
   5dce9:	mov    -0x670(%rbp),%rax
   5dcf0:	cmpb   $0x0,0x1(%rax)
   5dcf4:	lea    0x1(%rax),%rbx
   5dcf8:	jne    5dd33 <_IO_vfscanf+0x1813>
   5dcfa:	jmpq   5dd82 <_IO_vfscanf+0x1862>
   5dcff:	nop
   5dd00:	lea    0x1(%rax),%rdx
   5dd04:	mov    %rdx,0x8(%r13)
   5dd08:	movzbl (%rax),%esi
   5dd0b:	movzbl (%rbx),%r12d
   5dd0f:	add    $0x1,%r14
   5dd13:	sub    $0x1,%ecx
   5dd16:	cmp    %esi,%r12d
   5dd19:	mov    %r12d,%eax
   5dd1c:	jne    610d5 <_IO_vfscanf+0x4bb5>
   5dd22:	add    $0x1,%rbx
   5dd26:	cmpb   $0x0,(%rbx)
   5dd29:	je     5dd78 <_IO_vfscanf+0x1858>
   5dd2b:	test   %ecx,%ecx
   5dd2d:	je     5fb4c <_IO_vfscanf+0x362c>
   5dd33:	mov    0x8(%r13),%rax
   5dd37:	cmp    0x10(%r13),%rax
   5dd3b:	jb     5dd00 <_IO_vfscanf+0x17e0>
   5dd3d:	mov    %r13,%rdi
   5dd40:	mov    %ecx,-0x6c0(%rbp)
   5dd46:	callq  7d720 <__uflow>
   5dd4b:	cmp    $0xffffffff,%eax
   5dd4e:	mov    %eax,%r12d
   5dd51:	mov    -0x6c0(%rbp),%ecx
   5dd57:	jne    63dc1 <_IO_vfscanf+0x78a1>
   5dd5d:	mov    0x362104(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5dd64:	mov    %fs:(%rax),%eax
   5dd67:	mov    %eax,-0x5e4(%rbp)
   5dd6d:	movzbl (%rbx),%eax
   5dd70:	test   %al,%al
   5dd72:	jne    5fb4c <_IO_vfscanf+0x362c>
   5dd78:	mov    -0x670(%rbp),%rax
   5dd7f:	movzbl (%rax),%esi
   5dd82:	test   %sil,%sil
   5dd85:	mov    %rax,%r11
   5dd88:	mov    %ecx,%ebx
   5dd8a:	jne    5ddb7 <_IO_vfscanf+0x1897>
   5dd8c:	jmpq   5f340 <_IO_vfscanf+0x2e20>
   5dd91:	nopl   0x0(%rax)
   5dd98:	lea    0x1(%rax),%rdx
   5dd9c:	mov    %rdx,-0x450(%rbp)
   5dda3:	mov    %sil,(%rax)
   5dda6:	add    $0x1,%r11
   5ddaa:	movzbl (%r11),%esi
   5ddae:	test   %sil,%sil
   5ddb1:	je     5f33e <_IO_vfscanf+0x2e1e>
   5ddb7:	mov    -0x450(%rbp),%rax
   5ddbe:	cmp    -0x448(%rbp),%rax
   5ddc5:	jne    5dd98 <_IO_vfscanf+0x1878>
   5ddc7:	test   %rax,%rax
   5ddca:	mov    %sil,-0x6d0(%rbp)
   5ddd1:	je     5dda6 <_IO_vfscanf+0x1886>
   5ddd3:	sub    -0x440(%rbp),%rax
   5ddda:	mov    -0x6b0(%rbp),%rdi
   5dde1:	mov    %r11,-0x6c0(%rbp)
   5dde8:	mov    %rax,-0x678(%rbp)
   5ddef:	callq  8afb0 <__libc_scratch_buffer_grow_preserve>
   5ddf4:	test   %al,%al
   5ddf6:	mov    -0x6c0(%rbp),%r11
   5ddfd:	movzbl -0x6d0(%rbp),%esi
   5de04:	je     617da <_IO_vfscanf+0x52ba>
   5de0a:	mov    -0x440(%rbp),%rax
   5de11:	mov    %rax,%rdx
   5de14:	add    -0x678(%rbp),%rax
   5de1b:	add    -0x438(%rbp),%rdx
   5de22:	mov    %rdx,-0x448(%rbp)
   5de29:	lea    0x1(%rax),%rdx
   5de2d:	mov    %rdx,-0x450(%rbp)
   5de34:	mov    %sil,(%rax)
   5de37:	jmpq   5dda6 <_IO_vfscanf+0x1886>
   5de3c:	lea    0x2(%r15),%rdx
   5de40:	orl    $0x3,-0x5ec(%rbp)
   5de47:	movzbl 0x2(%r15),%ebx
   5de4c:	jmpq   5cc0c <_IO_vfscanf+0x6ec>
   5de51:	lea    0x2(%r15),%rdx
   5de55:	orl    $0x2001,-0x5ec(%rbp)
   5de5f:	movzbl 0x2(%r15),%ebx
   5de64:	jmpq   5cc0c <_IO_vfscanf+0x6ec>
   5de69:	lea    0x2(%r15),%rdx
   5de6d:	orl    $0x200,-0x5ec(%rbp)
   5de77:	movzbl 0x2(%r15),%ebx
   5de7c:	jmpq   5cc0c <_IO_vfscanf+0x6ec>
   5de81:	mov    %r13,%r15
   5de84:	mov    $0x2,%r13d
   5de8a:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5de8f:	testb  $0x10,0x74(%r13)
   5de94:	jne    5cda0 <_IO_vfscanf+0x880>
   5de9a:	orl    $0x100,-0x5ec(%rbp)
   5dea4:	mov    %eax,%ebx
   5dea6:	jmpq   5cc0c <_IO_vfscanf+0x6ec>
   5deab:	mov    %r14,%r8
   5deae:	mov    -0x5ec(%rbp),%eax
   5deb4:	movl   $0x10,-0x600(%rbp)
   5debe:	and    $0xfffffff9,%eax
   5dec1:	or     $0x1001,%eax
   5dec6:	mov    %eax,-0x5ec(%rbp)
   5decc:	jmpq   5d785 <_IO_vfscanf+0x1265>
   5ded1:	mov    %r8,%r14
   5ded4:	mov    -0x5ec(%rbp),%ebx
   5deda:	mov    %ebx,%eax
   5dedc:	and    $0x1,%eax
   5dedf:	mov    %eax,-0x600(%rbp)
   5dee5:	jne    5cfba <_IO_vfscanf+0xa9a>
   5deeb:	mov    %ebx,%eax
   5deed:	and    $0x8,%ebx
   5def0:	jne    5dfb6 <_IO_vfscanf+0x1a96>
   5def6:	test   $0x21,%ah
   5def9:	je     60a89 <_IO_vfscanf+0x4569>
   5deff:	mov    -0x638(%rbp),%ecx
   5df05:	test   %ecx,%ecx
   5df07:	jne    61250 <_IO_vfscanf+0x4d30>
   5df0d:	mov    -0x5a8(%rbp),%edx
   5df13:	cmp    $0x2f,%edx
   5df16:	ja     63e9b <_IO_vfscanf+0x797b>
   5df1c:	mov    %edx,%eax
   5df1e:	add    -0x598(%rbp),%rax
   5df25:	add    $0x8,%edx
   5df28:	mov    %edx,-0x5a8(%rbp)
   5df2e:	mov    (%rax),%rax
   5df31:	mov    %rax,-0x608(%rbp)
   5df38:	cmpq   $0x0,-0x608(%rbp)
   5df40:	mov    %r10d,-0x638(%rbp)
   5df47:	je     63e8d <_IO_vfscanf+0x796d>
   5df4d:	mov    $0x64,%edi
   5df52:	callq  1f998 <*ABS*+0x911b0@plt+0x18>
   5df57:	mov    -0x608(%rbp),%rdi
   5df5e:	test   %rax,%rax
   5df61:	mov    %rax,(%rdi)
   5df64:	je     6184d <_IO_vfscanf+0x532d>
   5df6a:	mov    -0x660(%rbp),%rdi
   5df71:	mov    -0x638(%rbp),%r10d
   5df78:	test   %rdi,%rdi
   5df7b:	je     61818 <_IO_vfscanf+0x52f8>
   5df81:	mov    (%rdi),%rdx
   5df84:	cmp    $0x20,%rdx
   5df88:	je     61818 <_IO_vfscanf+0x52f8>
   5df8e:	lea    0x1(%rdx),%rcx
   5df92:	mov    %rdi,%rsi
   5df95:	mov    -0x608(%rbp),%rdi
   5df9c:	mov    %rcx,(%rsi)
   5df9f:	mov    %rax,-0x668(%rbp)
   5dfa6:	movq   $0x64,-0x658(%rbp)
   5dfb1:	mov    %rdi,0x10(%rsi,%rdx,8)
   5dfb6:	cmp    $0xffffffff,%r10d
   5dfba:	je     60906 <_IO_vfscanf+0x43e6>
   5dfc0:	mov    0x8(%r13),%rax
   5dfc4:	cmp    0x10(%r13),%rax
   5dfc8:	jae    61ab0 <_IO_vfscanf+0x5590>
   5dfce:	lea    0x1(%rax),%rdx
   5dfd2:	mov    %rdx,0x8(%r13)
   5dfd6:	movzbl (%rax),%r10d
   5dfda:	mov    -0x5f8(%rbp),%rdi
   5dfe1:	movslq %r10d,%rax
   5dfe4:	add    $0x1,%r14
   5dfe8:	mov    0x68(%rdi),%rdx
   5dfec:	testb  $0x20,0x1(%rdx,%rax,2)
   5dff1:	jne    60afe <_IO_vfscanf+0x45de>
   5dff7:	mov    -0x5ec(%rbp),%ecx
   5dffd:	mov    %r15,-0x638(%rbp)
   5e004:	mov    %ebx,%r8d
   5e007:	mov    %r14,%rdx
   5e00a:	mov    -0x668(%rbp),%rsi
   5e011:	mov    -0x658(%rbp),%r15
   5e018:	mov    -0x5f8(%rbp),%r14
   5e01f:	mov    %r10d,%ebx
   5e022:	and    $0x2100,%ecx
   5e028:	jmp    5e089 <_IO_vfscanf+0x1b69>
   5e02a:	mov    -0x608(%rbp),%rdi
   5e031:	mov    %r15,-0x658(%rbp)
   5e038:	mov    %rax,%rsi
   5e03b:	mov    (%rdi),%rdi
   5e03e:	lea    (%rdi,%r15,1),%r11
   5e042:	cmp    %r11,%rax
   5e045:	je     60fbd <_IO_vfscanf+0x4a9d>
   5e04b:	test   %r12d,%r12d
   5e04e:	jle    5e05a <_IO_vfscanf+0x1b3a>
   5e050:	sub    $0x1,%r12d
   5e054:	je     61441 <_IO_vfscanf+0x4f21>
   5e05a:	mov    0x8(%r13),%rax
   5e05e:	cmp    0x10(%r13),%rax
   5e062:	jae    5ec1d <_IO_vfscanf+0x26fd>
   5e068:	lea    0x1(%rax),%rdi
   5e06c:	mov    %rdi,0x8(%r13)
   5e070:	movzbl (%rax),%ebx
   5e073:	mov    0x68(%r14),%rdi
   5e077:	movslq %ebx,%rax
   5e07a:	add    $0x1,%rdx
   5e07e:	testb  $0x20,0x1(%rdi,%rax,2)
   5e083:	jne    60ae0 <_IO_vfscanf+0x45c0>
   5e089:	test   %r8d,%r8d
   5e08c:	jne    5e04b <_IO_vfscanf+0x1b2b>
   5e08e:	test   %ecx,%ecx
   5e090:	lea    0x1(%rsi),%rax
   5e094:	mov    %bl,(%rsi)
   5e096:	jne    5e02a <_IO_vfscanf+0x1b0a>
   5e098:	mov    %rax,%rsi
   5e09b:	jmp    5e04b <_IO_vfscanf+0x1b2b>
   5e09d:	mov    0x8(%r13),%rax
   5e0a1:	cmp    0x10(%r13),%rax
   5e0a5:	jae    61540 <_IO_vfscanf+0x5020>
   5e0ab:	lea    0x1(%rax),%rdx
   5e0af:	mov    %rdx,0x8(%r13)
   5e0b3:	movzbl (%rax),%r10d
   5e0b7:	cmp    $0x25,%r10d
   5e0bb:	je     5c77d <_IO_vfscanf+0x25d>
   5e0c1:	mov    %r13,%rdi
   5e0c4:	movzbl %r10b,%esi
   5e0c8:	mov    %r13,%r15
   5e0cb:	callq  7e5a0 <_IO_sputbackc>
   5e0d0:	mov    $0x2,%r13d
   5e0d6:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5e0db:	mov    -0x628(%rbp),%rdx
   5e0e2:	mov    -0x5e4(%rbp),%eax
   5e0e8:	mov    %r13,%r15
   5e0eb:	mov    %eax,%fs:(%rdx)
   5e0ee:	mov    -0x5e8(%rbp),%r12d
   5e0f5:	mov    $0x1,%r13d
   5e0fb:	test   %r12d,%r12d
   5e0fe:	jne    5c9b8 <_IO_vfscanf+0x498>
   5e104:	movl   $0xffffffff,-0x5e8(%rbp)
   5e10e:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5e113:	mov    %r8,%r14
   5e116:	jmpq   5daae <_IO_vfscanf+0x158e>
   5e11b:	movl   $0x10,-0x600(%rbp)
   5e125:	jmpq   5d78f <_IO_vfscanf+0x126f>
   5e12a:	mov    -0x628(%rbp),%rdx
   5e131:	mov    %r13,%r15
   5e134:	mov    -0x5e4(%rbp),%eax
   5e13a:	mov    %eax,%fs:(%rdx)
   5e13d:	mov    -0x5e8(%rbp),%edx
   5e143:	mov    $0x1,%r13d
   5e149:	test   %edx,%edx
   5e14b:	jne    5c9b8 <_IO_vfscanf+0x498>
   5e151:	movl   $0xffffffff,-0x5e8(%rbp)
   5e15b:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5e160:	movl   $0x8,-0x600(%rbp)
   5e16a:	jmpq   5d78f <_IO_vfscanf+0x126f>
   5e16f:	movl   $0xa,-0x600(%rbp)
   5e179:	jmpq   5d78f <_IO_vfscanf+0x126f>
   5e17e:	mov    %r13,%r15
   5e181:	mov    $0x2,%r13d
   5e187:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5e18c:	mov    %r13,%r15
   5e18f:	mov    $0x2,%r13d
   5e195:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5e19a:	nopw   0x0(%rax,%rax,1)
   5e1a0:	mov    -0x5f8(%rbp),%rsi
   5e1a7:	movslq %ebx,%rax
   5e1aa:	mov    0x68(%rsi),%rcx
   5e1ae:	testb  $0x10,0x1(%rcx,%rax,2)
   5e1b3:	je     5d91a <_IO_vfscanf+0x13fa>
   5e1b9:	mov    -0x450(%rbp),%rax
   5e1c0:	mov    %ebx,%ecx
   5e1c2:	cmp    %rax,-0x448(%rbp)
   5e1c9:	je     5e3c8 <_IO_vfscanf+0x1ea8>
   5e1cf:	lea    0x1(%rax),%rsi
   5e1d3:	mov    %rsi,-0x450(%rbp)
   5e1da:	mov    %cl,(%rax)
   5e1dc:	xor    %eax,%eax
   5e1de:	test   %r15d,%r15d
   5e1e1:	setg   %al
   5e1e4:	sub    %eax,%r15d
   5e1e7:	cmp    $0xffffffff,%ebx
   5e1ea:	je     5e3b0 <_IO_vfscanf+0x1e90>
   5e1f0:	mov    0x8(%r13),%rax
   5e1f4:	cmp    0x10(%r13),%rax
   5e1f8:	jae    5e580 <_IO_vfscanf+0x2060>
   5e1fe:	lea    0x1(%rax),%rcx
   5e202:	mov    %rcx,0x8(%r13)
   5e206:	movzbl (%rax),%ebx
   5e209:	add    $0x1,%r14
   5e20d:	jmpq   5d8e8 <_IO_vfscanf+0x13c8>
   5e212:	nopw   0x0(%rax,%rax,1)
   5e218:	cmpl   $0xa,-0x600(%rbp)
   5e21f:	jne    5d91a <_IO_vfscanf+0x13fa>
   5e225:	mov    -0x690(%rbp),%edi
   5e22b:	test   %edi,%edi
   5e22d:	je     5d91a <_IO_vfscanf+0x13fa>
   5e233:	mov    -0x620(%rbp),%r12
   5e23a:	test   %r15d,%r15d
   5e23d:	mov    $0x7fffffff,%esi
   5e242:	cmovg  %r15d,%esi
   5e246:	movzbl (%r12),%eax
   5e24b:	cmp    %eax,%ebx
   5e24d:	jne    5e376 <_IO_vfscanf+0x1e56>
   5e253:	mov    %r15d,-0x628(%rbp)
   5e25a:	mov    %r13,%r15
   5e25d:	mov    %r12,%r13
   5e260:	mov    %r14,%r12
   5e263:	mov    %esi,%r14d
   5e266:	jmp    5e2c3 <_IO_vfscanf+0x1da3>
   5e268:	nopl   0x0(%rax,%rax,1)
   5e270:	lea    0x1(%rax),%rdi
   5e274:	mov    %rdi,-0x450(%rbp)
   5e27b:	mov    %bl,(%rax)
   5e27d:	add    $0x1,%r13
   5e281:	cmpb   $0x0,0x0(%r13)
   5e286:	je     5e430 <_IO_vfscanf+0x1f10>
   5e28c:	test   %r14d,%r14d
   5e28f:	je     5e478 <_IO_vfscanf+0x1f58>
   5e295:	mov    0x8(%r15),%rax
   5e299:	cmp    0x10(%r15),%rax
   5e29d:	jae    5e340 <_IO_vfscanf+0x1e20>
   5e2a3:	lea    0x1(%rax),%rcx
   5e2a7:	mov    %rcx,0x8(%r15)
   5e2ab:	movzbl (%rax),%ebx
   5e2ae:	movzbl 0x0(%r13),%eax
   5e2b3:	add    $0x1,%r12
   5e2b7:	sub    $0x1,%r14d
   5e2bb:	cmp    %ebx,%eax
   5e2bd:	jne    5e560 <_IO_vfscanf+0x2040>
   5e2c3:	mov    -0x450(%rbp),%rax
   5e2ca:	cmp    -0x448(%rbp),%rax
   5e2d1:	mov    %ebx,%ecx
   5e2d3:	jne    5e270 <_IO_vfscanf+0x1d50>
   5e2d5:	test   %rax,%rax
   5e2d8:	mov    %bl,-0x678(%rbp)
   5e2de:	je     5e68e <_IO_vfscanf+0x216e>
   5e2e4:	sub    -0x440(%rbp),%rax
   5e2eb:	mov    -0x698(%rbp),%rdi
   5e2f2:	mov    %rax,-0x688(%rbp)
   5e2f9:	callq  8afb0 <__libc_scratch_buffer_grow_preserve>
   5e2fe:	test   %al,%al
   5e300:	movzbl -0x678(%rbp),%ecx
   5e307:	je     5e6c1 <_IO_vfscanf+0x21a1>
   5e30d:	mov    -0x440(%rbp),%rax
   5e314:	mov    %rax,%rdi
   5e317:	add    -0x688(%rbp),%rax
   5e31e:	add    -0x438(%rbp),%rdi
   5e325:	mov    %rdi,-0x448(%rbp)
   5e32c:	lea    0x1(%rax),%rdi
   5e330:	mov    %rdi,-0x450(%rbp)
   5e337:	mov    %bl,(%rax)
   5e339:	jmpq   5e27d <_IO_vfscanf+0x1d5d>
   5e33e:	xchg   %ax,%ax
   5e340:	mov    %r15,%rdi
   5e343:	callq  7d720 <__uflow>
   5e348:	cmp    $0xffffffff,%eax
   5e34b:	mov    %eax,%ebx
   5e34d:	jne    5e2ae <_IO_vfscanf+0x1d8e>
   5e353:	mov    0x361b0e(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5e35a:	mov    %r14d,%esi
   5e35d:	mov    %r12,%r14
   5e360:	mov    %r13,%r12
   5e363:	mov    %r15,%r13
   5e366:	mov    -0x628(%rbp),%r15d
   5e36d:	mov    %fs:(%rax),%eax
   5e370:	mov    %eax,-0x5e4(%rbp)
   5e376:	mov    -0x450(%rbp),%rax
   5e37d:	test   %rax,%rax
   5e380:	je     5e450 <_IO_vfscanf+0x1f30>
   5e386:	cmpb   $0x0,(%r12)
   5e38b:	jne    6309f <_IO_vfscanf+0x6b7f>
   5e391:	mov    %ebx,%ecx
   5e393:	test   %r15d,%r15d
   5e396:	cmovle %r15d,%esi
   5e39a:	sub    $0x1,%rax
   5e39e:	mov    %rax,-0x450(%rbp)
   5e3a5:	mov    %esi,%r15d
   5e3a8:	jmpq   5e1c2 <_IO_vfscanf+0x1ca2>
   5e3ad:	nopl   (%rax)
   5e3b0:	mov    0x361ab1(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5e3b7:	mov    -0x5e4(%rbp),%edi
   5e3bd:	mov    %edi,%fs:(%rax)
   5e3c0:	jmpq   5d8e8 <_IO_vfscanf+0x13c8>
   5e3c5:	nopl   (%rax)
   5e3c8:	test   %rax,%rax
   5e3cb:	mov    %cl,-0x628(%rbp)
   5e3d1:	je     5e1dc <_IO_vfscanf+0x1cbc>
   5e3d7:	sub    -0x440(%rbp),%rax
   5e3de:	mov    -0x698(%rbp),%rdi
   5e3e5:	mov    %rax,%r12
   5e3e8:	callq  8afb0 <__libc_scratch_buffer_grow_preserve>
   5e3ed:	test   %al,%al
   5e3ef:	movzbl -0x628(%rbp),%ecx
   5e3f6:	je     5f46d <_IO_vfscanf+0x2f4d>
   5e3fc:	mov    -0x440(%rbp),%rax
   5e403:	mov    %rax,%rsi
   5e406:	add    -0x438(%rbp),%rsi
   5e40d:	add    %r12,%rax
   5e410:	mov    %rsi,-0x448(%rbp)
   5e417:	lea    0x1(%rax),%rsi
   5e41b:	mov    %rsi,-0x450(%rbp)
   5e422:	mov    %cl,(%rax)
   5e424:	jmpq   5e1dc <_IO_vfscanf+0x1cbc>
   5e429:	nopl   0x0(%rax)
   5e430:	mov    -0x450(%rbp),%rax
   5e437:	mov    %r14d,%esi
   5e43a:	mov    %r15,%r13
   5e43d:	mov    %r12,%r14
   5e440:	mov    -0x628(%rbp),%r15d
   5e447:	test   %rax,%rax
   5e44a:	jne    5e393 <_IO_vfscanf+0x1e73>
   5e450:	mov    %r13,%r15
   5e453:	mov    0x361a0e(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5e45a:	xor    %r13d,%r13d
   5e45d:	movl   $0xffffffff,-0x5e8(%rbp)
   5e467:	movl   $0xc,%fs:(%rax)
   5e46e:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5e473:	nopl   0x0(%rax,%rax,1)
   5e478:	mov    %ebx,%r10d
   5e47b:	mov    -0x450(%rbp),%rbx
   5e482:	mov    %r13,%rdx
   5e485:	mov    %r12,%r14
   5e488:	mov    %r15,%r13
   5e48b:	mov    -0x628(%rbp),%r12d
   5e492:	mov    -0x6a0(%rbp),%r15
   5e499:	test   %rbx,%rbx
   5e49c:	je     5e450 <_IO_vfscanf+0x1f30>
   5e49e:	mov    -0x620(%rbp),%rax
   5e4a5:	cmp    %rax,%rdx
   5e4a8:	jbe    5d937 <_IO_vfscanf+0x1417>
   5e4ae:	mov    %rdx,%rsi
   5e4b1:	sub    %rax,%rsi
   5e4b4:	sub    %rsi,%rbx
   5e4b7:	cmp    $0xffffffff,%r10d
   5e4bb:	mov    %rbx,-0x450(%rbp)
   5e4c2:	je     5e4e2 <_IO_vfscanf+0x1fc2>
   5e4c4:	movzbl %r10b,%esi
   5e4c8:	mov    %r13,%rdi
   5e4cb:	mov    %rdx,-0x628(%rbp)
   5e4d2:	callq  7e5a0 <_IO_sputbackc>
   5e4d7:	mov    -0x628(%rbp),%rdx
   5e4de:	sub    $0x1,%r14
   5e4e2:	mov    -0x620(%rbp),%rdi
   5e4e9:	lea    -0x1(%rdx),%rax
   5e4ed:	mov    %rax,-0x628(%rbp)
   5e4f4:	cmp    %rax,%rdi
   5e4f7:	jae    5e550 <_IO_vfscanf+0x2030>
   5e4f9:	mov    %r12d,-0x678(%rbp)
   5e500:	mov    %rdx,-0x688(%rbp)
   5e507:	mov    %rax,%r12
   5e50a:	mov    %rdi,%rbx
   5e50d:	movzbl (%r12),%esi
   5e512:	mov    %r13,%rdi
   5e515:	sub    $0x1,%r12
   5e519:	callq  7e5a0 <_IO_sputbackc>
   5e51e:	cmp    %r12,%rbx
   5e521:	jne    5e50d <_IO_vfscanf+0x1fed>
   5e523:	mov    -0x688(%rbp),%rdx
   5e52a:	mov    -0x620(%rbp),%rax
   5e531:	mov    -0x678(%rbp),%r12d
   5e538:	sub    %rdx,%rax
   5e53b:	add    $0x1,%rax
   5e53f:	add    %rax,-0x628(%rbp)
   5e546:	add    %rax,%r14
   5e549:	mov    -0x628(%rbp),%rax
   5e550:	movzbl (%rax),%r10d
   5e554:	mov    -0x450(%rbp),%rbx
   5e55b:	jmpq   5d92e <_IO_vfscanf+0x140e>
   5e560:	mov    %r14d,%esi
   5e563:	mov    %r12,%r14
   5e566:	mov    %r13,%r12
   5e569:	mov    %r15,%r13
   5e56c:	mov    -0x628(%rbp),%r15d
   5e573:	jmpq   5e376 <_IO_vfscanf+0x1e56>
   5e578:	nopl   0x0(%rax,%rax,1)
   5e580:	mov    %r13,%rdi
   5e583:	callq  7d720 <__uflow>
   5e588:	cmp    $0xffffffff,%eax
   5e58b:	mov    %eax,%ebx
   5e58d:	jne    5e209 <_IO_vfscanf+0x1ce9>
   5e593:	mov    0x3618ce(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5e59a:	mov    %fs:(%rax),%eax
   5e59d:	mov    %eax,-0x5e4(%rbp)
   5e5a3:	jmpq   5d8e8 <_IO_vfscanf+0x13c8>
   5e5a8:	mov    %r13,%rdi
   5e5ab:	mov    %r8,-0x628(%rbp)
   5e5b2:	callq  7d720 <__uflow>
   5e5b7:	cmp    $0xffffffff,%eax
   5e5ba:	mov    %eax,%r10d
   5e5bd:	mov    -0x628(%rbp),%r8
   5e5c4:	jne    5d800 <_IO_vfscanf+0x12e0>
   5e5ca:	mov    0x361897(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5e5d1:	mov    %fs:(%rax),%eax
   5e5d4:	mov    %eax,-0x5e4(%rbp)
   5e5da:	mov    -0x600(%rbp),%r11d
   5e5e1:	test   %r11d,%r11d
   5e5e4:	je     5d89a <_IO_vfscanf+0x137a>
   5e5ea:	jmpq   5d891 <_IO_vfscanf+0x1371>
   5e5ef:	mov    %r13,%r15
   5e5f2:	mov    $0x2,%r13d
   5e5f8:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5e5fd:	mov    %r13,%rdi
   5e600:	callq  7d720 <__uflow>
   5e605:	cmp    $0xffffffff,%eax
   5e608:	jne    5c71e <_IO_vfscanf+0x1fe>
   5e60e:	mov    %r13,%r15
   5e611:	jmpq   5cbc3 <_IO_vfscanf+0x6a3>
   5e616:	mov    %r13,%r15
   5e619:	mov    -0x600(%rbp),%r13d
   5e620:	test   %r13d,%r13d
   5e623:	je     5c9b8 <_IO_vfscanf+0x498>
   5e629:	mov    $0xfffffffffffffffe,%rbx
   5e630:	mov    -0x5e4(%rbp),%r13d
   5e637:	mov    -0x5f8(%rbp),%r12
   5e63e:	mov    %r10d,%eax
   5e641:	jmp    5e679 <_IO_vfscanf+0x2159>
   5e643:	nopl   0x0(%rax,%rax,1)
   5e648:	mov    0x8(%r15),%rax
   5e64c:	cmp    0x10(%r15),%rax
   5e650:	jae    5e752 <_IO_vfscanf+0x2232>
   5e656:	lea    0x1(%rax),%rdx
   5e65a:	mov    %rdx,0x8(%r15)
   5e65e:	movzbl (%rax),%eax
   5e661:	mov    %rax,%rdx
   5e664:	add    %rdx,%rdx
   5e667:	mov    0x68(%r12),%rcx
   5e66c:	movzwl (%rcx,%rdx,1),%edx
   5e670:	and    $0x20,%dh
   5e673:	je     5e707 <_IO_vfscanf+0x21e7>
   5e679:	cmp    $0xffffffff,%eax
   5e67c:	jne    5e648 <_IO_vfscanf+0x2128>
   5e67e:	mov    0x3617e3(%rip),%rdx        # 3bfe68 <_DYNAMIC+0x308>
   5e685:	mov    %r13d,%fs:(%rdx)
   5e689:	mov    %rbx,%rdx
   5e68c:	jmp    5e667 <_IO_vfscanf+0x2147>
   5e68e:	add    $0x1,%r13
   5e692:	cmpb   $0x0,0x0(%r13)
   5e697:	jne    5e28c <_IO_vfscanf+0x1d6c>
   5e69d:	jmpq   5e453 <_IO_vfscanf+0x1f33>
   5e6a2:	nopw   0x0(%rax,%rax,1)
   5e6a8:	mov    %r13,%rdi
   5e6ab:	movzbl %al,%esi
   5e6ae:	mov    %r13,%r15
   5e6b1:	callq  7e5a0 <_IO_sputbackc>
   5e6b6:	mov    $0x2,%r13d
   5e6bc:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5e6c1:	pxor   %xmm0,%xmm0
   5e6c5:	movaps %xmm0,-0x450(%rbp)
   5e6cc:	jmpq   5e27d <_IO_vfscanf+0x1d5d>
   5e6d1:	mov    0x361790(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5e6d8:	movl   $0xffffffff,-0x5e8(%rbp)
   5e6e2:	movl   $0x9,%fs:(%rax)
   5e6e9:	jmpq   5ca50 <_IO_vfscanf+0x530>
   5e6ee:	mov    %r13,%rdi
   5e6f1:	movzbl %al,%esi
   5e6f4:	mov    %r13,%r15
   5e6f7:	callq  7e5a0 <_IO_sputbackc>
   5e6fc:	mov    $0x2,%r13d
   5e702:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5e707:	xor    %r13d,%r13d
   5e70a:	cmp    $0xffffffff,%eax
   5e70d:	je     5c9b8 <_IO_vfscanf+0x498>
   5e713:	movzbl %al,%esi
   5e716:	mov    %r15,%rdi
   5e719:	callq  7e5a0 <_IO_sputbackc>
   5e71e:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5e723:	callq  3b7f0 <__strtoul_internal>
   5e728:	mov    -0x628(%rbp),%r10d
   5e72f:	jmpq   5d9ed <_IO_vfscanf+0x14cd>
   5e734:	movl   $0x8,-0x600(%rbp)
   5e73e:	jmpq   5d8b4 <_IO_vfscanf+0x1394>
   5e743:	mov    %r13,%r15
   5e746:	mov    0x36171b(%rip),%rdx        # 3bfe68 <_DYNAMIC+0x308>
   5e74d:	jmpq   5cf89 <_IO_vfscanf+0xa69>
   5e752:	mov    %r15,%rdi
   5e755:	callq  7d720 <__uflow>
   5e75a:	cmp    $0xffffffff,%eax
   5e75d:	jne    6385a <_IO_vfscanf+0x733a>
   5e763:	mov    0x3616fe(%rip),%rdx        # 3bfe68 <_DYNAMIC+0x308>
   5e76a:	mov    %fs:(%rdx),%r13d
   5e76e:	mov    %rbx,%rdx
   5e771:	jmpq   5e667 <_IO_vfscanf+0x2147>
   5e776:	mov    %rbx,%rdi
   5e779:	callq  7d720 <__uflow>
   5e77e:	cmp    $0xffffffff,%eax
   5e781:	mov    %eax,%r13d
   5e784:	jne    5d393 <_IO_vfscanf+0xe73>
   5e78a:	mov    0x3616d7(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5e791:	mov    %rbx,%r15
   5e794:	mov    $0x4,%r13d
   5e79a:	movl   $0x54,%fs:(%rax)
   5e7a1:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5e7a6:	mov    %r12,%rdi
   5e7a9:	callq  7d720 <__uflow>
   5e7ae:	cmp    $0xffffffff,%eax
   5e7b1:	mov    %eax,%r13d
   5e7b4:	jne    5d176 <_IO_vfscanf+0xc56>
   5e7ba:	mov    0x3616a7(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5e7c1:	mov    %r12,%r15
   5e7c4:	mov    $0x4,%r13d
   5e7ca:	movl   $0x54,%fs:(%rax)
   5e7d1:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5e7d6:	testl  $0x1000,-0x5ec(%rbp)
   5e7e0:	je     5e821 <_IO_vfscanf+0x2301>
   5e7e2:	cmp    $0x4,%r12d
   5e7e6:	jbe    5e821 <_IO_vfscanf+0x2301>
   5e7e8:	cmp    $0x28,%r10d
   5e7ec:	jne    5e821 <_IO_vfscanf+0x2301>
   5e7ee:	mov    -0x5f8(%rbp),%rax
   5e7f5:	mov    0x70(%rax),%rbx
   5e7f9:	mov    0x8(%r13),%rax
   5e7fd:	cmp    0x10(%r13),%rax
   5e801:	jae    61efc <_IO_vfscanf+0x59dc>
   5e807:	lea    0x1(%rax),%rdx
   5e80b:	mov    %rdx,0x8(%r13)
   5e80f:	movzbl (%rax),%r10d
   5e813:	movzbl %r10b,%eax
   5e817:	cmpl   $0x6e,(%rbx,%rax,4)
   5e81b:	je     5f600 <_IO_vfscanf+0x30e0>
   5e821:	cmp    $0xffffffff,%r10d
   5e825:	mov    %r13,%r15
   5e828:	je     61ba3 <_IO_vfscanf+0x5683>
   5e82e:	movzbl %r10b,%esi
   5e832:	mov    %r15,%rdi
   5e835:	mov    $0x2,%r13d
   5e83b:	callq  7e5a0 <_IO_sputbackc>
   5e840:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5e845:	nopl   (%rax)
   5e848:	mov    -0x600(%rbp),%esi
   5e84e:	test   %esi,%esi
   5e850:	je     5f368 <_IO_vfscanf+0x2e48>
   5e856:	cmp    $0xffffffff,%r10d
   5e85a:	je     60b4b <_IO_vfscanf+0x462b>
   5e860:	mov    0x8(%r13),%rax
   5e864:	cmp    0x10(%r13),%rax
   5e868:	jae    61acc <_IO_vfscanf+0x55ac>
   5e86e:	lea    0x1(%rax),%rdx
   5e872:	lea    0x1(%r14),%rbx
   5e876:	mov    %rdx,0x8(%r13)
   5e87a:	movzbl (%rax),%r10d
   5e87e:	lea    -0x570(%rbp),%rax
   5e885:	movq   $0x0,-0x570(%rbp)
   5e890:	movq   $0x0,-0x688(%rbp)
   5e89b:	mov    %rax,-0x628(%rbp)
   5e8a2:	mov    -0x5ec(%rbp),%eax
   5e8a8:	and    $0x2100,%eax
   5e8ad:	mov    %eax,-0x690(%rbp)
   5e8b3:	nopl   0x0(%rax,%rax,1)
   5e8b8:	mov    -0x440(%rbp),%rdx
   5e8bf:	movslq %r10d,%rax
   5e8c2:	movzbl -0x638(%rbp),%edi
   5e8c9:	cmp    (%rdx,%rax,1),%dil
   5e8cd:	je     5ffeb <_IO_vfscanf+0x3acb>
   5e8d3:	mov    -0x678(%rbp),%r11d
   5e8da:	test   %r11d,%r11d
   5e8dd:	je     5e909 <_IO_vfscanf+0x23e9>
   5e8df:	sub    $0x1,%r12d
   5e8e3:	je     5eeee <_IO_vfscanf+0x29ce>
   5e8e9:	mov    0x8(%r13),%rax
   5e8ed:	cmp    0x10(%r13),%rax
   5e8f1:	jae    5eeca <_IO_vfscanf+0x29aa>
   5e8f7:	lea    0x1(%rax),%rdx
   5e8fb:	add    $0x1,%rbx
   5e8ff:	mov    %rdx,0x8(%r13)
   5e903:	movzbl (%rax),%r10d
   5e907:	jmp    5e8b8 <_IO_vfscanf+0x2398>
   5e909:	mov    -0x628(%rbp),%rcx
   5e910:	mov    -0x630(%rbp),%rsi
   5e917:	mov    $0x1,%edx
   5e91c:	mov    -0x640(%rbp),%rdi
   5e923:	mov    %r10b,-0x520(%rbp)
   5e92a:	mov    %r10d,-0x600(%rbp)
   5e931:	callq  ac400 <__mbrtowc>
   5e936:	cmp    $0xfffffffffffffffe,%rax
   5e93a:	mov    -0x600(%rbp),%r10d
   5e941:	je     5f017 <_IO_vfscanf+0x2af7>
   5e947:	mov    -0x690(%rbp),%r9d
   5e94e:	addq   $0x4,-0x640(%rbp)
   5e956:	mov    -0x640(%rbp),%rsi
   5e95d:	test   %r9d,%r9d
   5e960:	je     5ea54 <_IO_vfscanf+0x2534>
   5e966:	mov    -0x608(%rbp),%rax
   5e96d:	movq   $0x0,-0x688(%rbp)
   5e978:	mov    (%rax),%rdi
   5e97b:	mov    -0x658(%rbp),%rax
   5e982:	lea    0x0(,%rax,4),%rdx
   5e98a:	lea    (%rdi,%rdx,1),%rax
   5e98e:	cmp    %rax,%rsi
   5e991:	jne    5e8df <_IO_vfscanf+0x23bf>
   5e997:	mov    -0x658(%rbp),%rax
   5e99e:	mov    %rdx,-0x640(%rbp)
   5e9a5:	mov    %r10d,-0x600(%rbp)
   5e9ac:	lea    0x0(,%rax,8),%rsi
   5e9b4:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   5e9b9:	test   %rax,%rax
   5e9bc:	mov    -0x600(%rbp),%r10d
   5e9c3:	mov    -0x640(%rbp),%rdx
   5e9ca:	je     63c5b <_IO_vfscanf+0x773b>
   5e9d0:	mov    -0x608(%rbp),%rdi
   5e9d7:	shlq   -0x658(%rbp)
   5e9de:	mov    %rax,(%rdi)
   5e9e1:	add    %rdx,%rax
   5e9e4:	mov    %rax,-0x640(%rbp)
   5e9eb:	jmpq   5e8df <_IO_vfscanf+0x23bf>
   5e9f0:	cmp    -0x448(%rbp),%rbx
   5e9f7:	jne    5d993 <_IO_vfscanf+0x1473>
   5e9fd:	sub    %rax,%rbx
   5ea00:	mov    -0x610(%rbp),%rax
   5ea07:	mov    %r10d,-0x628(%rbp)
   5ea0e:	lea    0x10(%rax),%rdi
   5ea12:	callq  8afb0 <__libc_scratch_buffer_grow_preserve>
   5ea17:	test   %al,%al
   5ea19:	mov    -0x628(%rbp),%r10d
   5ea20:	je     61ee9 <_IO_vfscanf+0x59c9>
   5ea26:	mov    -0x440(%rbp),%rax
   5ea2d:	mov    %rax,%rdx
   5ea30:	add    -0x438(%rbp),%rdx
   5ea37:	add    %rax,%rbx
   5ea3a:	lea    0x1(%rbx),%rax
   5ea3e:	mov    %rax,-0x450(%rbp)
   5ea45:	mov    %rdx,-0x448(%rbp)
   5ea4c:	movb   $0x0,(%rbx)
   5ea4f:	jmpq   5d9a1 <_IO_vfscanf+0x1481>
   5ea54:	movq   $0x0,-0x688(%rbp)
   5ea5f:	jmpq   5e8df <_IO_vfscanf+0x23bf>
   5ea64:	mov    -0x600(%rbp),%edi
   5ea6a:	test   %edi,%edi
   5ea6c:	je     5f140 <_IO_vfscanf+0x2c20>
   5ea72:	mov    -0x5f8(%rbp),%rsi
   5ea79:	movslq %r12d,%rax
   5ea7c:	mov    0x68(%rsi),%rcx
   5ea80:	testb  $0x10,0x1(%rcx,%rax,2)
   5ea85:	je     5f140 <_IO_vfscanf+0x2c20>
   5ea8b:	cmp    -0x448(%rbp),%rbx
   5ea92:	je     63083 <_IO_vfscanf+0x6b63>
   5ea98:	lea    0x1(%rbx),%rax
   5ea9c:	movb   $0x1,-0x628(%rbp)
   5eaa3:	mov    %rax,-0x450(%rbp)
   5eaaa:	mov    %r12b,(%rbx)
   5eaad:	test   %r15d,%r15d
   5eab0:	je     61130 <_IO_vfscanf+0x4c10>
   5eab6:	cmp    $0xffffffff,%r12d
   5eaba:	jne    5dc59 <_IO_vfscanf+0x1739>
   5eac0:	mov    0x3613a1(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5eac7:	mov    -0x5e4(%rbp),%esi
   5eacd:	mov    %r12d,%r10d
   5ead0:	mov    %r15d,%r12d
   5ead3:	mov    -0x698(%rbp),%r15
   5eada:	mov    %esi,%fs:(%rax)
   5eadd:	mov    -0x450(%rbp),%rax
   5eae4:	test   %rax,%rax
   5eae7:	je     62747 <_IO_vfscanf+0x6227>
   5eaed:	testl  $0x400,-0x5ec(%rbp)
   5eaf7:	jne    622d0 <_IO_vfscanf+0x5db0>
   5eafd:	mov    -0x440(%rbp),%rdx
   5eb04:	mov    %rax,%rcx
   5eb07:	sub    %rdx,%rcx
   5eb0a:	cmp    %rdx,%rax
   5eb0d:	je     622c2 <_IO_vfscanf+0x5da2>
   5eb13:	cmp    $0x2,%rcx
   5eb17:	jne    5eb27 <_IO_vfscanf+0x2607>
   5eb19:	mov    -0x600(%rbp),%edx
   5eb1f:	test   %edx,%edx
   5eb21:	jne    63e20 <_IO_vfscanf+0x7900>
   5eb27:	cmp    %rax,-0x448(%rbp)
   5eb2e:	je     61fbe <_IO_vfscanf+0x5a9e>
   5eb34:	lea    0x1(%rax),%rdx
   5eb38:	mov    %rdx,-0x450(%rbp)
   5eb3f:	movb   $0x0,(%rax)
   5eb42:	cmpq   $0x0,-0x450(%rbp)
   5eb4a:	je     61b46 <_IO_vfscanf+0x5626>
   5eb50:	testb  $0x2,-0x5ec(%rbp)
   5eb57:	jne    60c30 <_IO_vfscanf+0x4710>
   5eb5d:	mov    -0x5ec(%rbp),%ebx
   5eb63:	mov    %ebx,%eax
   5eb65:	test   $0x3,%al
   5eb67:	je     60870 <_IO_vfscanf+0x4350>
   5eb6d:	mov    -0x440(%rbp),%rdi
   5eb74:	mov    %ebx,%edx
   5eb76:	lea    -0x5c8(%rbp),%rsi
   5eb7d:	and    $0x80,%edx
   5eb83:	mov    %r10d,-0x5ec(%rbp)
   5eb8a:	callq  3c1d0 <__strtod_internal>
   5eb8f:	mov    %ebx,%eax
   5eb91:	mov    -0x5ec(%rbp),%r10d
   5eb98:	test   $0x8,%al
   5eb9a:	jne    5fa9c <_IO_vfscanf+0x357c>
   5eba0:	mov    -0x440(%rbp),%rdx
   5eba7:	mov    -0x5c8(%rbp),%rcx
   5ebae:	cmp    %rdx,%rcx
   5ebb1:	je     6346f <_IO_vfscanf+0x6f4f>
   5ebb7:	mov    -0x638(%rbp),%eax
   5ebbd:	test   %eax,%eax
   5ebbf:	jne    61938 <_IO_vfscanf+0x5418>
   5ebc5:	mov    -0x5a8(%rbp),%eax
   5ebcb:	cmp    $0x2f,%eax
   5ebce:	ja     63b31 <_IO_vfscanf+0x7611>
   5ebd4:	mov    %eax,%esi
   5ebd6:	add    -0x598(%rbp),%rsi
   5ebdd:	add    $0x8,%eax
   5ebe0:	mov    %eax,-0x5a8(%rbp)
   5ebe6:	cmpb   $0x0,-0x6a0(%rbp)
   5ebed:	mov    (%rsi),%rax
   5ebf0:	je     5ebfa <_IO_vfscanf+0x26da>
   5ebf2:	xorpd  0x132736(%rip),%xmm0        # 191330 <signmask>
   5ebfa:	movsd  %xmm0,(%rax)
   5ebfe:	cmp    %rdx,%rcx
   5ec01:	je     62185 <_IO_vfscanf+0x5c65>
   5ec07:	addl   $0x1,-0x5e8(%rbp)
   5ec0e:	movl   $0x0,-0x600(%rbp)
   5ec18:	jmpq   5c832 <_IO_vfscanf+0x312>
   5ec1d:	mov    %r13,%rdi
   5ec20:	mov    %rdx,-0x688(%rbp)
   5ec27:	mov    %ecx,-0x678(%rbp)
   5ec2d:	mov    %r8d,-0x668(%rbp)
   5ec34:	mov    %rsi,-0x658(%rbp)
   5ec3b:	callq  7d720 <__uflow>
   5ec40:	cmp    $0xffffffff,%eax
   5ec43:	mov    %eax,%ebx
   5ec45:	mov    -0x658(%rbp),%rsi
   5ec4c:	mov    -0x668(%rbp),%r8d
   5ec53:	mov    -0x678(%rbp),%ecx
   5ec59:	mov    -0x688(%rbp),%rdx
   5ec60:	jne    5e073 <_IO_vfscanf+0x1b53>
   5ec66:	mov    %eax,%r10d
   5ec69:	mov    -0x628(%rbp),%rax
   5ec70:	mov    %r15,-0x658(%rbp)
   5ec77:	mov    -0x638(%rbp),%r15
   5ec7e:	mov    %rsi,-0x668(%rbp)
   5ec85:	mov    %rdx,%r14
   5ec88:	mov    %r8d,%ebx
   5ec8b:	mov    %fs:(%rax),%eax
   5ec8e:	mov    %eax,-0x5e4(%rbp)
   5ec94:	test   %ebx,%ebx
   5ec96:	jne    5c832 <_IO_vfscanf+0x312>
   5ec9c:	testl  $0x2100,-0x5ec(%rbp)
   5eca6:	mov    -0x668(%rbp),%rax
   5ecad:	lea    0x1(%rax),%rbx
   5ecb1:	movb   $0x0,(%rax)
   5ecb4:	je     5ecec <_IO_vfscanf+0x27cc>
   5ecb6:	mov    -0x608(%rbp),%r12
   5ecbd:	mov    %rbx,%rsi
   5ecc0:	mov    (%r12),%rdi
   5ecc4:	sub    %rdi,%rsi
   5ecc7:	cmp    %rsi,-0x658(%rbp)
   5ecce:	je     5ecec <_IO_vfscanf+0x27cc>
   5ecd0:	mov    %r10d,-0x5ec(%rbp)
   5ecd7:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   5ecdc:	test   %rax,%rax
   5ecdf:	mov    -0x5ec(%rbp),%r10d
   5ece6:	je     5ecec <_IO_vfscanf+0x27cc>
   5ece8:	mov    %rax,(%r12)
   5ecec:	addl   $0x1,-0x5e8(%rbp)
   5ecf3:	movl   $0x0,-0x600(%rbp)
   5ecfd:	mov    %rbx,-0x668(%rbp)
   5ed04:	movq   $0x0,-0x608(%rbp)
   5ed0f:	jmpq   5c832 <_IO_vfscanf+0x312>
   5ed14:	mov    %r12,%rdi
   5ed17:	cmp    $0x1,%rax
   5ed1b:	mov    %r13d,%r12d
   5ed1e:	mov    %rdi,%r13
   5ed21:	jne    61778 <_IO_vfscanf+0x5258>
   5ed27:	mov    -0x600(%rbp),%eax
   5ed2d:	addq   $0x4,-0x640(%rbp)
   5ed35:	mov    -0x640(%rbp),%rsi
   5ed3c:	test   %eax,%eax
   5ed3e:	jne    5ed70 <_IO_vfscanf+0x2850>
   5ed40:	mov    -0x688(%rbp),%eax
   5ed46:	test   %eax,%eax
   5ed48:	je     5ed70 <_IO_vfscanf+0x2850>
   5ed4a:	mov    -0x608(%rbp),%rax
   5ed51:	mov    (%rax),%rdi
   5ed54:	mov    -0x658(%rbp),%rax
   5ed5b:	lea    0x0(,%rax,4),%rbx
   5ed63:	lea    (%rdi,%rbx,1),%rax
   5ed67:	cmp    %rax,%rsi
   5ed6a:	je     63427 <_IO_vfscanf+0x6f07>
   5ed70:	mov    -0x678(%rbp),%eax
   5ed76:	test   %eax,%eax
   5ed78:	jle    5ed87 <_IO_vfscanf+0x2867>
   5ed7a:	subl   $0x1,-0x678(%rbp)
   5ed81:	je     63b22 <_IO_vfscanf+0x7602>
   5ed87:	mov    0x8(%r13),%rax
   5ed8b:	cmp    0x10(%r13),%rax
   5ed8f:	jae    613db <_IO_vfscanf+0x4ebb>
   5ed95:	lea    0x1(%rax),%rdx
   5ed99:	mov    %rdx,0x8(%r13)
   5ed9d:	movzbl (%rax),%r12d
   5eda1:	mov    -0x5f8(%rbp),%rsi
   5eda8:	movslq %r12d,%rax
   5edab:	add    $0x1,%r14
   5edaf:	mov    0x68(%rsi),%rdx
   5edb3:	testb  $0x20,0x1(%rdx,%rax,2)
   5edb8:	je     5d110 <_IO_vfscanf+0xbf0>
   5edbe:	mov    -0x638(%rbp),%r15
   5edc5:	mov    %r12d,%r10d
   5edc8:	movzbl %r10b,%esi
   5edcc:	mov    %r13,%rdi
   5edcf:	mov    %r10d,-0x628(%rbp)
   5edd6:	callq  7e5a0 <_IO_sputbackc>
   5eddb:	mov    -0x628(%rbp),%r10d
   5ede2:	sub    $0x1,%r14
   5ede6:	mov    -0x600(%rbp),%ebx
   5edec:	test   %ebx,%ebx
   5edee:	jne    5c77d <_IO_vfscanf+0x25d>
   5edf4:	testl  $0x2100,-0x5ec(%rbp)
   5edfe:	mov    -0x640(%rbp),%rax
   5ee05:	lea    0x4(%rax),%rbx
   5ee09:	movl   $0x0,(%rax)
   5ee0f:	je     5ee4e <_IO_vfscanf+0x292e>
   5ee11:	mov    -0x608(%rbp),%r12
   5ee18:	mov    %rbx,%rsi
   5ee1b:	mov    (%r12),%rdi
   5ee1f:	sub    %rdi,%rsi
   5ee22:	mov    %rsi,%rax
   5ee25:	sar    $0x2,%rax
   5ee29:	cmp    %rax,-0x658(%rbp)
   5ee30:	je     5ee4e <_IO_vfscanf+0x292e>
   5ee32:	mov    %r10d,-0x5ec(%rbp)
   5ee39:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   5ee3e:	test   %rax,%rax
   5ee41:	mov    -0x5ec(%rbp),%r10d
   5ee48:	je     5ee4e <_IO_vfscanf+0x292e>
   5ee4a:	mov    %rax,(%r12)
   5ee4e:	addl   $0x1,-0x5e8(%rbp)
   5ee55:	mov    %rbx,-0x640(%rbp)
   5ee5c:	movq   $0x0,-0x608(%rbp)
   5ee67:	jmpq   5c77d <_IO_vfscanf+0x25d>
   5ee6c:	nopl   0x0(%rax)
   5ee70:	mov    %rbx,%rsi
   5ee73:	cmp    $0x1,%rax
   5ee77:	mov    %r13d,%ebx
   5ee7a:	mov    %rsi,%r13
   5ee7d:	jne    616ac <_IO_vfscanf+0x518c>
   5ee83:	mov    -0x628(%rbp),%edi
   5ee89:	addq   $0x4,-0x640(%rbp)
   5ee91:	test   %edi,%edi
   5ee93:	jle    63205 <_IO_vfscanf+0x6ce5>
   5ee99:	mov    0x8(%rsi),%rax
   5ee9d:	cmp    0x10(%rsi),%rax
   5eea1:	jae    61d67 <_IO_vfscanf+0x5847>
   5eea7:	lea    0x1(%rax),%rdx
   5eeab:	mov    %rdx,0x8(%rsi)
   5eeaf:	movzbl (%rax),%ebx
   5eeb2:	add    $0x1,%r14
   5eeb6:	addq   $0x1,-0x638(%rbp)
   5eebe:	subl   $0x1,-0x628(%rbp)
   5eec5:	jmpq   5d2ec <_IO_vfscanf+0xdcc>
   5eeca:	mov    %r13,%rdi
   5eecd:	callq  7d720 <__uflow>
   5eed2:	cmp    $0xffffffff,%eax
   5eed5:	mov    %eax,%r10d
   5eed8:	jne    631fc <_IO_vfscanf+0x6cdc>
   5eede:	mov    0x360f83(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5eee5:	mov    %fs:(%rax),%eax
   5eee8:	mov    %eax,-0x5e4(%rbp)
   5eeee:	cmpq   $0x0,-0x688(%rbp)
   5eef6:	jne    61d4b <_IO_vfscanf+0x582b>
   5eefc:	cmp    %r14,%rbx
   5eeff:	je     61d3d <_IO_vfscanf+0x581d>
   5ef05:	mov    -0x678(%rbp),%r8d
   5ef0c:	test   %r8d,%r8d
   5ef0f:	jne    5ef80 <_IO_vfscanf+0x2a60>
   5ef11:	mov    -0x690(%rbp),%edi
   5ef17:	mov    -0x640(%rbp),%rax
   5ef1e:	test   %edi,%edi
   5ef20:	lea    0x4(%rax),%r12
   5ef24:	movl   $0x0,(%rax)
   5ef2a:	je     5ef67 <_IO_vfscanf+0x2a47>
   5ef2c:	mov    -0x608(%rbp),%r14
   5ef33:	mov    %r12,%rsi
   5ef36:	mov    (%r14),%rdi
   5ef39:	sub    %rdi,%rsi
   5ef3c:	mov    %rsi,%rax
   5ef3f:	sar    $0x2,%rax
   5ef43:	cmp    %rax,-0x658(%rbp)
   5ef4a:	je     5ef67 <_IO_vfscanf+0x2a47>
   5ef4c:	mov    %r10d,-0x5ec(%rbp)
   5ef53:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   5ef58:	test   %rax,%rax
   5ef5b:	mov    -0x5ec(%rbp),%r10d
   5ef62:	je     5ef67 <_IO_vfscanf+0x2a47>
   5ef64:	mov    %rax,(%r14)
   5ef67:	addl   $0x1,-0x5e8(%rbp)
   5ef6e:	mov    %r12,-0x640(%rbp)
   5ef75:	movq   $0x0,-0x608(%rbp)
   5ef80:	movl   $0x0,-0x600(%rbp)
   5ef8a:	mov    %rbx,%r14
   5ef8d:	jmpq   5c832 <_IO_vfscanf+0x312>
   5ef92:	testb  $0x1,-0x5ec(%rbp)
   5ef99:	je     5f81c <_IO_vfscanf+0x32fc>
   5ef9f:	mov    -0x638(%rbp),%ebx
   5efa5:	test   %ebx,%ebx
   5efa7:	je     5da39 <_IO_vfscanf+0x1519>
   5efad:	mov    -0x650(%rbp),%rsi
   5efb4:	mov    -0x630(%rbp),%rdi
   5efbb:	xor    %ebx,%ebx
   5efbd:	mov    -0x638(%rbp),%r8d
   5efc4:	mov    (%rsi),%rdx
   5efc7:	mov    %rdx,(%rdi)
   5efca:	mov    0x8(%rsi),%rcx
   5efce:	mov    %rcx,0x8(%rdi)
   5efd2:	mov    0x10(%rsi),%rsi
   5efd6:	mov    %rsi,0x10(%rdi)
   5efda:	mov    %edx,%esi
   5efdc:	xor    %edi,%edi
   5efde:	sub    $0x1,%r8d
   5efe2:	je     636df <_IO_vfscanf+0x71bf>
   5efe8:	cmp    $0x2f,%esi
   5efeb:	ja     63cb0 <_IO_vfscanf+0x7790>
   5eff1:	add    $0x8,%esi
   5eff4:	mov    $0x1,%ebx
   5eff9:	jmp    5efde <_IO_vfscanf+0x2abe>
   5effb:	nopl   0x0(%rax,%rax,1)
   5f000:	movzbl (%rax),%edi
   5f003:	lea    -0x2b(%rdi),%edx
   5f006:	and    $0xfd,%edx
   5f00c:	jne    5d957 <_IO_vfscanf+0x1437>
   5f012:	jmpq   5e821 <_IO_vfscanf+0x2301>
   5f017:	mov    0x360d92(%rip),%rax        # 3bfdb0 <_DYNAMIC+0x250>
   5f01e:	addq   $0x1,-0x688(%rbp)
   5f026:	mov    -0x688(%rbp),%rsi
   5f02d:	mov    %fs:(%rax),%rax
   5f031:	mov    (%rax),%rax
   5f034:	mov    0xa8(%rax),%eax
   5f03a:	cmp    %rax,%rsi
   5f03d:	jb     5e8e9 <_IO_vfscanf+0x23c9>
   5f043:	lea    0x1318a6(%rip),%rcx        # 1908f0 <__PRETTY_FUNCTION__.12472>
   5f04a:	lea    0x12aa07(%rip),%rsi        # 189a58 <null+0x1a>
   5f051:	lea    0x12aa0a(%rip),%rdi        # 189a62 <null+0x24>
   5f058:	mov    $0xa76,%edx
   5f05d:	callq  2de10 <__assert_fail>
   5f062:	nopw   0x0(%rax,%rax,1)
   5f068:	and    $0x8,%eax
   5f06b:	mov    %eax,-0x678(%rbp)
   5f071:	jne    5d67d <_IO_vfscanf+0x115d>
   5f077:	mov    %esi,%eax
   5f079:	test   $0x21,%ah
   5f07c:	je     60b82 <_IO_vfscanf+0x4662>
   5f082:	mov    -0x638(%rbp),%eax
   5f088:	test   %eax,%eax
   5f08a:	jne    611ac <_IO_vfscanf+0x4c8c>
   5f090:	mov    -0x5a8(%rbp),%ecx
   5f096:	cmp    $0x2f,%ecx
   5f099:	ja     62f20 <_IO_vfscanf+0x6a00>
   5f09f:	mov    %ecx,%eax
   5f0a1:	add    -0x598(%rbp),%rax
   5f0a8:	add    $0x8,%ecx
   5f0ab:	mov    %ecx,-0x5a8(%rbp)
   5f0b1:	mov    (%rax),%rax
   5f0b4:	mov    %rax,-0x608(%rbp)
   5f0bb:	mov    %rax,%rbx
   5f0be:	test   %rbx,%rbx
   5f0c1:	mov    %r10d,-0x638(%rbp)
   5f0c8:	mov    %rdx,-0x628(%rbp)
   5f0cf:	je     62f12 <_IO_vfscanf+0x69f2>
   5f0d5:	mov    $0x64,%edi
   5f0da:	callq  1f998 <*ABS*+0x911b0@plt+0x18>
   5f0df:	test   %rax,%rax
   5f0e2:	mov    %rax,(%rbx)
   5f0e5:	je     618bf <_IO_vfscanf+0x539f>
   5f0eb:	mov    -0x660(%rbp),%rdi
   5f0f2:	mov    -0x628(%rbp),%rdx
   5f0f9:	mov    -0x638(%rbp),%r10d
   5f100:	test   %rdi,%rdi
   5f103:	je     61883 <_IO_vfscanf+0x5363>
   5f109:	mov    (%rdi),%rcx
   5f10c:	cmp    $0x20,%rcx
   5f110:	lea    0x1(%rcx),%rsi
   5f114:	je     61883 <_IO_vfscanf+0x5363>
   5f11a:	mov    %rsi,(%rdi)
   5f11d:	mov    -0x608(%rbp),%rsi
   5f124:	mov    %rax,-0x668(%rbp)
   5f12b:	movq   $0x64,-0x658(%rbp)
   5f136:	mov    %rsi,0x10(%rdi,%rcx,8)
   5f13b:	jmpq   5d67d <_IO_vfscanf+0x115d>
   5f140:	cmpb   $0x0,-0x628(%rbp)
   5f147:	je     5dcb9 <_IO_vfscanf+0x1799>
   5f14d:	mov    -0x5f8(%rbp),%rdi
   5f154:	movzbl %r12b,%eax
   5f158:	movzbl -0x688(%rbp),%esi
   5f15f:	mov    0x70(%rdi),%rcx
   5f163:	cmp    (%rcx,%rax,4),%sil
   5f167:	jne    5dcb9 <_IO_vfscanf+0x1799>
   5f16d:	cmp    -0x448(%rbp),%rbx
   5f174:	je     62ee8 <_IO_vfscanf+0x69c8>
   5f17a:	lea    0x1(%rbx),%rax
   5f17e:	mov    %rax,-0x450(%rbp)
   5f185:	movzbl -0x688(%rbp),%eax
   5f18c:	mov    %al,(%rbx)
   5f18e:	movzbl -0x628(%rbp),%eax
   5f195:	mov    %al,-0x690(%rbp)
   5f19b:	mov    %al,-0x678(%rbp)
   5f1a1:	jmpq   5eaad <_IO_vfscanf+0x258d>
   5f1a6:	mov    %r13,%r15
   5f1a9:	mov    $0x2,%r13d
   5f1af:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5f1b4:	movb   $0x0,-0x6a0(%rbp)
   5f1bb:	jmpq   5db1f <_IO_vfscanf+0x15ff>
   5f1c0:	cmpb   $0x0,(%rax)
   5f1c3:	je     5f340 <_IO_vfscanf+0x2e20>
   5f1c9:	mov    -0x620(%rbp),%rsi
   5f1d0:	test   %rsi,%rsi
   5f1d3:	je     6213d <_IO_vfscanf+0x5c1d>
   5f1d9:	cmpb   $0x0,(%rsi)
   5f1dc:	jne    6213d <_IO_vfscanf+0x5c1d>
   5f1e2:	mov    -0x620(%rbp),%rax
   5f1e9:	mov    %ecx,%ebx
   5f1eb:	movzbl (%rax),%esi
   5f1ee:	mov    %rax,%r11
   5f1f1:	test   %sil,%sil
   5f1f4:	jne    5f21f <_IO_vfscanf+0x2cff>
   5f1f6:	jmpq   5f461 <_IO_vfscanf+0x2f41>
   5f1fb:	nopl   0x0(%rax,%rax,1)
   5f200:	lea    0x1(%rax),%rdx
   5f204:	mov    %rdx,-0x450(%rbp)
   5f20b:	mov    %sil,(%rax)
   5f20e:	add    $0x1,%r11
   5f212:	movzbl (%r11),%esi
   5f216:	test   %sil,%sil
   5f219:	je     5f45f <_IO_vfscanf+0x2f3f>
   5f21f:	mov    -0x450(%rbp),%rax
   5f226:	cmp    -0x448(%rbp),%rax
   5f22d:	jne    5f200 <_IO_vfscanf+0x2ce0>
   5f22f:	test   %rax,%rax
   5f232:	mov    %sil,-0x6a8(%rbp)
   5f239:	je     5f20e <_IO_vfscanf+0x2cee>
   5f23b:	sub    -0x440(%rbp),%rax
   5f242:	mov    -0x6b0(%rbp),%rdi
   5f249:	mov    %r11,-0x6d0(%rbp)
   5f250:	mov    %rax,-0x6c0(%rbp)
   5f257:	callq  8afb0 <__libc_scratch_buffer_grow_preserve>
   5f25c:	test   %al,%al
   5f25e:	mov    -0x6d0(%rbp),%r11
   5f265:	movzbl -0x6a8(%rbp),%esi
   5f26c:	je     61b69 <_IO_vfscanf+0x5649>
   5f272:	mov    -0x440(%rbp),%rax
   5f279:	mov    %rax,%rdx
   5f27c:	add    -0x6c0(%rbp),%rax
   5f283:	add    -0x438(%rbp),%rdx
   5f28a:	mov    %rdx,-0x448(%rbp)
   5f291:	lea    0x1(%rax),%rdx
   5f295:	mov    %rdx,-0x450(%rbp)
   5f29c:	mov    %sil,(%rax)
   5f29f:	jmpq   5f20e <_IO_vfscanf+0x2cee>
   5f2a4:	mov    %r13,%rdi
   5f2a7:	mov    %r8,-0x628(%rbp)
   5f2ae:	callq  7d720 <__uflow>
   5f2b3:	cmp    $0xffffffff,%eax
   5f2b6:	mov    %eax,%r10d
   5f2b9:	mov    -0x628(%rbp),%r8
   5f2c0:	jne    5d7a9 <_IO_vfscanf+0x1289>
   5f2c6:	mov    %r13,%r15
   5f2c9:	jmpq   5cf92 <_IO_vfscanf+0xa72>
   5f2ce:	mov    0x360b93(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5f2d5:	mov    -0x5e4(%rbp),%esi
   5f2db:	mov    %r13,%r15
   5f2de:	mov    %esi,%fs:(%rax)
   5f2e1:	mov    -0x5e8(%rbp),%r9d
   5f2e8:	mov    $0x1,%r13d
   5f2ee:	test   %r9d,%r9d
   5f2f1:	jne    5c9b8 <_IO_vfscanf+0x498>
   5f2f7:	movl   $0xffffffff,-0x5e8(%rbp)
   5f301:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5f306:	mov    0x360b5b(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5f30d:	mov    -0x5e4(%rbp),%esi
   5f313:	mov    %r13,%r15
   5f316:	mov    %esi,%fs:(%rax)
   5f319:	mov    -0x5e8(%rbp),%r11d
   5f320:	mov    $0x1,%r13d
   5f326:	test   %r11d,%r11d
   5f329:	jne    5c9b8 <_IO_vfscanf+0x498>
   5f32f:	movl   $0xffffffff,-0x5e8(%rbp)
   5f339:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5f33e:	mov    %ebx,%ecx
   5f340:	test   %r15d,%r15d
   5f343:	jle    5f348 <_IO_vfscanf+0x2e28>
   5f345:	mov    %ecx,%r15d
   5f348:	movb   $0x1,-0x678(%rbp)
   5f34f:	jmpq   5eaad <_IO_vfscanf+0x258d>
   5f354:	mov    -0x440(%rbp),%rdx
   5f35b:	add    $0x1,%r15
   5f35f:	movb   $0x1,(%rdx,%rax,1)
   5f363:	jmpq   5d723 <_IO_vfscanf+0x1203>
   5f368:	cmp    $0xffffffff,%r10d
   5f36c:	je     60d18 <_IO_vfscanf+0x47f8>
   5f372:	mov    0x8(%r13),%rax
   5f376:	cmp    0x10(%r13),%rax
   5f37a:	jae    61d21 <_IO_vfscanf+0x5801>
   5f380:	lea    0x1(%rax),%rdx
   5f384:	mov    %rdx,0x8(%r13)
   5f388:	movzbl (%rax),%r10d
   5f38c:	mov    -0x440(%rbp),%rcx
   5f393:	movslq %r10d,%rax
   5f396:	movzbl -0x638(%rbp),%edi
   5f39d:	lea    0x1(%r14),%rbx
   5f3a1:	cmp    (%rcx,%rax,1),%dil
   5f3a5:	je     6130e <_IO_vfscanf+0x4dee>
   5f3ab:	mov    -0x5ec(%rbp),%eax
   5f3b1:	mov    %r15,-0x688(%rbp)
   5f3b8:	mov    %r12d,%r15d
   5f3bb:	mov    %r14,-0x690(%rbp)
   5f3c2:	mov    %r10d,%r12d
   5f3c5:	mov    %rbx,%r14
   5f3c8:	mov    %r13,%rbx
   5f3cb:	mov    -0x668(%rbp),%r13
   5f3d2:	and    $0x2100,%eax
   5f3d7:	mov    %eax,-0x628(%rbp)
   5f3dd:	jmp    5f43e <_IO_vfscanf+0x2f1e>
   5f3df:	mov    -0x608(%rbp),%rsi
   5f3e6:	mov    %rax,%r13
   5f3e9:	mov    (%rsi),%rdi
   5f3ec:	mov    -0x658(%rbp),%rsi
   5f3f3:	add    %rdi,%rsi
   5f3f6:	cmp    %rsi,%rax
   5f3f9:	je     6000e <_IO_vfscanf+0x3aee>
   5f3ff:	sub    $0x1,%r15d
   5f403:	je     5ffc8 <_IO_vfscanf+0x3aa8>
   5f409:	mov    0x8(%rbx),%rax
   5f40d:	cmp    0x10(%rbx),%rax
   5f411:	jae    5f47d <_IO_vfscanf+0x2f5d>
   5f413:	lea    0x1(%rax),%rsi
   5f417:	mov    %rsi,0x8(%rbx)
   5f41b:	movzbl (%rax),%r12d
   5f41f:	mov    -0x440(%rbp),%rsi
   5f426:	movslq %r12d,%rax
   5f429:	movzbl -0x638(%rbp),%edi
   5f430:	add    $0x1,%r14
   5f434:	cmp    (%rsi,%rax,1),%dil
   5f438:	je     612f0 <_IO_vfscanf+0x4dd0>
   5f43e:	mov    -0x678(%rbp),%ecx
   5f444:	test   %ecx,%ecx
   5f446:	jne    5f3ff <_IO_vfscanf+0x2edf>
   5f448:	mov    -0x628(%rbp),%edx
   5f44e:	lea    0x1(%r13),%rax
   5f452:	mov    %r12b,0x0(%r13)
   5f456:	test   %edx,%edx
   5f458:	jne    5f3df <_IO_vfscanf+0x2ebf>
   5f45a:	mov    %rax,%r13
   5f45d:	jmp    5f3ff <_IO_vfscanf+0x2edf>
   5f45f:	mov    %ebx,%ecx
   5f461:	test   %r15d,%r15d
   5f464:	cmovg  %ecx,%r15d
   5f468:	jmpq   5eaad <_IO_vfscanf+0x258d>
   5f46d:	pxor   %xmm0,%xmm0
   5f471:	movaps %xmm0,-0x450(%rbp)
   5f478:	jmpq   5e1dc <_IO_vfscanf+0x1cbc>
   5f47d:	mov    %rbx,%rdi
   5f480:	callq  7d720 <__uflow>
   5f485:	cmp    $0xffffffff,%eax
   5f488:	mov    %eax,%r12d
   5f48b:	jne    5f41f <_IO_vfscanf+0x2eff>
   5f48d:	mov    %eax,%r10d
   5f490:	mov    0x3609d1(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5f497:	mov    %r13,-0x668(%rbp)
   5f49e:	mov    -0x688(%rbp),%r15
   5f4a5:	mov    %rbx,%r13
   5f4a8:	mov    %r14,%rbx
   5f4ab:	mov    -0x690(%rbp),%r14
   5f4b2:	mov    %fs:(%rax),%eax
   5f4b5:	mov    %eax,-0x5e4(%rbp)
   5f4bb:	cmp    %r14,%rbx
   5f4be:	je     61914 <_IO_vfscanf+0x53f4>
   5f4c4:	mov    -0x678(%rbp),%eax
   5f4ca:	mov    %rbx,%r14
   5f4cd:	test   %eax,%eax
   5f4cf:	jne    5c832 <_IO_vfscanf+0x312>
   5f4d5:	testl  $0x2100,-0x5ec(%rbp)
   5f4df:	mov    -0x668(%rbp),%rax
   5f4e6:	lea    0x1(%rax),%r12
   5f4ea:	movb   $0x0,(%rax)
   5f4ed:	je     5f523 <_IO_vfscanf+0x3003>
   5f4ef:	mov    -0x608(%rbp),%r14
   5f4f6:	mov    %r12,%rsi
   5f4f9:	mov    (%r14),%rdi
   5f4fc:	sub    %rdi,%rsi
   5f4ff:	cmp    %rsi,-0x658(%rbp)
   5f506:	je     5f523 <_IO_vfscanf+0x3003>
   5f508:	mov    %r10d,-0x5ec(%rbp)
   5f50f:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   5f514:	test   %rax,%rax
   5f517:	mov    -0x5ec(%rbp),%r10d
   5f51e:	je     5f523 <_IO_vfscanf+0x3003>
   5f520:	mov    %rax,(%r14)
   5f523:	addl   $0x1,-0x5e8(%rbp)
   5f52a:	movl   $0x0,-0x600(%rbp)
   5f534:	mov    %rbx,%r14
   5f537:	mov    %r12,-0x668(%rbp)
   5f53e:	movq   $0x0,-0x608(%rbp)
   5f549:	jmpq   5c832 <_IO_vfscanf+0x312>
   5f54e:	mov    -0x638(%rbp),%r11d
   5f555:	test   %r11d,%r11d
   5f558:	jne    5fee4 <_IO_vfscanf+0x39c4>
   5f55e:	mov    -0x5a8(%rbp),%edx
   5f564:	cmp    $0x2f,%edx
   5f567:	ja     6338a <_IO_vfscanf+0x6e6a>
   5f56d:	mov    %edx,%eax
   5f56f:	add    -0x598(%rbp),%rax
   5f576:	add    $0x8,%edx
   5f579:	mov    %edx,-0x5a8(%rbp)
   5f57f:	mov    (%rax),%rax
   5f582:	mov    %rax,-0x640(%rbp)
   5f589:	cmpq   $0x0,-0x640(%rbp)
   5f591:	jne    5d274 <_IO_vfscanf+0xd54>
   5f597:	mov    %r13,%r15
   5f59a:	mov    $0x2,%r13d
   5f5a0:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5f5a5:	nopl   (%rax)
   5f5a8:	mov    -0x638(%rbp),%eax
   5f5ae:	test   %eax,%eax
   5f5b0:	jne    5ff76 <_IO_vfscanf+0x3a56>
   5f5b6:	mov    -0x5a8(%rbp),%edx
   5f5bc:	cmp    $0x2f,%edx
   5f5bf:	ja     63b0b <_IO_vfscanf+0x75eb>
   5f5c5:	mov    %edx,%eax
   5f5c7:	add    -0x598(%rbp),%rax
   5f5ce:	add    $0x8,%edx
   5f5d1:	mov    %edx,-0x5a8(%rbp)
   5f5d7:	mov    (%rax),%rax
   5f5da:	mov    %rax,-0x640(%rbp)
   5f5e1:	cmpq   $0x0,-0x640(%rbp)
   5f5e9:	jne    5d08a <_IO_vfscanf+0xb6a>
   5f5ef:	mov    %r13,%r15
   5f5f2:	mov    $0x2,%r13d
   5f5f8:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5f5fd:	nopl   (%rax)
   5f600:	mov    -0x5f8(%rbp),%rax
   5f607:	mov    0x70(%rax),%rbx
   5f60b:	mov    0x8(%r13),%rax
   5f60f:	cmp    0x10(%r13),%rax
   5f613:	jae    61bb0 <_IO_vfscanf+0x5690>
   5f619:	lea    0x1(%rax),%rdx
   5f61d:	mov    %rdx,0x8(%r13)
   5f621:	movzbl (%rax),%r10d
   5f625:	movzbl %r10b,%eax
   5f629:	cmpl   $0x69,(%rbx,%rax,4)
   5f62d:	jne    5e821 <_IO_vfscanf+0x2301>
   5f633:	mov    -0x5f8(%rbp),%rax
   5f63a:	mov    0x70(%rax),%rbx
   5f63e:	mov    0x8(%r13),%rax
   5f642:	cmp    0x10(%r13),%rax
   5f646:	jae    61b79 <_IO_vfscanf+0x5659>
   5f64c:	lea    0x1(%rax),%rdx
   5f650:	mov    %rdx,0x8(%r13)
   5f654:	movzbl (%rax),%r10d
   5f658:	movzbl %r10b,%eax
   5f65c:	cmpl   $0x6c,(%rbx,%rax,4)
   5f660:	jne    5e821 <_IO_vfscanf+0x2301>
   5f666:	mov    0x8(%r13),%rax
   5f66a:	cmp    0x10(%r13),%rax
   5f66e:	jae    6163d <_IO_vfscanf+0x511d>
   5f674:	lea    0x1(%rax),%rdx
   5f678:	mov    %rdx,0x8(%r13)
   5f67c:	movzbl (%rax),%r10d
   5f680:	add    $0x4,%r14
   5f684:	cmp    $0x29,%r10d
   5f688:	jne    6300e <_IO_vfscanf+0x6aee>
   5f68e:	mov    -0x450(%rbp),%rax
   5f695:	cmp    -0x448(%rbp),%rax
   5f69c:	je     61619 <_IO_vfscanf+0x50f9>
   5f6a2:	lea    0x1(%rax),%rdx
   5f6a6:	mov    %rdx,-0x450(%rbp)
   5f6ad:	movb   $0x30,(%rax)
   5f6b0:	jmpq   5d97f <_IO_vfscanf+0x145f>
   5f6b5:	mov    0x3607ac(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5f6bc:	movl   $0x16,%fs:(%rax)
   5f6c3:	jmpq   5c849 <_IO_vfscanf+0x329>
   5f6c8:	mov    0x360799(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5f6cf:	mov    %r13,%r15
   5f6d2:	movl   $0xffffffff,-0x5e8(%rbp)
   5f6dc:	xor    %r13d,%r13d
   5f6df:	movl   $0xc,%fs:(%rax)
   5f6e6:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5f6eb:	test   %rbx,%rbx
   5f6ee:	mov    %r10d,-0x678(%rbp)
   5f6f5:	je     5d7db <_IO_vfscanf+0x12bb>
   5f6fb:	mov    -0x610(%rbp),%rax
   5f702:	mov    %r8,-0x628(%rbp)
   5f709:	sub    -0x440(%rbp),%rbx
   5f710:	lea    0x10(%rax),%rdi
   5f714:	callq  8afb0 <__libc_scratch_buffer_grow_preserve>
   5f719:	test   %al,%al
   5f71b:	mov    -0x628(%rbp),%r8
   5f722:	mov    -0x678(%rbp),%r10d
   5f729:	je     61f4f <_IO_vfscanf+0x5a2f>
   5f72f:	mov    -0x440(%rbp),%rax
   5f736:	mov    %rax,%rdx
   5f739:	add    -0x438(%rbp),%rdx
   5f740:	add    %rax,%rbx
   5f743:	lea    0x1(%rbx),%rax
   5f747:	mov    %rax,-0x450(%rbp)
   5f74e:	mov    %rdx,-0x448(%rbp)
   5f755:	mov    %r10b,(%rbx)
   5f758:	jmpq   5d7db <_IO_vfscanf+0x12bb>
   5f75d:	lea    0x2(%rdx),%r15
   5f761:	movb   $0x1,-0x638(%rbp)
   5f768:	jmpq   5d68e <_IO_vfscanf+0x116e>
   5f76d:	test   %rbx,%rbx
   5f770:	je     5d847 <_IO_vfscanf+0x1327>
   5f776:	mov    -0x610(%rbp),%rax
   5f77d:	sub    -0x440(%rbp),%rbx
   5f784:	lea    0x10(%rax),%rdi
   5f788:	callq  8afb0 <__libc_scratch_buffer_grow_preserve>
   5f78d:	test   %al,%al
   5f78f:	je     61e38 <_IO_vfscanf+0x5918>
   5f795:	mov    -0x440(%rbp),%rax
   5f79c:	mov    %rax,%rdx
   5f79f:	add    -0x438(%rbp),%rdx
   5f7a6:	add    %rax,%rbx
   5f7a9:	lea    0x1(%rbx),%rax
   5f7ad:	mov    %rax,-0x450(%rbp)
   5f7b4:	mov    %rdx,-0x448(%rbp)
   5f7bb:	movb   $0x30,(%rbx)
   5f7be:	jmpq   5d847 <_IO_vfscanf+0x1327>
   5f7c3:	mov    %r13,%rdi
   5f7c6:	callq  7d720 <__uflow>
   5f7cb:	cmp    $0xffffffff,%eax
   5f7ce:	mov    %eax,%r12d
   5f7d1:	jne    5dc73 <_IO_vfscanf+0x1753>
   5f7d7:	mov    %eax,%r10d
   5f7da:	mov    0x360687(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5f7e1:	mov    %r15d,%r12d
   5f7e4:	mov    -0x698(%rbp),%r15
   5f7eb:	mov    %fs:(%rax),%eax
   5f7ee:	mov    %eax,-0x5e4(%rbp)
   5f7f4:	jmpq   5eadd <_IO_vfscanf+0x25bd>
   5f7f9:	mov    0x360668(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5f800:	mov    %r13,%r15
   5f803:	movl   $0xffffffff,-0x5e8(%rbp)
   5f80d:	xor    %r13d,%r13d
   5f810:	movl   $0xc,%fs:(%rax)
   5f817:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5f81c:	testb  $0x4,-0x5ec(%rbp)
   5f823:	je     61053 <_IO_vfscanf+0x4b33>
   5f829:	mov    -0x638(%rbp),%r11d
   5f830:	test   %r11d,%r11d
   5f833:	jne    61380 <_IO_vfscanf+0x4e60>
   5f839:	mov    -0x5a8(%rbp),%ecx
   5f83f:	cmp    $0x2f,%ecx
   5f842:	ja     63329 <_IO_vfscanf+0x6e09>
   5f848:	mov    %ecx,%edx
   5f84a:	add    -0x598(%rbp),%rdx
   5f851:	add    $0x8,%ecx
   5f854:	mov    %ecx,-0x5a8(%rbp)
   5f85a:	mov    (%rdx),%rdx
   5f85d:	mov    %ax,(%rdx)
   5f860:	jmpq   5da60 <_IO_vfscanf+0x1540>
   5f865:	testb  $0x4,-0x5ec(%rbp)
   5f86c:	je     60f70 <_IO_vfscanf+0x4a50>
   5f872:	mov    -0x638(%rbp),%eax
   5f878:	test   %eax,%eax
   5f87a:	jne    61331 <_IO_vfscanf+0x4e11>
   5f880:	mov    -0x5a8(%rbp),%edx
   5f886:	cmp    $0x2f,%edx
   5f889:	ja     6203f <_IO_vfscanf+0x5b1f>
   5f88f:	mov    %edx,%eax
   5f891:	add    -0x598(%rbp),%rax
   5f898:	add    $0x8,%edx
   5f89b:	mov    %edx,-0x5a8(%rbp)
   5f8a1:	mov    (%rax),%rax
   5f8a4:	mov    %r14w,(%rax)
   5f8a8:	movl   $0x0,-0x600(%rbp)
   5f8b2:	jmpq   5c832 <_IO_vfscanf+0x312>
   5f8b7:	testb  $0x4,-0x5ec(%rbp)
   5f8be:	je     60a40 <_IO_vfscanf+0x4520>
   5f8c4:	mov    -0x638(%rbp),%ecx
   5f8ca:	test   %ecx,%ecx
   5f8cc:	je     5f839 <_IO_vfscanf+0x3319>
   5f8d2:	mov    -0x650(%rbp),%rsi
   5f8d9:	mov    -0x630(%rbp),%rdi
   5f8e0:	xor    %ebx,%ebx
   5f8e2:	mov    (%rsi),%rdx
   5f8e5:	mov    %rdx,(%rdi)
   5f8e8:	mov    0x8(%rsi),%rcx
   5f8ec:	mov    %rcx,0x8(%rdi)
   5f8f0:	mov    0x10(%rsi),%rsi
   5f8f4:	mov    %rsi,0x10(%rdi)
   5f8f8:	mov    %edx,%esi
   5f8fa:	xor    %edi,%edi
   5f8fc:	subl   $0x1,-0x638(%rbp)
   5f903:	je     637ac <_IO_vfscanf+0x728c>
   5f909:	cmp    $0x2f,%esi
   5f90c:	ja     6388a <_IO_vfscanf+0x736a>
   5f912:	add    $0x8,%esi
   5f915:	mov    $0x1,%ebx
   5f91a:	jmp    5f8fc <_IO_vfscanf+0x33dc>
   5f91c:	nopl   0x0(%rax)
   5f920:	testb  $0xa,-0x600(%rbp)
   5f927:	jne    5d891 <_IO_vfscanf+0x1371>
   5f92d:	xor    %eax,%eax
   5f92f:	test   %r12d,%r12d
   5f932:	setg   %al
   5f935:	sub    %eax,%r12d
   5f938:	cmp    $0xffffffff,%r10d
   5f93c:	je     618f5 <_IO_vfscanf+0x53d5>
   5f942:	mov    0x8(%r13),%rax
   5f946:	cmp    0x10(%r13),%rax
   5f94a:	jae    63ad8 <_IO_vfscanf+0x75b8>
   5f950:	lea    0x1(%rax),%rdx
   5f954:	mov    %rdx,0x8(%r13)
   5f958:	movzbl (%rax),%r10d
   5f95c:	add    $0x1,%r14
   5f960:	movl   $0x10,-0x600(%rbp)
   5f96a:	jmpq   5d8b4 <_IO_vfscanf+0x1394>
   5f96f:	mov    %r13,%r15
   5f972:	mov    0x3604ef(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5f979:	xor    %r13d,%r13d
   5f97c:	movl   $0xffffffff,-0x5e8(%rbp)
   5f986:	movl   $0xc,%fs:(%rax)
   5f98d:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5f992:	mov    %r13,%r15
   5f995:	mov    $0x2,%r13d
   5f99b:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5f9a0:	mov    -0x450(%rbp),%rax
   5f9a7:	cmp    -0x448(%rbp),%rax
   5f9ae:	je     61cf0 <_IO_vfscanf+0x57d0>
   5f9b4:	lea    0x1(%rax),%rdx
   5f9b8:	mov    %rdx,-0x450(%rbp)
   5f9bf:	mov    %r10b,(%rax)
   5f9c2:	test   %r12d,%r12d
   5f9c5:	je     614e3 <_IO_vfscanf+0x4fc3>
   5f9cb:	mov    0x8(%r13),%rax
   5f9cf:	cmp    0x10(%r13),%rax
   5f9d3:	jae    6226c <_IO_vfscanf+0x5d4c>
   5f9d9:	lea    0x1(%rax),%rdx
   5f9dd:	mov    %rdx,0x8(%r13)
   5f9e1:	movzbl (%rax),%eax
   5f9e4:	mov    -0x5f8(%rbp),%rsi
   5f9eb:	movzbl %al,%edx
   5f9ee:	mov    0x70(%rsi),%rcx
   5f9f2:	cmpl   $0x61,(%rcx,%rdx,4)
   5f9f6:	jne    61fb0 <_IO_vfscanf+0x5a90>
   5f9fc:	xor    %edx,%edx
   5f9fe:	test   %r12d,%r12d
   5fa01:	setg   %dl
   5fa04:	sub    %edx,%r12d
   5fa07:	mov    -0x450(%rbp),%rdx
   5fa0e:	cmp    -0x448(%rbp),%rdx
   5fa15:	je     62019 <_IO_vfscanf+0x5af9>
   5fa1b:	lea    0x1(%rdx),%rcx
   5fa1f:	mov    %rcx,-0x450(%rbp)
   5fa26:	mov    %al,(%rdx)
   5fa28:	test   %r12d,%r12d
   5fa2b:	je     6200b <_IO_vfscanf+0x5aeb>
   5fa31:	mov    0x8(%r13),%rax
   5fa35:	cmp    0x10(%r13),%rax
   5fa39:	jae    61fed <_IO_vfscanf+0x5acd>
   5fa3f:	lea    0x1(%rax),%rdx
   5fa43:	add    $0x2,%r14
   5fa47:	mov    %rdx,0x8(%r13)
   5fa4b:	movzbl (%rax),%r10d
   5fa4f:	mov    -0x5f8(%rbp),%rdi
   5fa56:	movzbl %r10b,%eax
   5fa5a:	mov    0x70(%rdi),%rdx
   5fa5e:	cmpl   $0x6e,(%rdx,%rax,4)
   5fa62:	jne    61fdf <_IO_vfscanf+0x5abf>
   5fa68:	mov    -0x450(%rbp),%rax
   5fa6f:	cmp    -0x448(%rbp),%rax
   5fa76:	movsbl %r10b,%esi
   5fa7a:	je     62c6f <_IO_vfscanf+0x674f>
   5fa80:	lea    0x1(%rax),%rdx
   5fa84:	mov    %rdx,-0x450(%rbp)
   5fa8b:	mov    %r10b,(%rax)
   5fa8e:	mov    -0x450(%rbp),%rax
   5fa95:	jmpq   5eb27 <_IO_vfscanf+0x2607>
   5fa9a:	fstp   %st(0)
   5fa9c:	mov    -0x440(%rbp),%rax
   5faa3:	cmp    %rax,-0x5c8(%rbp)
   5faaa:	jne    5c77d <_IO_vfscanf+0x25d>
   5fab0:	mov    %r13,%r15
   5fab3:	mov    $0x2,%r13d
   5fab9:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   5fabe:	mov    %r13,%r15
   5fac1:	mov    0x3603a0(%rip),%rdx        # 3bfe68 <_DYNAMIC+0x308>
   5fac8:	jmpq   5e134 <_IO_vfscanf+0x1c14>
   5facd:	mov    -0x5ec(%rbp),%edi
   5fad3:	and    $0x2100,%edi
   5fad9:	mov    %edi,-0x5ec(%rbp)
   5fadf:	jne    60d4e <_IO_vfscanf+0x482e>
   5fae5:	mov    -0x668(%rbp),%rbx
   5faec:	mov    %r12d,%edi
   5faef:	mov    %rax,%r14
   5faf2:	mov    %r15,%r12
   5faf5:	mov    %r10d,%eax
   5faf8:	mov    %edi,%r15d
   5fafb:	add    $0x1,%rbx
   5faff:	mov    %r15d,%edx
   5fb02:	mov    %al,-0x1(%rbx)
   5fb05:	sub    %ebx,%edx
   5fb07:	add    -0x668(%rbp),%edx
   5fb0d:	test   %edx,%edx
   5fb0f:	jle    613d0 <_IO_vfscanf+0x4eb0>
   5fb15:	mov    0x8(%r13),%rax
   5fb19:	cmp    %rax,0x10(%r13)
   5fb1d:	jbe    5fe50 <_IO_vfscanf+0x3930>
   5fb23:	lea    0x1(%rax),%rdx
   5fb27:	mov    %rdx,0x8(%r13)
   5fb2b:	movzbl (%rax),%eax
   5fb2e:	add    $0x1,%r14
   5fb32:	jmp    5fafb <_IO_vfscanf+0x35db>
   5fb34:	movl   $0x65,-0x6a4(%rbp)
   5fb3e:	movb   $0x65,-0x688(%rbp)
   5fb45:	xor    %edx,%edx
   5fb47:	jmpq   5dbd2 <_IO_vfscanf+0x16b2>
   5fb4c:	mov    -0x6b8(%rbp),%esi
   5fb52:	test   %esi,%esi
   5fb54:	je     5f1c9 <_IO_vfscanf+0x2ca9>
   5fb5a:	mov    -0x670(%rbp),%rax
   5fb61:	sub    %rax,%rbx
   5fb64:	test   %rbx,%rbx
   5fb67:	jle    6387c <_IO_vfscanf+0x735c>
   5fb6d:	mov    -0x620(%rbp),%rdi
   5fb74:	movzbl (%rax),%esi
   5fb77:	cmp    %sil,(%rdi)
   5fb7a:	jne    6366f <_IO_vfscanf+0x714f>
   5fb80:	mov    %rdi,%rsi
   5fb83:	mov    %rdi,%rdx
   5fb86:	mov    %rax,%rdi
   5fb89:	jmp    5fb97 <_IO_vfscanf+0x3677>
   5fb8b:	movzbl (%rdi,%rax,1),%eax
   5fb8f:	cmp    %al,(%rsi)
   5fb91:	jne    5f1d9 <_IO_vfscanf+0x2cb9>
   5fb97:	add    $0x1,%rsi
   5fb9b:	mov    %rsi,%rax
   5fb9e:	sub    %rdx,%rax
   5fba1:	cmp    %rbx,%rax
   5fba4:	jl     5fb8b <_IO_vfscanf+0x366b>
   5fba6:	cmp    %rbx,%rax
   5fba9:	jne    5f1d0 <_IO_vfscanf+0x2cb0>
   5fbaf:	movzbl (%rsi),%eax
   5fbb2:	cmp    %r12d,%eax
   5fbb5:	jne    5f1d9 <_IO_vfscanf+0x2cb9>
   5fbbb:	cmpb   $0x0,0x1(%rsi)
   5fbbf:	lea    0x1(%rsi),%rax
   5fbc3:	je     5f1e2 <_IO_vfscanf+0x2cc2>
   5fbc9:	test   %ecx,%ecx
   5fbcb:	je     6213d <_IO_vfscanf+0x5c1d>
   5fbd1:	mov    %rax,%rbx
   5fbd4:	jmp    5fc0a <_IO_vfscanf+0x36ea>
   5fbd6:	lea    0x1(%rax),%rdx
   5fbda:	mov    %rdx,0x8(%r13)
   5fbde:	movzbl (%rax),%eax
   5fbe1:	movzbl (%rbx),%r12d
   5fbe5:	add    $0x1,%r14
   5fbe9:	sub    $0x1,%ecx
   5fbec:	cmp    %eax,%r12d
   5fbef:	jne    6369a <_IO_vfscanf+0x717a>
   5fbf5:	add    $0x1,%rbx
   5fbf9:	cmpb   $0x0,(%rbx)
   5fbfc:	je     5f1e2 <_IO_vfscanf+0x2cc2>
   5fc02:	test   %ecx,%ecx
   5fc04:	je     6213d <_IO_vfscanf+0x5c1d>
   5fc0a:	mov    0x8(%r13),%rax
   5fc0e:	cmp    0x10(%r13),%rax
   5fc12:	jb     5fbd6 <_IO_vfscanf+0x36b6>
   5fc14:	mov    %r13,%rdi
   5fc17:	mov    %ecx,-0x6c0(%rbp)
   5fc1d:	callq  7d720 <__uflow>
   5fc22:	cmp    $0xffffffff,%eax
   5fc25:	mov    %eax,%r12d
   5fc28:	mov    -0x6c0(%rbp),%ecx
   5fc2e:	jne    5fbe1 <_IO_vfscanf+0x36c1>
   5fc30:	mov    0x360231(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5fc37:	mov    %rbx,%rsi
   5fc3a:	mov    %fs:(%rax),%eax
   5fc3d:	mov    %eax,-0x5e4(%rbp)
   5fc43:	jmpq   5f1d9 <_IO_vfscanf+0x2cb9>
   5fc48:	mov    -0x650(%rbp),%rsi
   5fc4f:	mov    -0x630(%rbp),%rdi
   5fc56:	mov    -0x638(%rbp),%r8d
   5fc5d:	mov    (%rsi),%rax
   5fc60:	mov    %rax,(%rdi)
   5fc63:	mov    0x8(%rsi),%rdx
   5fc67:	mov    %rdx,0x8(%rdi)
   5fc6b:	mov    0x10(%rsi),%rcx
   5fc6f:	xor    %esi,%esi
   5fc71:	mov    %rcx,0x10(%rdi)
   5fc75:	mov    %eax,%ecx
   5fc77:	xor    %edi,%edi
   5fc79:	sub    $0x1,%r8d
   5fc7d:	je     63766 <_IO_vfscanf+0x7246>
   5fc83:	cmp    $0x2f,%ecx
   5fc86:	ja     63758 <_IO_vfscanf+0x7238>
   5fc8c:	add    $0x8,%ecx
   5fc8f:	mov    $0x1,%edi
   5fc94:	jmp    5fc79 <_IO_vfscanf+0x3759>
   5fc96:	nopw   %cs:0x0(%rax,%rax,1)
   5fca0:	mov    -0x650(%rbp),%rsi
   5fca7:	mov    -0x630(%rbp),%rdi
   5fcae:	mov    -0x638(%rbp),%r8d
   5fcb5:	mov    (%rsi),%rax
   5fcb8:	mov    %rax,(%rdi)
   5fcbb:	mov    0x8(%rsi),%rdx
   5fcbf:	mov    %rdx,0x8(%rdi)
   5fcc3:	mov    0x10(%rsi),%rcx
   5fcc7:	xor    %esi,%esi
   5fcc9:	mov    %rcx,0x10(%rdi)
   5fccd:	mov    %eax,%ecx
   5fccf:	xor    %edi,%edi
   5fcd1:	sub    $0x1,%r8d
   5fcd5:	je     63231 <_IO_vfscanf+0x6d11>
   5fcdb:	cmp    $0x2f,%ecx
   5fcde:	ja     63223 <_IO_vfscanf+0x6d03>
   5fce4:	add    $0x8,%ecx
   5fce7:	mov    $0x1,%edi
   5fcec:	jmp    5fcd1 <_IO_vfscanf+0x37b1>
   5fcee:	xchg   %ax,%ax
   5fcf0:	mov    -0x450(%rbp),%rax
   5fcf7:	cmp    -0x448(%rbp),%rax
   5fcfe:	je     636bc <_IO_vfscanf+0x719c>
   5fd04:	lea    0x1(%rax),%rdx
   5fd08:	mov    %rdx,-0x450(%rbp)
   5fd0f:	mov    %r10b,(%rax)
   5fd12:	test   %r12d,%r12d
   5fd15:	je     61d13 <_IO_vfscanf+0x57f3>
   5fd1b:	mov    0x8(%r13),%rax
   5fd1f:	cmp    0x10(%r13),%rax
   5fd23:	jae    6360d <_IO_vfscanf+0x70ed>
   5fd29:	lea    0x1(%rax),%rdx
   5fd2d:	mov    %rdx,0x8(%r13)
   5fd31:	movzbl (%rax),%eax
   5fd34:	mov    -0x5f8(%rbp),%rsi
   5fd3b:	movzbl %al,%edx
   5fd3e:	mov    0x70(%rsi),%rcx
   5fd42:	cmpl   $0x6e,(%rcx,%rdx,4)
   5fd46:	jne    61d05 <_IO_vfscanf+0x57e5>
   5fd4c:	xor    %edx,%edx
   5fd4e:	test   %r12d,%r12d
   5fd51:	setg   %dl
   5fd54:	sub    %edx,%r12d
   5fd57:	mov    -0x450(%rbp),%rdx
   5fd5e:	cmp    -0x448(%rbp),%rdx
   5fd65:	je     63801 <_IO_vfscanf+0x72e1>
   5fd6b:	lea    0x1(%rdx),%rcx
   5fd6f:	mov    %rcx,-0x450(%rbp)
   5fd76:	mov    %al,(%rdx)
   5fd78:	test   %r12d,%r12d
   5fd7b:	je     637f3 <_IO_vfscanf+0x72d3>
   5fd81:	mov    0x8(%r13),%rax
   5fd85:	cmp    0x10(%r13),%rax
   5fd89:	jae    61aef <_IO_vfscanf+0x55cf>
   5fd8f:	lea    0x1(%rax),%rdx
   5fd93:	lea    0x2(%r14),%rbx
   5fd97:	mov    %rdx,0x8(%r13)
   5fd9b:	movzbl (%rax),%r10d
   5fd9f:	mov    -0x5f8(%rbp),%rdi
   5fda6:	movzbl %r10b,%eax
   5fdaa:	mov    0x70(%rdi),%rdx
   5fdae:	cmpl   $0x66,(%rdx,%rax,4)
   5fdb2:	jne    63815 <_IO_vfscanf+0x72f5>
   5fdb8:	xor    %eax,%eax
   5fdba:	test   %r12d,%r12d
   5fdbd:	setg   %al
   5fdc0:	sub    %eax,%r12d
   5fdc3:	mov    -0x450(%rbp),%rax
   5fdca:	cmp    -0x448(%rbp),%rax
   5fdd1:	je     63d1b <_IO_vfscanf+0x77fb>
   5fdd7:	lea    0x1(%rax),%rdx
   5fddb:	mov    %rdx,-0x450(%rbp)
   5fde2:	mov    %r10b,(%rax)
   5fde5:	test   %r12d,%r12d
   5fde8:	je     61432 <_IO_vfscanf+0x4f12>
   5fdee:	mov    0x8(%r13),%rax
   5fdf2:	cmp    0x10(%r13),%rax
   5fdf6:	jae    6140e <_IO_vfscanf+0x4eee>
   5fdfc:	lea    0x1(%rax),%rdx
   5fe00:	mov    %rdx,0x8(%r13)
   5fe04:	movzbl (%rax),%r10d
   5fe08:	mov    -0x5f8(%rbp),%rdi
   5fe0f:	movzbl %r10b,%eax
   5fe13:	mov    0x70(%rdi),%rdx
   5fe17:	cmpl   $0x69,(%rdx,%rax,4)
   5fe1b:	je     62aab <_IO_vfscanf+0x658b>
   5fe21:	movzbl %r10b,%esi
   5fe25:	mov    %r13,%rdi
   5fe28:	mov    %r10d,-0x600(%rbp)
   5fe2f:	mov    %rbx,%r14
   5fe32:	callq  7e5a0 <_IO_sputbackc>
   5fe37:	mov    -0x450(%rbp),%rax
   5fe3e:	mov    -0x600(%rbp),%r10d
   5fe45:	jmpq   5eb27 <_IO_vfscanf+0x2607>
   5fe4a:	nopw   0x0(%rax,%rax,1)
   5fe50:	mov    %r13,%rdi
   5fe53:	callq  7d720 <__uflow>
   5fe58:	cmp    $0xffffffff,%eax
   5fe5b:	jne    5fb2e <_IO_vfscanf+0x360e>
   5fe61:	mov    %r12,%r15
   5fe64:	mov    0x35fffd(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5fe6b:	mov    -0x5ec(%rbp),%r12d
   5fe72:	mov    $0xffffffff,%r10d
   5fe78:	mov    %fs:(%rax),%eax
   5fe7b:	test   %r12d,%r12d
   5fe7e:	mov    %eax,-0x5e4(%rbp)
   5fe84:	je     5febc <_IO_vfscanf+0x399c>
   5fe86:	mov    -0x608(%rbp),%r12
   5fe8d:	mov    %rbx,%rsi
   5fe90:	mov    (%r12),%rdi
   5fe94:	sub    %rdi,%rsi
   5fe97:	cmp    -0x658(%rbp),%rsi
   5fe9e:	je     5febc <_IO_vfscanf+0x399c>
   5fea0:	mov    %r10d,-0x5ec(%rbp)
   5fea7:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   5feac:	test   %rax,%rax
   5feaf:	mov    -0x5ec(%rbp),%r10d
   5feb6:	je     5febc <_IO_vfscanf+0x399c>
   5feb8:	mov    %rax,(%r12)
   5febc:	mov    %rbx,-0x668(%rbp)
   5fec3:	addl   $0x1,-0x5e8(%rbp)
   5feca:	movl   $0x0,-0x600(%rbp)
   5fed4:	movq   $0x0,-0x608(%rbp)
   5fedf:	jmpq   5c832 <_IO_vfscanf+0x312>
   5fee4:	mov    -0x650(%rbp),%rsi
   5feeb:	mov    -0x630(%rbp),%rdi
   5fef2:	mov    -0x638(%rbp),%r8d
   5fef9:	mov    (%rsi),%rax
   5fefc:	mov    %rax,(%rdi)
   5feff:	mov    0x8(%rsi),%rdx
   5ff03:	mov    %rdx,0x8(%rdi)
   5ff07:	mov    0x10(%rsi),%rcx
   5ff0b:	xor    %esi,%esi
   5ff0d:	mov    %rcx,0x10(%rdi)
   5ff11:	mov    %eax,%ecx
   5ff13:	xor    %edi,%edi
   5ff15:	sub    $0x1,%r8d
   5ff19:	je     630da <_IO_vfscanf+0x6bba>
   5ff1f:	cmp    $0x2f,%ecx
   5ff22:	ja     630cc <_IO_vfscanf+0x6bac>
   5ff28:	add    $0x8,%ecx
   5ff2b:	mov    $0x1,%edi
   5ff30:	jmp    5ff15 <_IO_vfscanf+0x39f5>
   5ff32:	nopw   0x0(%rax,%rax,1)
   5ff38:	test   %rbx,%rbx
   5ff3b:	je     5f96f <_IO_vfscanf+0x344f>
   5ff41:	mov    -0x440(%rbp),%rax
   5ff48:	jmpq   5e9fd <_IO_vfscanf+0x24dd>
   5ff4d:	mov    %r13,%rdi
   5ff50:	callq  7d720 <__uflow>
   5ff55:	cmp    $0xffffffff,%eax
   5ff58:	mov    %eax,%r10d
   5ff5b:	jne    5d861 <_IO_vfscanf+0x1341>
   5ff61:	mov    0x35ff00(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   5ff68:	mov    %fs:(%rax),%eax
   5ff6b:	mov    %eax,-0x5e4(%rbp)
   5ff71:	jmpq   5d865 <_IO_vfscanf+0x1345>
   5ff76:	mov    -0x650(%rbp),%rsi
   5ff7d:	mov    -0x630(%rbp),%rdi
   5ff84:	mov    -0x638(%rbp),%r8d
   5ff8b:	mov    (%rsi),%rax
   5ff8e:	mov    %rax,(%rdi)
   5ff91:	mov    0x8(%rsi),%rdx
   5ff95:	mov    %rdx,0x8(%rdi)
   5ff99:	mov    0x10(%rsi),%rcx
   5ff9d:	xor    %esi,%esi
   5ff9f:	mov    %rcx,0x10(%rdi)
   5ffa3:	mov    %eax,%ecx
   5ffa5:	xor    %edi,%edi
   5ffa7:	sub    $0x1,%r8d
   5ffab:	je     63b56 <_IO_vfscanf+0x7636>
   5ffb1:	cmp    $0x2f,%ecx
   5ffb4:	ja     63b48 <_IO_vfscanf+0x7628>
   5ffba:	add    $0x8,%ecx
   5ffbd:	mov    $0x1,%edi
   5ffc2:	jmp    5ffa7 <_IO_vfscanf+0x3a87>
   5ffc4:	nopl   0x0(%rax)
   5ffc8:	mov    %r13,-0x668(%rbp)
   5ffcf:	mov    -0x688(%rbp),%r15
   5ffd6:	mov    %rbx,%r13
   5ffd9:	mov    %r12d,%r10d
   5ffdc:	mov    %r14,%rbx
   5ffdf:	mov    -0x690(%rbp),%r14
   5ffe6:	jmpq   5f4bb <_IO_vfscanf+0x2f9b>
   5ffeb:	movzbl %r10b,%esi
   5ffef:	mov    %r13,%rdi
   5fff2:	mov    %r10d,-0x5ec(%rbp)
   5fff9:	sub    $0x1,%rbx
   5fffd:	callq  7e5a0 <_IO_sputbackc>
   60002:	mov    -0x5ec(%rbp),%r10d
   60009:	jmpq   5eeee <_IO_vfscanf+0x29ce>
   6000e:	mov    -0x658(%rbp),%rax
   60015:	mov    %r12d,-0x668(%rbp)
   6001c:	lea    0x1(%rax),%r13
   60020:	lea    (%rax,%rax,1),%r9
   60024:	mov    %r13,%r12
   60027:	mov    %rbx,%r13
   6002a:	mov    %r9,%rbx
   6002d:	jmp    60046 <_IO_vfscanf+0x3b26>
   6002f:	nop
   60030:	cmp    %r12,%rbx
   60033:	jbe    61794 <_IO_vfscanf+0x5274>
   60039:	mov    -0x608(%rbp),%rax
   60040:	mov    %r12,%rbx
   60043:	mov    (%rax),%rdi
   60046:	mov    %rbx,%rsi
   60049:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   6004e:	test   %rax,%rax
   60051:	je     60030 <_IO_vfscanf+0x3b10>
   60053:	mov    %rbx,%r9
   60056:	mov    -0x608(%rbp),%rdi
   6005d:	mov    %r13,%rbx
   60060:	mov    -0x658(%rbp),%r13
   60067:	mov    -0x668(%rbp),%r12d
   6006e:	mov    %r9,-0x658(%rbp)
   60075:	mov    %rax,(%rdi)
   60078:	add    %rax,%r13
   6007b:	jmpq   5f3ff <_IO_vfscanf+0x2edf>
   60080:	lea    0x1299c6(%rip),%rdi        # 189a4d <null+0xf>
   60087:	mov    %r10d,-0x628(%rbp)
   6008e:	callq  10b870 <wctrans>
   60093:	mov    -0x648(%rbp),%rsi
   6009a:	mov    %rax,-0x6a0(%rbp)
   600a1:	mov    -0x628(%rbp),%r10d
   600a8:	mov    0xd8(%rsi),%edi
   600ae:	mov    %edi,-0x600(%rbp)
   600b4:	sub    $0x1,%edi
   600b7:	test   %rax,%rax
   600ba:	mov    %edi,-0x6b0(%rbp)
   600c0:	jne    62d4c <_IO_vfscanf+0x682c>
   600c6:	mov    -0x5ec(%rbp),%eax
   600cc:	mov    %r12d,-0x6a4(%rbp)
   600d3:	mov    %r13,%r12
   600d6:	movl   $0x0,-0x698(%rbp)
   600e0:	mov    %r15,-0x6b8(%rbp)
   600e7:	mov    %r10d,%r13d
   600ea:	and    $0x80,%eax
   600ef:	mov    %eax,-0x6c0(%rbp)
   600f5:	mov    -0x610(%rbp),%rax
   600fc:	add    $0x10,%rax
   60100:	mov    %rax,-0x6c8(%rbp)
   60107:	cmp    $0xffffffff,%r13d
   6010b:	je     60b21 <_IO_vfscanf+0x4601>
   60111:	mov    -0x6a4(%rbp),%r8d
   60118:	test   %r8d,%r8d
   6011b:	je     60b21 <_IO_vfscanf+0x4601>
   60121:	mov    -0x6a4(%rbp),%edi
   60127:	mov    $0x7fffffff,%eax
   6012c:	test   %edi,%edi
   6012e:	cmovg  %edi,%eax
   60131:	xor    %ebx,%ebx
   60133:	mov    %eax,-0x688(%rbp)
   60139:	lea    -0x570(%rbp),%rax
   60140:	mov    %rax,-0x628(%rbp)
   60147:	nopw   0x0(%rax,%rax,1)
   60150:	cmpq   $0x0,-0x6a0(%rbp)
   60158:	mov    %ebx,-0x678(%rbp)
   6015e:	jne    606cf <_IO_vfscanf+0x41af>
   60164:	mov    -0x648(%rbp),%rax
   6016b:	mov    0xe0(%rax,%rbx,8),%rdx
   60173:	mov    -0x698(%rbp),%esi
   60179:	mov    -0x628(%rbp),%rax
   60180:	test   %esi,%esi
   60182:	mov    %rdx,(%rax,%rbx,8)
   60186:	je     601d1 <_IO_vfscanf+0x3cb1>
   60188:	xor    %r15d,%r15d
   6018b:	mov    %r14,-0x600(%rbp)
   60192:	mov    %r12,-0x690(%rbp)
   60199:	mov    %rdx,%rdi
   6019c:	mov    %r15d,%r12d
   6019f:	mov    %esi,%r14d
   601a2:	mov    %rax,%r15
   601a5:	nopl   (%rax)
   601a8:	xor    %esi,%esi
   601aa:	add    $0x1,%r12d
   601ae:	callq  97340 <__rawmemchr>
   601b3:	lea    0x1(%rax),%rdi
   601b7:	cmp    %r12d,%r14d
   601ba:	mov    %rdi,(%r15,%rbx,8)
   601be:	jne    601a8 <_IO_vfscanf+0x3c88>
   601c0:	mov    -0x600(%rbp),%r14
   601c7:	mov    -0x690(%rbp),%r12
   601ce:	mov    %rdi,%rdx
   601d1:	movzbl (%rdx),%ecx
   601d4:	cmp    %r13d,%ecx
   601d7:	jne    6075b <_IO_vfscanf+0x423b>
   601dd:	cmpb   $0x0,0x1(%rdx)
   601e1:	lea    0x1(%rdx),%rcx
   601e5:	mov    -0x688(%rbp),%r8d
   601ec:	je     6076a <_IO_vfscanf+0x424a>
   601f2:	mov    %rcx,%r15
   601f5:	jmp    6023b <_IO_vfscanf+0x3d1b>
   601f7:	nopw   0x0(%rax,%rax,1)
   60200:	lea    0x1(%rax),%rcx
   60204:	mov    %rcx,0x8(%r12)
   60209:	movzbl (%rax),%r13d
   6020d:	movzbl (%r15),%ecx
   60211:	add    $0x1,%r14
   60215:	sub    $0x1,%r8d
   60219:	cmp    %r13d,%ecx
   6021c:	mov    %ecx,%eax
   6021e:	jne    606c7 <_IO_vfscanf+0x41a7>
   60224:	add    $0x1,%r15
   60228:	cmpb   $0x0,(%r15)
   6022c:	je     6076a <_IO_vfscanf+0x424a>
   60232:	test   %r8d,%r8d
   60235:	je     6068a <_IO_vfscanf+0x416a>
   6023b:	mov    0x8(%r12),%rax
   60240:	cmp    0x10(%r12),%rax
   60245:	jb     60200 <_IO_vfscanf+0x3ce0>
   60247:	mov    %r12,%rdi
   6024a:	mov    %rdx,-0x690(%rbp)
   60251:	mov    %r8d,-0x600(%rbp)
   60258:	callq  7d720 <__uflow>
   6025d:	cmp    $0xffffffff,%eax
   60260:	mov    %eax,%r13d
   60263:	mov    -0x600(%rbp),%r8d
   6026a:	mov    -0x690(%rbp),%rdx
   60271:	jne    6020d <_IO_vfscanf+0x3ced>
   60273:	mov    0x35fbee(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   6027a:	mov    %r15,%rcx
   6027d:	mov    %fs:(%rax),%eax
   60280:	mov    %eax,-0x5e4(%rbp)
   60286:	movzbl (%r15),%eax
   6028a:	test   %al,%al
   6028c:	je     6076a <_IO_vfscanf+0x424a>
   60292:	cmp    %rdx,%rcx
   60295:	jbe    602f9 <_IO_vfscanf+0x3dd9>
   60297:	cmp    $0xffffffff,%r13d
   6029b:	jne    60696 <_IO_vfscanf+0x4176>
   602a1:	lea    -0x1(%rcx),%r15
   602a5:	cmp    %r15,%rdx
   602a8:	jae    602f5 <_IO_vfscanf+0x3dd5>
   602aa:	mov    %rbx,-0x678(%rbp)
   602b1:	mov    %rcx,-0x600(%rbp)
   602b8:	mov    %r15,%rbx
   602bb:	mov    %rdx,%r13
   602be:	xchg   %ax,%ax
   602c0:	movzbl (%rbx),%esi
   602c3:	mov    %r12,%rdi
   602c6:	sub    $0x1,%rbx
   602ca:	callq  7e5a0 <_IO_sputbackc>
   602cf:	cmp    %r13,%rbx
   602d2:	jne    602c0 <_IO_vfscanf+0x3da0>
   602d4:	mov    -0x600(%rbp),%rcx
   602db:	mov    %r13,%rax
   602de:	mov    -0x678(%rbp),%rbx
   602e5:	mov    %r13,%rdx
   602e8:	sub    %rcx,%rax
   602eb:	add    $0x1,%rax
   602ef:	add    %rax,%r15
   602f2:	add    %rax,%r14
   602f5:	movzbl (%r15),%r13d
   602f9:	xor    %esi,%esi
   602fb:	mov    %rdx,%rdi
   602fe:	callq  97340 <__rawmemchr>
   60303:	mov    -0x628(%rbp),%rsi
   6030a:	add    $0x1,%rax
   6030e:	mov    %rax,(%rsi,%rbx,8)
   60312:	add    $0x1,%rbx
   60316:	cmp    $0xa,%rbx
   6031a:	jne    60150 <_IO_vfscanf+0x3c30>
   60320:	mov    -0x698(%rbp),%eax
   60326:	add    $0x1,%eax
   60329:	cmp    %eax,-0x6b0(%rbp)
   6032f:	mov    %eax,-0x690(%rbp)
   60335:	jl     604ab <_IO_vfscanf+0x3f8b>
   6033b:	nopl   0x0(%rax,%rax,1)
   60340:	mov    -0x628(%rbp),%rdi
   60347:	movq   $0x0,-0x600(%rbp)
   60352:	nopw   0x0(%rax,%rax,1)
   60358:	mov    -0x600(%rbp),%rax
   6035f:	mov    (%rdi,%rax,8),%rbx
   60363:	mov    %eax,-0x678(%rbp)
   60369:	movzbl (%rbx),%edx
   6036c:	cmp    %r13d,%edx
   6036f:	jne    606df <_IO_vfscanf+0x41bf>
   60375:	cmpb   $0x0,0x1(%rbx)
   60379:	lea    0x1(%rbx),%r15
   6037d:	mov    -0x688(%rbp),%r8d
   60384:	je     605fb <_IO_vfscanf+0x40db>
   6038a:	mov    %r8d,%r13d
   6038d:	jmp    603c7 <_IO_vfscanf+0x3ea7>
   6038f:	nop
   60390:	lea    0x1(%rax),%rdx
   60394:	mov    %rdx,0x8(%r12)
   60399:	movzbl (%rax),%eax
   6039c:	movzbl (%r15),%ecx
   603a0:	add    $0x1,%r14
   603a4:	sub    $0x1,%r13d
   603a8:	cmp    %eax,%ecx
   603aa:	jne    605e8 <_IO_vfscanf+0x40c8>
   603b0:	add    $0x1,%r15
   603b4:	cmpb   $0x0,(%r15)
   603b8:	je     605f8 <_IO_vfscanf+0x40d8>
   603be:	test   %r13d,%r13d
   603c1:	je     605c0 <_IO_vfscanf+0x40a0>
   603c7:	mov    0x8(%r12),%rax
   603cc:	cmp    0x10(%r12),%rax
   603d1:	jb     60390 <_IO_vfscanf+0x3e70>
   603d3:	mov    %r12,%rdi
   603d6:	callq  7d720 <__uflow>
   603db:	cmp    $0xffffffff,%eax
   603de:	jne    6039c <_IO_vfscanf+0x3e7c>
   603e0:	mov    %r13d,%r8d
   603e3:	mov    %eax,%r13d
   603e6:	mov    0x35fa7b(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   603ed:	mov    %fs:(%rax),%eax
   603f0:	mov    %eax,-0x5e4(%rbp)
   603f6:	movzbl (%r15),%eax
   603fa:	test   %al,%al
   603fc:	je     605fb <_IO_vfscanf+0x40db>
   60402:	cmp    %r15,%rbx
   60405:	jae    6045d <_IO_vfscanf+0x3f3d>
   60407:	cmp    $0xffffffff,%r13d
   6040b:	jne    605cc <_IO_vfscanf+0x40ac>
   60411:	lea    -0x1(%r15),%rax
   60415:	cmp    %rbx,%rax
   60418:	mov    %rax,-0x678(%rbp)
   6041f:	jbe    60459 <_IO_vfscanf+0x3f39>
   60421:	mov    %rax,%r13
   60424:	nopl   0x0(%rax)
   60428:	movzbl 0x0(%r13),%esi
   6042d:	mov    %r12,%rdi
   60430:	sub    $0x1,%r13
   60434:	callq  7e5a0 <_IO_sputbackc>
   60439:	cmp    %r13,%rbx
   6043c:	jne    60428 <_IO_vfscanf+0x3f08>
   6043e:	mov    %rbx,%rax
   60441:	sub    %r15,%rax
   60444:	add    $0x1,%rax
   60448:	add    %rax,-0x678(%rbp)
   6044f:	add    %rax,%r14
   60452:	mov    -0x678(%rbp),%rax
   60459:	movzbl (%rax),%r13d
   6045d:	xor    %esi,%esi
   6045f:	mov    %rbx,%rdi
   60462:	callq  97340 <__rawmemchr>
   60467:	mov    -0x600(%rbp),%rsi
   6046e:	mov    -0x628(%rbp),%rdi
   60475:	add    $0x1,%rax
   60479:	mov    %rax,(%rdi,%rsi,8)
   6047d:	add    $0x1,%rsi
   60481:	cmp    $0xa,%rsi
   60485:	mov    %rsi,-0x600(%rbp)
   6048c:	jne    60358 <_IO_vfscanf+0x3e38>
   60492:	addl   $0x1,-0x690(%rbp)
   60499:	mov    -0x690(%rbp),%eax
   6049f:	cmp    %eax,-0x6b0(%rbp)
   604a5:	jge    60340 <_IO_vfscanf+0x3e20>
   604ab:	mov    -0x6c0(%rbp),%edi
   604b1:	test   %edi,%edi
   604b3:	je     60b21 <_IO_vfscanf+0x4601>
   604b9:	mov    -0x6a4(%rbp),%eax
   604bf:	mov    -0x620(%rbp),%r15
   604c6:	mov    $0x7fffffff,%r8d
   604cc:	test   %eax,%eax
   604ce:	cmovg  %eax,%r8d
   604d2:	movzbl (%r15),%eax
   604d6:	cmp    %eax,%r13d
   604d9:	jne    62a9f <_IO_vfscanf+0x657f>
   604df:	mov    %r8d,%ebx
   604e2:	jmp    6053d <_IO_vfscanf+0x401d>
   604e4:	nopl   0x0(%rax)
   604e8:	lea    0x1(%rax),%rcx
   604ec:	mov    %rcx,-0x450(%rbp)
   604f3:	mov    %r13b,(%rax)
   604f6:	add    $0x1,%r15
   604fa:	cmpb   $0x0,(%r15)
   604fe:	je     60852 <_IO_vfscanf+0x4332>
   60504:	test   %ebx,%ebx
   60506:	je     60808 <_IO_vfscanf+0x42e8>
   6050c:	mov    0x8(%r12),%rax
   60511:	cmp    0x10(%r12),%rax
   60516:	jae    606f8 <_IO_vfscanf+0x41d8>
   6051c:	lea    0x1(%rax),%rdx
   60520:	mov    %rdx,0x8(%r12)
   60525:	movzbl (%rax),%r13d
   60529:	movzbl (%r15),%eax
   6052d:	add    $0x1,%r14
   60531:	sub    $0x1,%ebx
   60534:	cmp    %r13d,%eax
   60537:	jne    609a2 <_IO_vfscanf+0x4482>
   6053d:	mov    -0x450(%rbp),%rax
   60544:	mov    -0x448(%rbp),%rcx
   6054b:	mov    %r13d,%edx
   6054e:	cmp    %rax,%rcx
   60551:	jne    604e8 <_IO_vfscanf+0x3fc8>
   60553:	test   %rcx,%rcx
   60556:	mov    %r13b,-0x628(%rbp)
   6055d:	je     61239 <_IO_vfscanf+0x4d19>
   60563:	sub    -0x440(%rbp),%rcx
   6056a:	mov    -0x6c8(%rbp),%rdi
   60571:	mov    %rcx,-0x600(%rbp)
   60578:	callq  8afb0 <__libc_scratch_buffer_grow_preserve>
   6057d:	test   %al,%al
   6057f:	movzbl -0x628(%rbp),%edx
   60586:	je     61229 <_IO_vfscanf+0x4d09>
   6058c:	mov    -0x440(%rbp),%rcx
   60593:	mov    %rcx,%rax
   60596:	add    -0x600(%rbp),%rcx
   6059d:	add    -0x438(%rbp),%rax
   605a4:	mov    %rax,-0x448(%rbp)
   605ab:	lea    0x1(%rcx),%rax
   605af:	mov    %rax,-0x450(%rbp)
   605b6:	mov    %r13b,(%rcx)
   605b9:	jmpq   604f6 <_IO_vfscanf+0x3fd6>
   605be:	xchg   %ax,%ax
   605c0:	cmp    %r15,%rbx
   605c3:	mov    %eax,%r13d
   605c6:	jae    6045d <_IO_vfscanf+0x3f3d>
   605cc:	movzbl %r13b,%esi
   605d0:	mov    %r12,%rdi
   605d3:	sub    $0x1,%r14
   605d7:	callq  7e5a0 <_IO_sputbackc>
   605dc:	jmpq   60411 <_IO_vfscanf+0x3ef1>
   605e1:	nopl   0x0(%rax)
   605e8:	mov    %r13d,%r8d
   605eb:	mov    %eax,%r13d
   605ee:	mov    %ecx,%eax
   605f0:	jmpq   603fa <_IO_vfscanf+0x3eda>
   605f5:	nopl   (%rax)
   605f8:	mov    %r13d,%r8d
   605fb:	mov    -0x6a4(%rbp),%eax
   60601:	test   %eax,%eax
   60603:	cmovle %eax,%r8d
   60607:	mov    -0x678(%rbp),%r13d
   6060e:	mov    -0x690(%rbp),%eax
   60614:	mov    -0x450(%rbp),%rbx
   6061b:	add    $0x30,%r13d
   6061f:	mov    %eax,-0x6b0(%rbp)
   60625:	mov    %eax,-0x698(%rbp)
   6062b:	mov    %r13d,%edx
   6062e:	cmp    %rbx,-0x448(%rbp)
   60635:	je     6079c <_IO_vfscanf+0x427c>
   6063b:	lea    0x1(%rbx),%rax
   6063f:	mov    %rax,-0x450(%rbp)
   60646:	mov    %dl,(%rbx)
   60648:	xor    %eax,%eax
   6064a:	test   %r8d,%r8d
   6064d:	setg   %al
   60650:	sub    %eax,%r8d
   60653:	cmp    $0xffffffff,%r13d
   60657:	mov    %r8d,-0x6a4(%rbp)
   6065e:	je     60787 <_IO_vfscanf+0x4267>
   60664:	mov    0x8(%r12),%rax
   60669:	cmp    0x10(%r12),%rax
   6066e:	jae    609aa <_IO_vfscanf+0x448a>
   60674:	lea    0x1(%rax),%rcx
   60678:	mov    %rcx,0x8(%r12)
   6067d:	movzbl (%rax),%r13d
   60681:	add    $0x1,%r14
   60685:	jmpq   60107 <_IO_vfscanf+0x3be7>
   6068a:	cmp    %rdx,%r15
   6068d:	mov    %r15,%rcx
   60690:	jbe    602f9 <_IO_vfscanf+0x3dd9>
   60696:	movzbl %r13b,%esi
   6069a:	mov    %r12,%rdi
   6069d:	mov    %rcx,-0x678(%rbp)
   606a4:	mov    %rdx,-0x600(%rbp)
   606ab:	sub    $0x1,%r14
   606af:	callq  7e5a0 <_IO_sputbackc>
   606b4:	mov    -0x678(%rbp),%rcx
   606bb:	mov    -0x600(%rbp),%rdx
   606c2:	jmpq   602a1 <_IO_vfscanf+0x3d81>
   606c7:	mov    %r15,%rcx
   606ca:	jmpq   6028a <_IO_vfscanf+0x3d6a>
   606cf:	mov    -0x630(%rbp),%rax
   606d6:	mov    (%rax,%rbx,8),%rdx
   606da:	jmpq   60173 <_IO_vfscanf+0x3c53>
   606df:	test   %dl,%dl
   606e1:	jne    6045d <_IO_vfscanf+0x3f3d>
   606e7:	mov    -0x688(%rbp),%r8d
   606ee:	jmpq   605fb <_IO_vfscanf+0x40db>
   606f3:	nopl   0x0(%rax,%rax,1)
   606f8:	mov    %r12,%rdi
   606fb:	callq  7d720 <__uflow>
   60700:	cmp    $0xffffffff,%eax
   60703:	mov    %eax,%r13d
   60706:	jne    60529 <_IO_vfscanf+0x4009>
   6070c:	mov    0x35f755(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   60713:	mov    %ebx,%r8d
   60716:	mov    %fs:(%rax),%eax
   60719:	mov    %eax,-0x5e4(%rbp)
   6071f:	mov    -0x450(%rbp),%rax
   60726:	test   %rax,%rax
   60729:	mov    %rax,%rbx
   6072c:	je     60865 <_IO_vfscanf+0x4345>
   60732:	cmpb   $0x0,(%r15)
   60736:	jne    639e7 <_IO_vfscanf+0x74c7>
   6073c:	mov    %r13d,%edx
   6073f:	mov    -0x6a4(%rbp),%edi
   60745:	lea    -0x1(%rax),%rbx
   60749:	mov    %rbx,-0x450(%rbp)
   60750:	test   %edi,%edi
   60752:	cmovle %edi,%r8d
   60756:	jmpq   6062e <_IO_vfscanf+0x410e>
   6075b:	test   %cl,%cl
   6075d:	jne    602f9 <_IO_vfscanf+0x3dd9>
   60763:	mov    -0x688(%rbp),%r8d
   6076a:	mov    -0x698(%rbp),%eax
   60770:	mov    %eax,-0x690(%rbp)
   60776:	mov    -0x6a4(%rbp),%eax
   6077c:	test   %eax,%eax
   6077e:	cmovle %eax,%r8d
   60782:	jmpq   60607 <_IO_vfscanf+0x40e7>
   60787:	mov    0x35f6da(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   6078e:	mov    -0x5e4(%rbp),%esi
   60794:	mov    %esi,%fs:(%rax)
   60797:	jmpq   60107 <_IO_vfscanf+0x3be7>
   6079c:	test   %rbx,%rbx
   6079f:	mov    %dl,-0x628(%rbp)
   607a5:	je     60648 <_IO_vfscanf+0x4128>
   607ab:	mov    -0x6c8(%rbp),%rdi
   607b2:	mov    %r8d,-0x600(%rbp)
   607b9:	sub    -0x440(%rbp),%rbx
   607c0:	callq  8afb0 <__libc_scratch_buffer_grow_preserve>
   607c5:	test   %al,%al
   607c7:	mov    -0x600(%rbp),%r8d
   607ce:	movzbl -0x628(%rbp),%edx
   607d5:	je     63e2e <_IO_vfscanf+0x790e>
   607db:	mov    -0x440(%rbp),%rax
   607e2:	mov    %rax,%rcx
   607e5:	add    -0x438(%rbp),%rcx
   607ec:	add    %rax,%rbx
   607ef:	lea    0x1(%rbx),%rax
   607f3:	mov    %rax,-0x450(%rbp)
   607fa:	mov    %rcx,-0x448(%rbp)
   60801:	mov    %dl,(%rbx)
   60803:	jmpq   60648 <_IO_vfscanf+0x4128>
   60808:	mov    -0x450(%rbp),%rbx
   6080f:	mov    %r15,%rcx
   60812:	mov    %r13d,%r10d
   60815:	mov    -0x6b8(%rbp),%r15
   6081c:	mov    %r12,%r13
   6081f:	mov    -0x6a4(%rbp),%r12d
   60826:	test   %rbx,%rbx
   60829:	jne    639fe <_IO_vfscanf+0x74de>
   6082f:	mov    %r13,%r15
   60832:	mov    0x35f62f(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   60839:	xor    %r13d,%r13d
   6083c:	movl   $0xffffffff,-0x5e8(%rbp)
   60846:	movl   $0xc,%fs:(%rax)
   6084d:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   60852:	mov    -0x450(%rbp),%rax
   60859:	mov    %ebx,%r8d
   6085c:	test   %rax,%rax
   6085f:	jne    6073f <_IO_vfscanf+0x421f>
   60865:	mov    %r12,%r15
   60868:	jmp    60832 <_IO_vfscanf+0x4312>
   6086a:	nopw   0x0(%rax,%rax,1)
   60870:	mov    -0x440(%rbp),%rdi
   60877:	mov    %ebx,%edx
   60879:	lea    -0x5c8(%rbp),%rsi
   60880:	and    $0x80,%edx
   60886:	mov    %r10d,-0x600(%rbp)
   6088d:	callq  3c1a0 <__strtof_internal>
   60892:	mov    %ebx,%edx
   60894:	mov    -0x600(%rbp),%r10d
   6089b:	and    $0x8,%edx
   6089e:	jne    5fa9c <_IO_vfscanf+0x357c>
   608a4:	mov    -0x440(%rbp),%rdx
   608ab:	mov    -0x5c8(%rbp),%rcx
   608b2:	cmp    %rdx,%rcx
   608b5:	je     6346f <_IO_vfscanf+0x6f4f>
   608bb:	mov    -0x638(%rbp),%eax
   608c1:	test   %eax,%eax
   608c3:	jne    61c50 <_IO_vfscanf+0x5730>
   608c9:	mov    -0x5a8(%rbp),%eax
   608cf:	cmp    $0x2f,%eax
   608d2:	ja     6382c <_IO_vfscanf+0x730c>
   608d8:	mov    %eax,%esi
   608da:	add    -0x598(%rbp),%rsi
   608e1:	add    $0x8,%eax
   608e4:	mov    %eax,-0x5a8(%rbp)
   608ea:	cmpb   $0x0,-0x6a0(%rbp)
   608f1:	mov    (%rsi),%rax
   608f4:	je     608fd <_IO_vfscanf+0x43dd>
   608f6:	xorps  0x130a83(%rip),%xmm0        # 191380 <othermask+0x40>
   608fd:	movss  %xmm0,(%rax)
   60901:	jmpq   5ebfe <_IO_vfscanf+0x26de>
   60906:	mov    -0x628(%rbp),%rdx
   6090d:	mov    -0x5e4(%rbp),%eax
   60913:	mov    %r13,%r15
   60916:	mov    %eax,%fs:(%rdx)
   60919:	mov    -0x5e8(%rbp),%r10d
   60920:	mov    $0x1,%r13d
   60926:	test   %r10d,%r10d
   60929:	jne    5c9b8 <_IO_vfscanf+0x498>
   6092f:	movl   $0xffffffff,-0x5e8(%rbp)
   60939:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   6093e:	mov    0x35f523(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   60945:	mov    -0x5e4(%rbp),%esi
   6094b:	mov    %r13,%r15
   6094e:	mov    %esi,%fs:(%rax)
   60951:	mov    -0x5e8(%rbp),%ebx
   60957:	mov    $0x1,%r13d
   6095d:	test   %ebx,%ebx
   6095f:	jne    5c9b8 <_IO_vfscanf+0x498>
   60965:	movl   $0xffffffff,-0x5e8(%rbp)
   6096f:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   60974:	lea    -0x2b(%r12),%eax
   60979:	and    $0xfffffffd,%eax
   6097c:	jne    5dcb9 <_IO_vfscanf+0x1799>
   60982:	cmp    -0x448(%rbp),%rbx
   60989:	je     63e3e <_IO_vfscanf+0x791e>
   6098f:	lea    0x1(%rbx),%rax
   60993:	mov    %rax,-0x450(%rbp)
   6099a:	mov    %r12b,(%rbx)
   6099d:	jmpq   5eaad <_IO_vfscanf+0x258d>
   609a2:	mov    %ebx,%r8d
   609a5:	jmpq   6071f <_IO_vfscanf+0x41ff>
   609aa:	mov    %r12,%rdi
   609ad:	callq  7d720 <__uflow>
   609b2:	cmp    $0xffffffff,%eax
   609b5:	mov    %eax,%r13d
   609b8:	jne    60681 <_IO_vfscanf+0x4161>
   609be:	mov    0x35f4a3(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   609c5:	mov    %fs:(%rax),%eax
   609c8:	mov    %eax,-0x5e4(%rbp)
   609ce:	jmpq   60107 <_IO_vfscanf+0x3be7>
   609d3:	mov    %r13,%rdi
   609d6:	callq  7d720 <__uflow>
   609db:	cmp    $0xffffffff,%eax
   609de:	mov    %eax,%r10d
   609e1:	jne    5d298 <_IO_vfscanf+0xd78>
   609e7:	mov    %r13,%r15
   609ea:	jmpq   5f319 <_IO_vfscanf+0x2df9>
   609ef:	sub    $0x120,%rsp
   609f6:	mov    $0x1,%ecx
   609fb:	lea    0xf(%rsp),%rdx
   60a00:	and    $0xfffffffffffffff0,%rdx
   60a04:	mov    %rdx,-0x660(%rbp)
   60a0b:	movq   $0x0,(%rdx)
   60a12:	mov    %rdi,0x8(%rdx)
   60a16:	mov    -0x660(%rbp),%rsi
   60a1d:	xor    %edx,%edx
   60a1f:	jmpq   5d069 <_IO_vfscanf+0xb49>
   60a24:	mov    %r13,%rdi
   60a27:	callq  7d720 <__uflow>
   60a2c:	cmp    $0xffffffff,%eax
   60a2f:	mov    %eax,%r10d
   60a32:	jne    5d0ae <_IO_vfscanf+0xb8e>
   60a38:	mov    %r13,%r15
   60a3b:	jmpq   5f2e1 <_IO_vfscanf+0x2dc1>
   60a40:	testl  $0x200,-0x5ec(%rbp)
   60a4a:	jne    614a8 <_IO_vfscanf+0x4f88>
   60a50:	mov    -0x638(%rbp),%edx
   60a56:	test   %edx,%edx
   60a58:	jne    61a60 <_IO_vfscanf+0x5540>
   60a5e:	mov    -0x5a8(%rbp),%ecx
   60a64:	cmp    $0x2f,%ecx
   60a67:	ja     63e76 <_IO_vfscanf+0x7956>
   60a6d:	mov    %ecx,%edx
   60a6f:	add    -0x598(%rbp),%rdx
   60a76:	add    $0x8,%ecx
   60a79:	mov    %ecx,-0x5a8(%rbp)
   60a7f:	mov    (%rdx),%rdx
   60a82:	mov    %eax,(%rdx)
   60a84:	jmpq   5da60 <_IO_vfscanf+0x1540>
   60a89:	mov    -0x638(%rbp),%edx
   60a8f:	test   %edx,%edx
   60a91:	jne    612a0 <_IO_vfscanf+0x4d80>
   60a97:	mov    -0x5a8(%rbp),%edx
   60a9d:	cmp    $0x2f,%edx
   60aa0:	ja     63aaa <_IO_vfscanf+0x758a>
   60aa6:	mov    %edx,%eax
   60aa8:	add    -0x598(%rbp),%rax
   60aaf:	add    $0x8,%edx
   60ab2:	mov    %edx,-0x5a8(%rbp)
   60ab8:	mov    (%rax),%rax
   60abb:	mov    %rax,-0x668(%rbp)
   60ac2:	cmpq   $0x0,-0x668(%rbp)
   60aca:	jne    5dfb6 <_IO_vfscanf+0x1a96>
   60ad0:	mov    %r13,%r15
   60ad3:	mov    $0x2,%r13d
   60ad9:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   60ade:	xchg   %ax,%ax
   60ae0:	mov    %r15,-0x658(%rbp)
   60ae7:	mov    -0x638(%rbp),%r15
   60aee:	mov    %ebx,%r10d
   60af1:	mov    %rsi,-0x668(%rbp)
   60af8:	mov    %rdx,%r14
   60afb:	mov    %r8d,%ebx
   60afe:	movzbl %r10b,%esi
   60b02:	mov    %r13,%rdi
   60b05:	mov    %r10d,-0x628(%rbp)
   60b0c:	sub    $0x1,%r14
   60b10:	callq  7e5a0 <_IO_sputbackc>
   60b15:	mov    -0x628(%rbp),%r10d
   60b1c:	jmpq   5ec94 <_IO_vfscanf+0x2774>
   60b21:	mov    %r13d,%r10d
   60b24:	mov    -0x6b8(%rbp),%r15
   60b2b:	mov    %r12,%r13
   60b2e:	mov    -0x450(%rbp),%rbx
   60b35:	mov    -0x6a4(%rbp),%r12d
   60b3c:	movl   $0xa,-0x600(%rbp)
   60b46:	jmpq   5d92e <_IO_vfscanf+0x140e>
   60b4b:	mov    0x35f316(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   60b52:	mov    -0x5e4(%rbp),%edi
   60b58:	mov    %r13,%r15
   60b5b:	mov    -0x600(%rbp),%r13d
   60b62:	mov    %edi,%fs:(%rax)
   60b65:	mov    -0x5e8(%rbp),%esi
   60b6b:	mov    $0xffffffff,%eax
   60b70:	mov    %eax,%edi
   60b72:	test   %esi,%esi
   60b74:	cmovne %esi,%edi
   60b77:	mov    %edi,-0x5e8(%rbp)
   60b7d:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   60b82:	mov    -0x638(%rbp),%ebx
   60b88:	test   %ebx,%ebx
   60b8a:	jne    615b0 <_IO_vfscanf+0x5090>
   60b90:	mov    -0x5a8(%rbp),%ecx
   60b96:	cmp    $0x2f,%ecx
   60b99:	ja     6302f <_IO_vfscanf+0x6b0f>
   60b9f:	mov    %ecx,%eax
   60ba1:	add    -0x598(%rbp),%rax
   60ba8:	add    $0x8,%ecx
   60bab:	mov    %ecx,-0x5a8(%rbp)
   60bb1:	mov    (%rax),%rax
   60bb4:	mov    %rax,-0x668(%rbp)
   60bbb:	cmpq   $0x0,-0x668(%rbp)
   60bc3:	je     633ee <_IO_vfscanf+0x6ece>
   60bc9:	movl   $0x0,-0x678(%rbp)
   60bd3:	jmpq   5d67d <_IO_vfscanf+0x115d>
   60bd8:	mov    -0x638(%rbp),%eax
   60bde:	test   %eax,%eax
   60be0:	jne    614f1 <_IO_vfscanf+0x4fd1>
   60be6:	mov    -0x5a8(%rbp),%edx
   60bec:	cmp    $0x2f,%edx
   60bef:	ja     635f6 <_IO_vfscanf+0x70d6>
   60bf5:	mov    %edx,%eax
   60bf7:	add    -0x598(%rbp),%rax
   60bfe:	add    $0x8,%edx
   60c01:	mov    %edx,-0x5a8(%rbp)
   60c07:	mov    (%rax),%rax
   60c0a:	mov    %rax,-0x668(%rbp)
   60c11:	cmpq   $0x0,-0x668(%rbp)
   60c19:	jne    5d499 <_IO_vfscanf+0xf79>
   60c1f:	mov    %r13,%r15
   60c22:	mov    $0x2,%r13d
   60c28:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   60c2d:	nopl   (%rax)
   60c30:	mov    -0x5ec(%rbp),%ebx
   60c36:	mov    -0x440(%rbp),%rdi
   60c3d:	lea    -0x5c8(%rbp),%rsi
   60c44:	mov    %r10d,-0x600(%rbp)
   60c4b:	mov    %ebx,%edx
   60c4d:	and    $0x80,%edx
   60c53:	callq  3c200 <__strtold_internal>
   60c58:	mov    %ebx,%edx
   60c5a:	mov    -0x600(%rbp),%r10d
   60c61:	and    $0x8,%edx
   60c64:	jne    5fa9a <_IO_vfscanf+0x357a>
   60c6a:	mov    -0x440(%rbp),%rdx
   60c71:	mov    -0x5c8(%rbp),%rcx
   60c78:	cmp    %rdx,%rcx
   60c7b:	je     6346d <_IO_vfscanf+0x6f4d>
   60c81:	mov    -0x638(%rbp),%eax
   60c87:	test   %eax,%eax
   60c89:	jne    61ca0 <_IO_vfscanf+0x5780>
   60c8f:	mov    -0x5a8(%rbp),%eax
   60c95:	cmp    $0x2f,%eax
   60c98:	ja     63843 <_IO_vfscanf+0x7323>
   60c9e:	mov    %eax,%esi
   60ca0:	add    -0x598(%rbp),%rsi
   60ca7:	add    $0x8,%eax
   60caa:	mov    %eax,-0x5a8(%rbp)
   60cb0:	cmpb   $0x0,-0x6a0(%rbp)
   60cb7:	mov    (%rsi),%rax
   60cba:	je     60cbe <_IO_vfscanf+0x479e>
   60cbc:	fchs   
   60cbe:	fstpt  (%rax)
   60cc0:	jmpq   5ebfe <_IO_vfscanf+0x26de>
   60cc5:	mov    -0x650(%rbp),%rsi
   60ccc:	mov    -0x630(%rbp),%rdi
   60cd3:	xor    %ebx,%ebx
   60cd5:	mov    -0x638(%rbp),%r8d
   60cdc:	mov    (%rsi),%rdx
   60cdf:	mov    %rdx,(%rdi)
   60ce2:	mov    0x8(%rsi),%rcx
   60ce6:	mov    %rcx,0x8(%rdi)
   60cea:	mov    0x10(%rsi),%rsi
   60cee:	mov    %rsi,0x10(%rdi)
   60cf2:	mov    %edx,%esi
   60cf4:	xor    %edi,%edi
   60cf6:	sub    $0x1,%r8d
   60cfa:	je     636df <_IO_vfscanf+0x71bf>
   60d00:	cmp    $0x2f,%esi
   60d03:	ja     636d1 <_IO_vfscanf+0x71b1>
   60d09:	add    $0x8,%esi
   60d0c:	mov    $0x1,%ebx
   60d11:	jmp    60cf6 <_IO_vfscanf+0x47d6>
   60d13:	nopl   0x0(%rax,%rax,1)
   60d18:	mov    0x35f149(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   60d1f:	mov    -0x5e4(%rbp),%esi
   60d25:	mov    %r13,%r15
   60d28:	mov    %esi,%fs:(%rax)
   60d2b:	mov    -0x5e8(%rbp),%esi
   60d31:	mov    $0x1,%r13d
   60d37:	test   %esi,%esi
   60d39:	jne    5c9b8 <_IO_vfscanf+0x498>
   60d3f:	movl   $0xffffffff,-0x5e8(%rbp)
   60d49:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   60d4e:	lea    -0x1(%r12),%ecx
   60d53:	movslq %r12d,%r12
   60d56:	mov    %rax,%r14
   60d59:	lea    (%r12,%rax,1),%rax
   60d5d:	mov    -0x608(%rbp),%r12
   60d64:	mov    -0x658(%rbp),%rbx
   60d6b:	mov    %r15,-0x600(%rbp)
   60d72:	mov    %r14,%r15
   60d75:	mov    %ecx,%r14d
   60d78:	mov    %rax,-0x628(%rbp)
   60d7f:	mov    -0x668(%rbp),%rax
   60d86:	mov    (%r12),%rdi
   60d8a:	lea    (%rdi,%rbx,1),%rsi
   60d8e:	cmp    %rsi,%rax
   60d91:	je     60dd5 <_IO_vfscanf+0x48b5>
   60d93:	test   %r14d,%r14d
   60d96:	lea    0x1(%rax),%rsi
   60d9a:	mov    %r10b,(%rax)
   60d9d:	jle    61600 <_IO_vfscanf+0x50e0>
   60da3:	mov    0x8(%r13),%rax
   60da7:	cmp    0x10(%r13),%rax
   60dab:	jae    60e36 <_IO_vfscanf+0x4916>
   60db1:	lea    0x1(%rax),%rcx
   60db5:	mov    %rcx,0x8(%r13)
   60db9:	movzbl (%rax),%r10d
   60dbd:	mov    (%r12),%rdi
   60dc1:	mov    %rsi,%rax
   60dc4:	add    $0x1,%r15
   60dc8:	sub    $0x1,%r14d
   60dcc:	lea    (%rdi,%rbx,1),%rsi
   60dd0:	cmp    %rsi,%rax
   60dd3:	jne    60d93 <_IO_vfscanf+0x4873>
   60dd5:	mov    -0x628(%rbp),%rax
   60ddc:	movslq %r14d,%r8
   60ddf:	mov    %r10d,-0x668(%rbp)
   60de6:	mov    %rbx,-0x658(%rbp)
   60ded:	sub    %r15,%rax
   60df0:	cmp    %rax,%rbx
   60df3:	cmovl  %rbx,%r8
   60df7:	add    %rbx,%r8
   60dfa:	mov    %r8,%rsi
   60dfd:	mov    %r8,-0x638(%rbp)
   60e04:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   60e09:	test   %rax,%rax
   60e0c:	mov    -0x638(%rbp),%r8
   60e13:	mov    -0x658(%rbp),%rcx
   60e1a:	mov    -0x668(%rbp),%r10d
   60e21:	je     63046 <_IO_vfscanf+0x6b26>
   60e27:	mov    %rax,(%r12)
   60e2b:	add    %rbx,%rax
   60e2e:	mov    %r8,%rbx
   60e31:	jmpq   60d93 <_IO_vfscanf+0x4873>
   60e36:	mov    %r13,%rdi
   60e39:	mov    %rsi,-0x638(%rbp)
   60e40:	callq  7d720 <__uflow>
   60e45:	cmp    $0xffffffff,%eax
   60e48:	mov    %eax,%r10d
   60e4b:	mov    -0x638(%rbp),%rsi
   60e52:	jne    60dbd <_IO_vfscanf+0x489d>
   60e58:	mov    %rbx,-0x658(%rbp)
   60e5f:	mov    %r15,%r14
   60e62:	mov    %rsi,%rbx
   60e65:	mov    -0x600(%rbp),%r15
   60e6c:	jmpq   5fe64 <_IO_vfscanf+0x3944>
   60e71:	mov    -0x638(%rbp),%eax
   60e77:	test   %eax,%eax
   60e79:	jne    61728 <_IO_vfscanf+0x5208>
   60e7f:	mov    -0x5a8(%rbp),%ecx
   60e85:	cmp    $0x2f,%ecx
   60e88:	ja     63eeb <_IO_vfscanf+0x79cb>
   60e8e:	mov    %ecx,%eax
   60e90:	add    -0x598(%rbp),%rax
   60e97:	add    $0x8,%ecx
   60e9a:	mov    %ecx,-0x5a8(%rbp)
   60ea0:	mov    (%rax),%rax
   60ea3:	mov    %rax,-0x640(%rbp)
   60eaa:	cmpq   $0x0,-0x640(%rbp)
   60eb2:	jne    60bc9 <_IO_vfscanf+0x46a9>
   60eb8:	mov    %r13,%r15
   60ebb:	mov    $0x2,%r13d
   60ec1:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   60ec6:	nopw   %cs:0x0(%rax,%rax,1)
   60ed0:	mov    -0x6b0(%rbp),%rdi
   60ed7:	sub    -0x440(%rbp),%rbx
   60ede:	callq  8afb0 <__libc_scratch_buffer_grow_preserve>
   60ee3:	test   %al,%al
   60ee5:	je     62733 <_IO_vfscanf+0x6213>
   60eeb:	mov    -0x440(%rbp),%rax
   60ef2:	mov    %rax,%rcx
   60ef5:	add    -0x438(%rbp),%rcx
   60efc:	add    %rax,%rbx
   60eff:	lea    0x1(%rbx),%rax
   60f03:	mov    %rax,-0x450(%rbp)
   60f0a:	mov    %rcx,-0x448(%rbp)
   60f11:	mov    %r12b,(%rbx)
   60f14:	jmpq   5dc49 <_IO_vfscanf+0x1729>
   60f19:	mov    -0x650(%rbp),%rsi
   60f20:	mov    -0x630(%rbp),%rdi
   60f27:	mov    -0x638(%rbp),%r8d
   60f2e:	mov    (%rsi),%rax
   60f31:	mov    %rax,(%rdi)
   60f34:	mov    0x8(%rsi),%rdx
   60f38:	mov    %rdx,0x8(%rdi)
   60f3c:	mov    0x10(%rsi),%rcx
   60f40:	xor    %esi,%esi
   60f42:	mov    %rcx,0x10(%rdi)
   60f46:	mov    %eax,%ecx
   60f48:	xor    %edi,%edi
   60f4a:	sub    $0x1,%r8d
   60f4e:	je     62064 <_IO_vfscanf+0x5b44>
   60f54:	cmp    $0x2f,%ecx
   60f57:	ja     62056 <_IO_vfscanf+0x5b36>
   60f5d:	add    $0x8,%ecx
   60f60:	mov    $0x1,%edi
   60f65:	jmp    60f4a <_IO_vfscanf+0x4a2a>
   60f67:	nopw   0x0(%rax,%rax,1)
   60f70:	mov    %esi,%eax
   60f72:	and    $0x200,%eax
   60f77:	mov    %eax,-0x600(%rbp)
   60f7d:	jne    61464 <_IO_vfscanf+0x4f44>
   60f83:	mov    -0x638(%rbp),%eax
   60f89:	test   %eax,%eax
   60f8b:	jne    61a10 <_IO_vfscanf+0x54f0>
   60f91:	mov    -0x5a8(%rbp),%edx
   60f97:	cmp    $0x2f,%edx
   60f9a:	ja     63d84 <_IO_vfscanf+0x7864>
   60fa0:	mov    %edx,%eax
   60fa2:	add    -0x598(%rbp),%rax
   60fa9:	add    $0x8,%edx
   60fac:	mov    %edx,-0x5a8(%rbp)
   60fb2:	mov    (%rax),%rax
   60fb5:	mov    %r14d,(%rax)
   60fb8:	jmpq   5c832 <_IO_vfscanf+0x312>
   60fbd:	lea    (%r15,%r15,1),%r11
   60fc1:	mov    %rdx,-0x690(%rbp)
   60fc8:	mov    %ecx,-0x688(%rbp)
   60fce:	mov    %r8d,-0x678(%rbp)
   60fd5:	mov    %r11,%rsi
   60fd8:	mov    %r11,-0x668(%rbp)
   60fdf:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   60fe4:	test   %rax,%rax
   60fe7:	mov    -0x668(%rbp),%r11
   60fee:	mov    -0x678(%rbp),%r8d
   60ff5:	mov    -0x688(%rbp),%ecx
   60ffb:	mov    -0x690(%rbp),%rdx
   61002:	je     621a1 <_IO_vfscanf+0x5c81>
   61008:	mov    -0x608(%rbp),%rsi
   6100f:	mov    %rax,(%rsi)
   61012:	lea    (%rax,%r15,1),%rsi
   61016:	mov    %r11,%r15
   61019:	jmpq   5e04b <_IO_vfscanf+0x1b2b>
   6101e:	sub    $0x120,%rsp
   61025:	mov    $0x1,%ecx
   6102a:	lea    0xf(%rsp),%rdx
   6102f:	and    $0xfffffffffffffff0,%rdx
   61033:	mov    %rdx,-0x660(%rbp)
   6103a:	movq   $0x0,(%rdx)
   61041:	mov    %rdi,0x8(%rdx)
   61045:	mov    -0x660(%rbp),%rsi
   6104c:	xor    %edx,%edx
   6104e:	jmpq   5d25e <_IO_vfscanf+0xd3e>
   61053:	testl  $0x200,-0x5ec(%rbp)
   6105d:	jne    616c8 <_IO_vfscanf+0x51a8>
   61063:	mov    -0x638(%rbp),%r9d
   6106a:	test   %r9d,%r9d
   6106d:	je     60a5e <_IO_vfscanf+0x453e>
   61073:	mov    -0x650(%rbp),%rsi
   6107a:	mov    -0x630(%rbp),%rdi
   61081:	xor    %ebx,%ebx
   61083:	mov    (%rsi),%rdx
   61086:	mov    %rdx,(%rdi)
   61089:	mov    0x8(%rsi),%rcx
   6108d:	mov    %rcx,0x8(%rdi)
   61091:	mov    0x10(%rsi),%rsi
   61095:	mov    %rsi,0x10(%rdi)
   61099:	mov    %edx,%esi
   6109b:	xor    %edi,%edi
   6109d:	subl   $0x1,-0x638(%rbp)
   610a4:	je     63eb2 <_IO_vfscanf+0x7992>
   610aa:	cmp    $0x2f,%esi
   610ad:	ja     62177 <_IO_vfscanf+0x5c57>
   610b3:	add    $0x8,%esi
   610b6:	mov    $0x1,%ebx
   610bb:	jmp    6109d <_IO_vfscanf+0x4b7d>
   610bd:	nopl   (%rax)
   610c0:	mov    %r13,%r15
   610c3:	movl   $0xffffffff,-0x5e8(%rbp)
   610cd:	xor    %r13d,%r13d
   610d0:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   610d5:	mov    %esi,%r12d
   610d8:	jmpq   5dd70 <_IO_vfscanf+0x1850>
   610dd:	mov    -0x650(%rbp),%rsi
   610e4:	mov    -0x630(%rbp),%rdi
   610eb:	xor    %ebx,%ebx
   610ed:	mov    (%rsi),%rax
   610f0:	mov    %rax,(%rdi)
   610f3:	mov    0x8(%rsi),%rcx
   610f7:	mov    %rcx,0x8(%rdi)
   610fb:	mov    0x10(%rsi),%rsi
   610ff:	mov    %rsi,0x10(%rdi)
   61103:	mov    %eax,%esi
   61105:	xor    %edi,%edi
   61107:	subl   $0x1,-0x638(%rbp)
   6110e:	je     63ddf <_IO_vfscanf+0x78bf>
   61114:	cmp    $0x2f,%esi
   61117:	ja     63dd1 <_IO_vfscanf+0x78b1>
   6111d:	add    $0x8,%esi
   61120:	mov    $0x1,%edi
   61125:	jmp    61107 <_IO_vfscanf+0x4be7>
   61127:	nopw   0x0(%rax,%rax,1)
   61130:	mov    %r12d,%r10d
   61133:	mov    %r15d,%r12d
   61136:	mov    -0x698(%rbp),%r15
   6113d:	jmpq   5eadd <_IO_vfscanf+0x25bd>
   61142:	mov    -0x688(%rbp),%rax
   61149:	sub    -0x638(%rbp),%rax
   61150:	mov    -0x658(%rbp),%rsi
   61157:	movslq -0x628(%rbp),%r15
   6115e:	mov    %rdx,-0x640(%rbp)
   61165:	cmp    %rax,%rsi
   61168:	cmovle %rsi,%r15
   6116c:	add    %rsi,%r15
   6116f:	lea    0x0(,%r15,4),%rsi
   61177:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   6117c:	test   %rax,%rax
   6117f:	mov    -0x640(%rbp),%rdx
   61186:	je     62fd5 <_IO_vfscanf+0x6ab5>
   6118c:	mov    -0x608(%rbp),%rdi
   61193:	mov    %r15,-0x658(%rbp)
   6119a:	mov    %rax,(%rdi)
   6119d:	add    %rdx,%rax
   611a0:	mov    %rax,-0x640(%rbp)
   611a7:	jmpq   5d334 <_IO_vfscanf+0xe14>
   611ac:	mov    -0x650(%rbp),%rsi
   611b3:	mov    -0x630(%rbp),%rdi
   611ba:	xor    %ebx,%ebx
   611bc:	mov    (%rsi),%rax
   611bf:	mov    %rax,(%rdi)
   611c2:	mov    0x8(%rsi),%rcx
   611c6:	mov    %rcx,0x8(%rdi)
   611ca:	mov    0x10(%rsi),%rsi
   611ce:	mov    %rsi,0x10(%rdi)
   611d2:	mov    %eax,%esi
   611d4:	xor    %edi,%edi
   611d6:	subl   $0x1,-0x638(%rbp)
   611dd:	je     6357c <_IO_vfscanf+0x705c>
   611e3:	cmp    $0x2f,%esi
   611e6:	ja     6356e <_IO_vfscanf+0x704e>
   611ec:	add    $0x8,%esi
   611ef:	mov    $0x1,%edi
   611f4:	jmp    611d6 <_IO_vfscanf+0x4cb6>
   611f6:	nopw   %cs:0x0(%rax,%rax,1)
   61200:	mov    -0x5ec(%rbp),%r12d
   61207:	mov    %r13,%r15
   6120a:	mov    -0x600(%rbp),%r13d
   61211:	and    $0x2000,%r12d
   61218:	jne    63e67 <_IO_vfscanf+0x7947>
   6121e:	mov    $0x2,%r13d
   61224:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   61229:	pxor   %xmm0,%xmm0
   6122d:	movaps %xmm0,-0x450(%rbp)
   61234:	jmpq   604f6 <_IO_vfscanf+0x3fd6>
   61239:	add    $0x1,%r15
   6123d:	cmpb   $0x0,(%r15)
   61241:	jne    60504 <_IO_vfscanf+0x3fe4>
   61247:	jmpq   60865 <_IO_vfscanf+0x4345>
   6124c:	nopl   0x0(%rax)
   61250:	mov    -0x650(%rbp),%rsi
   61257:	mov    -0x630(%rbp),%rdi
   6125e:	mov    (%rsi),%rax
   61261:	mov    %rax,(%rdi)
   61264:	mov    0x8(%rsi),%rdx
   61268:	mov    %rdx,0x8(%rdi)
   6126c:	mov    0x10(%rsi),%rcx
   61270:	xor    %esi,%esi
   61272:	mov    %rcx,0x10(%rdi)
   61276:	mov    %eax,%ecx
   61278:	xor    %edi,%edi
   6127a:	subl   $0x1,-0x638(%rbp)
   61281:	je     63c18 <_IO_vfscanf+0x76f8>
   61287:	cmp    $0x2f,%ecx
   6128a:	ja     63c0a <_IO_vfscanf+0x76ea>
   61290:	add    $0x8,%ecx
   61293:	mov    $0x1,%esi
   61298:	jmp    6127a <_IO_vfscanf+0x4d5a>
   6129a:	nopw   0x0(%rax,%rax,1)
   612a0:	mov    -0x650(%rbp),%rsi
   612a7:	mov    -0x630(%rbp),%rdi
   612ae:	mov    (%rsi),%rax
   612b1:	mov    %rax,(%rdi)
   612b4:	mov    0x8(%rsi),%rdx
   612b8:	mov    %rdx,0x8(%rdi)
   612bc:	mov    0x10(%rsi),%rcx
   612c0:	xor    %esi,%esi
   612c2:	mov    %rcx,0x10(%rdi)
   612c6:	mov    %eax,%ecx
   612c8:	xor    %edi,%edi
   612ca:	subl   $0x1,-0x638(%rbp)
   612d1:	je     63ba3 <_IO_vfscanf+0x7683>
   612d7:	cmp    $0x2f,%ecx
   612da:	ja     63b95 <_IO_vfscanf+0x7675>
   612e0:	add    $0x8,%ecx
   612e3:	mov    $0x1,%esi
   612e8:	jmp    612ca <_IO_vfscanf+0x4daa>
   612ea:	nopw   0x0(%rax,%rax,1)
   612f0:	mov    %r13,-0x668(%rbp)
   612f7:	mov    -0x688(%rbp),%r15
   612fe:	mov    %rbx,%r13
   61301:	mov    %r14,%rbx
   61304:	mov    -0x690(%rbp),%r14
   6130b:	mov    %r12d,%r10d
   6130e:	movzbl %r10b,%esi
   61312:	mov    %r13,%rdi
   61315:	mov    %r10d,-0x628(%rbp)
   6131c:	sub    $0x1,%rbx
   61320:	callq  7e5a0 <_IO_sputbackc>
   61325:	mov    -0x628(%rbp),%r10d
   6132c:	jmpq   5f4bb <_IO_vfscanf+0x2f9b>
   61331:	mov    -0x650(%rbp),%rsi
   61338:	mov    -0x630(%rbp),%rdi
   6133f:	mov    (%rsi),%rax
   61342:	mov    %rax,(%rdi)
   61345:	mov    0x8(%rsi),%rdx
   61349:	mov    %rdx,0x8(%rdi)
   6134d:	mov    0x10(%rsi),%rcx
   61351:	xor    %esi,%esi
   61353:	mov    %rcx,0x10(%rdi)
   61357:	mov    %eax,%ecx
   61359:	xor    %edi,%edi
   6135b:	subl   $0x1,-0x638(%rbp)
   61362:	je     6334e <_IO_vfscanf+0x6e2e>
   61368:	cmp    $0x2f,%ecx
   6136b:	ja     63340 <_IO_vfscanf+0x6e20>
   61371:	add    $0x8,%ecx
   61374:	mov    $0x1,%edi
   61379:	jmp    6135b <_IO_vfscanf+0x4e3b>
   6137b:	nopl   0x0(%rax,%rax,1)
   61380:	mov    -0x650(%rbp),%rsi
   61387:	mov    -0x630(%rbp),%rdi
   6138e:	xor    %ebx,%ebx
   61390:	mov    (%rsi),%rdx
   61393:	mov    %rdx,(%rdi)
   61396:	mov    0x8(%rsi),%rcx
   6139a:	mov    %rcx,0x8(%rdi)
   6139e:	mov    0x10(%rsi),%rsi
   613a2:	mov    %rsi,0x10(%rdi)
   613a6:	mov    %edx,%esi
   613a8:	xor    %edi,%edi
   613aa:	subl   $0x1,-0x638(%rbp)
   613b1:	je     637ac <_IO_vfscanf+0x728c>
   613b7:	cmp    $0x2f,%esi
   613ba:	ja     635d4 <_IO_vfscanf+0x70b4>
   613c0:	add    $0x8,%esi
   613c3:	mov    $0x1,%ebx
   613c8:	jmp    613aa <_IO_vfscanf+0x4e8a>
   613ca:	nopw   0x0(%rax,%rax,1)
   613d0:	mov    %r12,%r15
   613d3:	mov    %eax,%r10d
   613d6:	jmpq   5febc <_IO_vfscanf+0x399c>
   613db:	mov    %r13,%rdi
   613de:	callq  7d720 <__uflow>
   613e3:	cmp    $0xffffffff,%eax
   613e6:	mov    %eax,%r12d
   613e9:	jne    5eda1 <_IO_vfscanf+0x2881>
   613ef:	mov    %eax,%r10d
   613f2:	mov    0x35ea6f(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   613f9:	mov    -0x638(%rbp),%r15
   61400:	mov    %fs:(%rax),%eax
   61403:	mov    %eax,-0x5e4(%rbp)
   61409:	jmpq   5ede6 <_IO_vfscanf+0x28c6>
   6140e:	mov    %r13,%rdi
   61411:	callq  7d720 <__uflow>
   61416:	cmp    $0xffffffff,%eax
   61419:	mov    %eax,%r10d
   6141c:	jne    5fe08 <_IO_vfscanf+0x38e8>
   61422:	mov    0x35ea3f(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   61429:	mov    %fs:(%rax),%eax
   6142c:	mov    %eax,-0x5e4(%rbp)
   61432:	mov    -0x450(%rbp),%rax
   61439:	mov    %rbx,%r14
   6143c:	jmpq   5eb27 <_IO_vfscanf+0x2607>
   61441:	mov    %r15,-0x658(%rbp)
   61448:	mov    %ebx,%r10d
   6144b:	mov    %rsi,-0x668(%rbp)
   61452:	mov    -0x638(%rbp),%r15
   61459:	mov    %rdx,%r14
   6145c:	mov    %r8d,%ebx
   6145f:	jmpq   5ec94 <_IO_vfscanf+0x2774>
   61464:	mov    -0x638(%rbp),%eax
   6146a:	test   %eax,%eax
   6146c:	jne    61c01 <_IO_vfscanf+0x56e1>
   61472:	mov    -0x5a8(%rbp),%edx
   61478:	cmp    $0x2f,%edx
   6147b:	ja     6367b <_IO_vfscanf+0x715b>
   61481:	mov    %edx,%eax
   61483:	add    -0x598(%rbp),%rax
   6148a:	add    $0x8,%edx
   6148d:	mov    %edx,-0x5a8(%rbp)
   61493:	mov    (%rax),%rax
   61496:	mov    %r14b,(%rax)
   61499:	movl   $0x0,-0x600(%rbp)
   614a3:	jmpq   5c832 <_IO_vfscanf+0x312>
   614a8:	mov    -0x638(%rbp),%r12d
   614af:	test   %r12d,%r12d
   614b2:	jne    61f5f <_IO_vfscanf+0x5a3f>
   614b8:	mov    -0x5a8(%rbp),%ecx
   614be:	cmp    $0x2f,%ecx
   614c1:	ja     622ab <_IO_vfscanf+0x5d8b>
   614c7:	mov    %ecx,%edx
   614c9:	add    -0x598(%rbp),%rdx
   614d0:	add    $0x8,%ecx
   614d3:	mov    %ecx,-0x5a8(%rbp)
   614d9:	mov    (%rdx),%rdx
   614dc:	mov    %al,(%rdx)
   614de:	jmpq   5da60 <_IO_vfscanf+0x1540>
   614e3:	mov    %r13,%r15
   614e6:	mov    $0x2,%r13d
   614ec:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   614f1:	mov    -0x650(%rbp),%rsi
   614f8:	mov    -0x630(%rbp),%rdi
   614ff:	mov    (%rsi),%rax
   61502:	mov    %rax,(%rdi)
   61505:	mov    0x8(%rsi),%rdx
   61509:	mov    %rdx,0x8(%rdi)
   6150d:	mov    0x10(%rsi),%rcx
   61511:	xor    %esi,%esi
   61513:	mov    %rcx,0x10(%rdi)
   61517:	mov    %eax,%ecx
   61519:	xor    %edi,%edi
   6151b:	subl   $0x1,-0x638(%rbp)
   61522:	je     620bc <_IO_vfscanf+0x5b9c>
   61528:	cmp    $0x2f,%ecx
   6152b:	ja     620ae <_IO_vfscanf+0x5b8e>
   61531:	add    $0x8,%ecx
   61534:	mov    $0x1,%edi
   61539:	jmp    6151b <_IO_vfscanf+0x4ffb>
   6153b:	nopl   0x0(%rax,%rax,1)
   61540:	mov    %r13,%rdi
   61543:	callq  7d720 <__uflow>
   61548:	cmp    $0xffffffff,%eax
   6154b:	mov    %eax,%r10d
   6154e:	jne    5e0b7 <_IO_vfscanf+0x1b97>
   61554:	mov    %r13,%r15
   61557:	jmpq   5e0ee <_IO_vfscanf+0x1bce>
   6155c:	mov    -0x650(%rbp),%rsi
   61563:	mov    -0x630(%rbp),%rdi
   6156a:	mov    (%rsi),%rax
   6156d:	mov    %rax,(%rdi)
   61570:	mov    0x8(%rsi),%rdx
   61574:	mov    %rdx,0x8(%rdi)
   61578:	mov    0x10(%rsi),%rcx
   6157c:	xor    %esi,%esi
   6157e:	mov    %rcx,0x10(%rdi)
   61582:	mov    %eax,%ecx
   61584:	xor    %edi,%edi
   61586:	subl   $0x1,-0x638(%rbp)
   6158d:	je     633af <_IO_vfscanf+0x6e8f>
   61593:	cmp    $0x2f,%ecx
   61596:	ja     633a1 <_IO_vfscanf+0x6e81>
   6159c:	add    $0x8,%ecx
   6159f:	mov    $0x1,%edi
   615a4:	jmp    61586 <_IO_vfscanf+0x5066>
   615a6:	nopw   %cs:0x0(%rax,%rax,1)
   615b0:	mov    -0x650(%rbp),%rsi
   615b7:	mov    -0x630(%rbp),%rdi
   615be:	xor    %ebx,%ebx
   615c0:	mov    (%rsi),%rax
   615c3:	mov    %rax,(%rdi)
   615c6:	mov    0x8(%rsi),%rcx
   615ca:	mov    %rcx,0x8(%rdi)
   615ce:	mov    0x10(%rsi),%rsi
   615d2:	mov    %rsi,0x10(%rdi)
   615d6:	mov    %eax,%esi
   615d8:	xor    %edi,%edi
   615da:	subl   $0x1,-0x638(%rbp)
   615e1:	je     631ba <_IO_vfscanf+0x6c9a>
   615e7:	cmp    $0x2f,%esi
   615ea:	ja     631ac <_IO_vfscanf+0x6c8c>
   615f0:	add    $0x8,%esi
   615f3:	mov    $0x1,%edi
   615f8:	jmp    615da <_IO_vfscanf+0x50ba>
   615fa:	nopw   0x0(%rax,%rax,1)
   61600:	mov    %rbx,-0x658(%rbp)
   61607:	mov    %r15,%r14
   6160a:	mov    %rsi,%rbx
   6160d:	mov    -0x600(%rbp),%r15
   61614:	jmpq   5fe86 <_IO_vfscanf+0x3966>
   61619:	mov    -0x610(%rbp),%rdi
   61620:	mov    $0x30,%esi
   61625:	mov    %r10d,-0x628(%rbp)
   6162c:	callq  5c4c0 <char_buffer_add_slow>
   61631:	mov    -0x628(%rbp),%r10d
   61638:	jmpq   5d97f <_IO_vfscanf+0x145f>
   6163d:	mov    %r13,%rdi
   61640:	callq  7d720 <__uflow>
   61645:	cmp    $0xffffffff,%eax
   61648:	mov    %eax,%r10d
   6164b:	jne    5f680 <_IO_vfscanf+0x3160>
   61651:	mov    %r13,%r15
   61654:	mov    $0x2,%r13d
   6165a:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   6165f:	mov    %eax,%r10d
   61662:	jmpq   5c832 <_IO_vfscanf+0x312>
   61667:	mov    %r13,%rdi
   6166a:	callq  7d720 <__uflow>
   6166f:	cmp    $0xffffffff,%eax
   61672:	mov    %eax,%r10d
   61675:	jne    621fd <_IO_vfscanf+0x5cdd>
   6167b:	mov    %r13,%r15
   6167e:	jmpq   5e13d <_IO_vfscanf+0x1c1d>
   61683:	mov    -0x5ec(%rbp),%r12d
   6168a:	mov    %r13,%r15
   6168d:	mov    -0x600(%rbp),%r13d
   61694:	and    $0x2000,%r12d
   6169b:	jne    63214 <_IO_vfscanf+0x6cf4>
   616a1:	mov    $0x2,%r13d
   616a7:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   616ac:	mov    0x35e7b5(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   616b3:	mov    %rsi,%r15
   616b6:	mov    $0x4,%r13d
   616bc:	movl   $0x54,%fs:(%rax)
   616c3:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   616c8:	mov    -0x638(%rbp),%r8d
   616cf:	test   %r8d,%r8d
   616d2:	je     614b8 <_IO_vfscanf+0x4f98>
   616d8:	mov    -0x650(%rbp),%rsi
   616df:	mov    -0x630(%rbp),%rdi
   616e6:	xor    %ebx,%ebx
   616e8:	mov    (%rsi),%rdx
   616eb:	mov    %rdx,(%rdi)
   616ee:	mov    0x8(%rsi),%rcx
   616f2:	mov    %rcx,0x8(%rdi)
   616f6:	mov    0x10(%rsi),%rsi
   616fa:	mov    %rsi,0x10(%rdi)
   616fe:	mov    %edx,%esi
   61700:	xor    %edi,%edi
   61702:	subl   $0x1,-0x638(%rbp)
   61709:	je     632c5 <_IO_vfscanf+0x6da5>
   6170f:	cmp    $0x2f,%esi
   61712:	ja     63277 <_IO_vfscanf+0x6d57>
   61718:	add    $0x8,%esi
   6171b:	mov    $0x1,%ebx
   61720:	jmp    61702 <_IO_vfscanf+0x51e2>
   61722:	nopw   0x0(%rax,%rax,1)
   61728:	mov    -0x650(%rbp),%rsi
   6172f:	mov    -0x630(%rbp),%rdi
   61736:	xor    %ebx,%ebx
   61738:	mov    (%rsi),%rax
   6173b:	mov    %rax,(%rdi)
   6173e:	mov    0x8(%rsi),%rcx
   61742:	mov    %rcx,0x8(%rdi)
   61746:	mov    0x10(%rsi),%rsi
   6174a:	mov    %rsi,0x10(%rdi)
   6174e:	mov    %eax,%esi
   61750:	xor    %edi,%edi
   61752:	subl   $0x1,-0x638(%rbp)
   61759:	je     634c4 <_IO_vfscanf+0x6fa4>
   6175f:	cmp    $0x2f,%esi
   61762:	ja     634b6 <_IO_vfscanf+0x6f96>
   61768:	add    $0x8,%esi
   6176b:	mov    $0x1,%edi
   61770:	jmp    61752 <_IO_vfscanf+0x5232>
   61772:	nopw   0x0(%rax,%rax,1)
   61778:	mov    0x35e6e9(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   6177f:	mov    %rdi,%r15
   61782:	mov    $0x4,%r13d
   61788:	movl   $0x54,%fs:(%rax)
   6178f:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   61794:	mov    -0x5ec(%rbp),%r12d
   6179b:	mov    %r13,%r15
   6179e:	and    $0x2000,%r12d
   617a5:	jne    61806 <_IO_vfscanf+0x52e6>
   617a7:	mov    -0x608(%rbp),%rax
   617ae:	mov    -0x658(%rbp),%rsi
   617b5:	mov    $0x2,%r13d
   617bb:	addl   $0x1,-0x5e8(%rbp)
   617c2:	movq   $0x0,-0x608(%rbp)
   617cd:	mov    (%rax),%rax
   617d0:	movb   $0x0,-0x1(%rax,%rsi,1)
   617d5:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   617da:	pxor   %xmm0,%xmm0
   617de:	movaps %xmm0,-0x450(%rbp)
   617e5:	jmpq   5dda6 <_IO_vfscanf+0x1886>
   617ea:	mov    %r13,%rdi
   617ed:	callq  7d720 <__uflow>
   617f2:	cmp    $0xffffffff,%eax
   617f5:	mov    %eax,%r10d
   617f8:	jne    5d4bd <_IO_vfscanf+0xf9d>
   617fe:	mov    %r13,%r15
   61801:	jmpq   60951 <_IO_vfscanf+0x4431>
   61806:	xor    %r13d,%r13d
   61809:	movl   $0xffffffff,-0x5e8(%rbp)
   61813:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   61818:	sub    $0x120,%rsp
   6181f:	mov    $0x1,%ecx
   61824:	lea    0xf(%rsp),%rdx
   61829:	and    $0xfffffffffffffff0,%rdx
   6182d:	mov    %rdx,-0x660(%rbp)
   61834:	movq   $0x0,(%rdx)
   6183b:	mov    %rdi,0x8(%rdx)
   6183f:	mov    -0x660(%rbp),%rsi
   61846:	xor    %edx,%edx
   61848:	jmpq   5df95 <_IO_vfscanf+0x1a75>
   6184d:	mov    -0x5ec(%rbp),%r12d
   61854:	mov    %r13,%r15
   61857:	mov    $0xffffffff,%eax
   6185c:	and    $0x2000,%r12d
   61863:	cmp    $0x1,%r12d
   61867:	sbb    %r13d,%r13d
   6186a:	and    $0x2,%r13d
   6186e:	test   %r12d,%r12d
   61871:	cmove  -0x5e8(%rbp),%eax
   61878:	mov    %eax,-0x5e8(%rbp)
   6187e:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   61883:	sub    $0x120,%rsp
   6188a:	mov    -0x660(%rbp),%rsi
   61891:	lea    0xf(%rsp),%rcx
   61896:	and    $0xfffffffffffffff0,%rcx
   6189a:	mov    %rsi,0x8(%rcx)
   6189e:	mov    %rcx,-0x660(%rbp)
   618a5:	mov    $0x1,%esi
   618aa:	movq   $0x0,(%rcx)
   618b1:	mov    -0x660(%rbp),%rdi
   618b8:	xor    %ecx,%ecx
   618ba:	jmpq   5f11a <_IO_vfscanf+0x2bfa>
   618bf:	mov    -0x5ec(%rbp),%r12d
   618c6:	mov    %r13,%r15
   618c9:	mov    $0xffffffff,%eax
   618ce:	and    $0x2000,%r12d
   618d5:	cmp    $0x1,%r12d
   618d9:	sbb    %r13d,%r13d
   618dc:	and    $0x2,%r13d
   618e0:	test   %r12d,%r12d
   618e3:	cmove  -0x5e8(%rbp),%eax
   618ea:	mov    %eax,-0x5e8(%rbp)
   618f0:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   618f5:	mov    0x35e56c(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   618fc:	mov    -0x5e4(%rbp),%edi
   61902:	movl   $0x10,-0x600(%rbp)
   6190c:	mov    %edi,%fs:(%rax)
   6190f:	jmpq   5d8b4 <_IO_vfscanf+0x1394>
   61914:	mov    %r13,%r15
   61917:	mov    $0x2,%r13d
   6191d:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   61922:	mov    -0x610(%rbp),%rdi
   61929:	mov    $0x30,%esi
   6192e:	callq  5c4c0 <char_buffer_add_slow>
   61933:	jmpq   5db78 <_IO_vfscanf+0x1658>
   61938:	mov    -0x650(%rbp),%rsi
   6193f:	mov    -0x630(%rbp),%rbx
   61946:	xor    %r12d,%r12d
   61949:	mov    (%rsi),%rax
   6194c:	mov    %rsi,%rdi
   6194f:	mov    %rax,(%rbx)
   61952:	mov    0x8(%rsi),%rsi
   61956:	mov    %rsi,0x8(%rbx)
   6195a:	mov    0x10(%rdi),%rdi
   6195e:	mov    %rdi,0x10(%rbx)
   61962:	mov    %eax,%edi
   61964:	xor    %ebx,%ebx
   61966:	subl   $0x1,-0x638(%rbp)
   6196d:	je     63128 <_IO_vfscanf+0x6c08>
   61973:	cmp    $0x2f,%edi
   61976:	ja     63119 <_IO_vfscanf+0x6bf9>
   6197c:	add    $0x8,%edi
   6197f:	mov    $0x1,%ebx
   61984:	jmp    61966 <_IO_vfscanf+0x5446>
   61986:	nopw   %cs:0x0(%rax,%rax,1)
   61990:	mov    -0x450(%rbp),%rax
   61997:	cmp    -0x448(%rbp),%rax
   6199e:	je     62f8d <_IO_vfscanf+0x6a6d>
   619a4:	lea    0x1(%rax),%rdx
   619a8:	mov    %rdx,-0x450(%rbp)
   619af:	mov    %r10b,(%rax)
   619b2:	mov    -0x5ec(%rbp),%eax
   619b8:	and    $0x7f,%al
   619ba:	or     $0x8,%ah
   619bd:	cmp    $0xffffffff,%r10d
   619c1:	mov    %eax,-0x5ec(%rbp)
   619c7:	je     62f78 <_IO_vfscanf+0x6a58>
   619cd:	mov    0x8(%r13),%rax
   619d1:	cmp    0x10(%r13),%rax
   619d5:	jae    62f4f <_IO_vfscanf+0x6a2f>
   619db:	lea    0x1(%rax),%rdx
   619df:	mov    %rdx,0x8(%r13)
   619e3:	movzbl (%rax),%r10d
   619e7:	add    $0x1,%r14
   619eb:	test   %r12d,%r12d
   619ee:	jle    62f37 <_IO_vfscanf+0x6a17>
   619f4:	sub    $0x1,%r12d
   619f8:	movl   $0x70,-0x6a4(%rbp)
   61a02:	movb   $0x70,-0x688(%rbp)
   61a09:	xor    %edx,%edx
   61a0b:	jmpq   5dbd2 <_IO_vfscanf+0x16b2>
   61a10:	mov    -0x650(%rbp),%rsi
   61a17:	mov    -0x630(%rbp),%rdi
   61a1e:	mov    (%rsi),%rax
   61a21:	mov    %rax,(%rdi)
   61a24:	mov    0x8(%rsi),%rdx
   61a28:	mov    %rdx,0x8(%rdi)
   61a2c:	mov    0x10(%rsi),%rcx
   61a30:	xor    %esi,%esi
   61a32:	mov    %rcx,0x10(%rdi)
   61a36:	mov    %eax,%ecx
   61a38:	xor    %edi,%edi
   61a3a:	subl   $0x1,-0x638(%rbp)
   61a41:	je     63d4c <_IO_vfscanf+0x782c>
   61a47:	cmp    $0x2f,%ecx
   61a4a:	ja     63d3e <_IO_vfscanf+0x781e>
   61a50:	add    $0x8,%ecx
   61a53:	mov    $0x1,%edi
   61a58:	jmp    61a3a <_IO_vfscanf+0x551a>
   61a5a:	nopw   0x0(%rax,%rax,1)
   61a60:	mov    -0x650(%rbp),%rsi
   61a67:	mov    -0x630(%rbp),%rdi
   61a6e:	xor    %ebx,%ebx
   61a70:	mov    (%rsi),%rdx
   61a73:	mov    %rdx,(%rdi)
   61a76:	mov    0x8(%rsi),%rcx
   61a7a:	mov    %rcx,0x8(%rdi)
   61a7e:	mov    0x10(%rsi),%rsi
   61a82:	mov    %rsi,0x10(%rdi)
   61a86:	mov    %edx,%esi
   61a88:	xor    %edi,%edi
   61a8a:	subl   $0x1,-0x638(%rbp)
   61a91:	je     63eb2 <_IO_vfscanf+0x7992>
   61a97:	cmp    $0x2f,%esi
   61a9a:	ja     62193 <_IO_vfscanf+0x5c73>
   61aa0:	add    $0x8,%esi
   61aa3:	mov    $0x1,%ebx
   61aa8:	jmp    61a8a <_IO_vfscanf+0x556a>
   61aaa:	nopw   0x0(%rax,%rax,1)
   61ab0:	mov    %r13,%rdi
   61ab3:	callq  7d720 <__uflow>
   61ab8:	cmp    $0xffffffff,%eax
   61abb:	mov    %eax,%r10d
   61abe:	jne    5dfda <_IO_vfscanf+0x1aba>
   61ac4:	mov    %r13,%r15
   61ac7:	jmpq   60919 <_IO_vfscanf+0x43f9>
   61acc:	mov    %r13,%rdi
   61acf:	callq  7d720 <__uflow>
   61ad4:	cmp    $0xffffffff,%eax
   61ad7:	mov    %eax,%r10d
   61ada:	jne    63823 <_IO_vfscanf+0x7303>
   61ae0:	mov    %r13,%r15
   61ae3:	mov    -0x600(%rbp),%r13d
   61aea:	jmpq   60b65 <_IO_vfscanf+0x4645>
   61aef:	mov    %r13,%rdi
   61af2:	callq  7d720 <__uflow>
   61af7:	cmp    $0xffffffff,%eax
   61afa:	mov    %eax,%r10d
   61afd:	jne    62036 <_IO_vfscanf+0x5b16>
   61b03:	mov    %r13,%r15
   61b06:	mov    $0x2,%r13d
   61b0c:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   61b11:	sub    $0x120,%rsp
   61b18:	mov    $0x1,%ecx
   61b1d:	lea    0xf(%rsp),%rdx
   61b22:	and    $0xfffffffffffffff0,%rdx
   61b26:	mov    %rsi,0x8(%rdx)
   61b2a:	mov    %rdx,-0x660(%rbp)
   61b31:	movq   $0x0,(%rdx)
   61b38:	mov    -0x660(%rbp),%rsi
   61b3f:	xor    %edx,%edx
   61b41:	jmpq   5d483 <_IO_vfscanf+0xf63>
   61b46:	mov    0x35e31b(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   61b4d:	mov    %r13,%r15
   61b50:	movl   $0xffffffff,-0x5e8(%rbp)
   61b5a:	xor    %r13d,%r13d
   61b5d:	movl   $0xc,%fs:(%rax)
   61b64:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   61b69:	pxor   %xmm0,%xmm0
   61b6d:	movaps %xmm0,-0x450(%rbp)
   61b74:	jmpq   5f20e <_IO_vfscanf+0x2cee>
   61b79:	mov    %r13,%rdi
   61b7c:	callq  7d720 <__uflow>
   61b81:	cmp    $0xffffffff,%eax
   61b84:	mov    %eax,%r10d
   61b87:	jne    5f658 <_IO_vfscanf+0x3138>
   61b8d:	cmpl   $0x6c,0x3fc(%rbx)
   61b94:	mov    0x35e2cd(%rip),%rdx        # 3bfe68 <_DYNAMIC+0x308>
   61b9b:	mov    %r13,%r15
   61b9e:	mov    %fs:(%rdx),%eax
   61ba1:	je     61bf3 <_IO_vfscanf+0x56d3>
   61ba3:	mov    $0x2,%r13d
   61ba9:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   61bae:	xchg   %ax,%ax
   61bb0:	mov    %r13,%rdi
   61bb3:	callq  7d720 <__uflow>
   61bb8:	cmp    $0xffffffff,%eax
   61bbb:	mov    %eax,%r10d
   61bbe:	jne    5f625 <_IO_vfscanf+0x3105>
   61bc4:	cmpl   $0x69,0x3fc(%rbx)
   61bcb:	mov    0x35e296(%rip),%rdx        # 3bfe68 <_DYNAMIC+0x308>
   61bd2:	mov    %r13,%r15
   61bd5:	mov    %fs:(%rdx),%eax
   61bd8:	jne    61ba3 <_IO_vfscanf+0x5683>
   61bda:	mov    -0x5f8(%rbp),%rsi
   61be1:	mov    %eax,%fs:(%rdx)
   61be4:	mov    0x70(%rsi),%rcx
   61be8:	mov    0x3fc(%rcx),%ecx
   61bee:	cmp    $0x6c,%ecx
   61bf1:	jne    61bf6 <_IO_vfscanf+0x56d6>
   61bf3:	mov    %eax,%fs:(%rdx)
   61bf6:	mov    $0x2,%r13d
   61bfc:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   61c01:	mov    -0x650(%rbp),%rsi
   61c08:	mov    -0x630(%rbp),%rdi
   61c0f:	mov    (%rsi),%rax
   61c12:	mov    %rax,(%rdi)
   61c15:	mov    0x8(%rsi),%rdx
   61c19:	mov    %rdx,0x8(%rdi)
   61c1d:	mov    0x10(%rsi),%rcx
   61c21:	xor    %esi,%esi
   61c23:	mov    %rcx,0x10(%rdi)
   61c27:	mov    %eax,%ecx
   61c29:	xor    %edi,%edi
   61c2b:	subl   $0x1,-0x638(%rbp)
   61c32:	je     63f24 <_IO_vfscanf+0x7a04>
   61c38:	cmp    $0x2f,%ecx
   61c3b:	ja     63f16 <_IO_vfscanf+0x79f6>
   61c41:	add    $0x8,%ecx
   61c44:	mov    $0x1,%edi
   61c49:	jmp    61c2b <_IO_vfscanf+0x570b>
   61c4b:	nopl   0x0(%rax,%rax,1)
   61c50:	mov    -0x650(%rbp),%rsi
   61c57:	mov    -0x630(%rbp),%rbx
   61c5e:	xor    %r12d,%r12d
   61c61:	mov    (%rsi),%rax
   61c64:	mov    %rsi,%rdi
   61c67:	mov    %rax,(%rbx)
   61c6a:	mov    0x8(%rsi),%rsi
   61c6e:	mov    %rsi,0x8(%rbx)
   61c72:	mov    0x10(%rdi),%rdi
   61c76:	mov    %rdi,0x10(%rbx)
   61c7a:	mov    %eax,%edi
   61c7c:	xor    %ebx,%ebx
   61c7e:	subl   $0x1,-0x638(%rbp)
   61c85:	je     6363b <_IO_vfscanf+0x711b>
   61c8b:	cmp    $0x2f,%edi
   61c8e:	ja     6362c <_IO_vfscanf+0x710c>
   61c94:	add    $0x8,%edi
   61c97:	mov    $0x1,%ebx
   61c9c:	jmp    61c7e <_IO_vfscanf+0x575e>
   61c9e:	xchg   %ax,%ax
   61ca0:	mov    -0x650(%rbp),%rsi
   61ca7:	mov    -0x630(%rbp),%rbx
   61cae:	xor    %r12d,%r12d
   61cb1:	mov    (%rsi),%rax
   61cb4:	mov    %rsi,%rdi
   61cb7:	mov    %rax,(%rbx)
   61cba:	mov    0x8(%rsi),%rsi
   61cbe:	mov    %rsi,0x8(%rbx)
   61cc2:	mov    0x10(%rdi),%rdi
   61cc6:	mov    %rdi,0x10(%rbx)
   61cca:	mov    %eax,%edi
   61ccc:	xor    %ebx,%ebx
   61cce:	subl   $0x1,-0x638(%rbp)
   61cd5:	je     62ca4 <_IO_vfscanf+0x6784>
   61cdb:	cmp    $0x2f,%edi
   61cde:	ja     62c95 <_IO_vfscanf+0x6775>
   61ce4:	add    $0x8,%edi
   61ce7:	mov    $0x1,%ebx
   61cec:	jmp    61cce <_IO_vfscanf+0x57ae>
   61cee:	xchg   %ax,%ax
   61cf0:	mov    -0x610(%rbp),%rdi
   61cf7:	movsbl %r10b,%esi
   61cfb:	callq  5c4c0 <char_buffer_add_slow>
   61d00:	jmpq   5f9c2 <_IO_vfscanf+0x34a2>
   61d05:	mov    %r13,%r15
   61d08:	mov    $0x2,%r13d
   61d0e:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   61d13:	mov    %r13,%r15
   61d16:	mov    $0x2,%r13d
   61d1c:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   61d21:	mov    %r13,%rdi
   61d24:	callq  7d720 <__uflow>
   61d29:	cmp    $0xffffffff,%eax
   61d2c:	mov    %eax,%r10d
   61d2f:	jne    5f38c <_IO_vfscanf+0x2e6c>
   61d35:	mov    %r13,%r15
   61d38:	jmpq   60d2b <_IO_vfscanf+0x480b>
   61d3d:	mov    %r13,%r15
   61d40:	mov    $0x2,%r13d
   61d46:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   61d4b:	mov    0x35e116(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   61d52:	mov    %r13,%r15
   61d55:	mov    $0x4,%r13d
   61d5b:	movl   $0x54,%fs:(%rax)
   61d62:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   61d67:	mov    %rsi,%rdi
   61d6a:	callq  7d720 <__uflow>
   61d6f:	cmp    $0xffffffff,%eax
   61d72:	mov    %eax,%ebx
   61d74:	jne    5eeb2 <_IO_vfscanf+0x2992>
   61d7a:	mov    %eax,%r10d
   61d7d:	mov    0x35e0e4(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   61d84:	mov    -0x678(%rbp),%r15
   61d8b:	mov    %fs:(%rax),%eax
   61d8e:	mov    %eax,-0x5e4(%rbp)
   61d94:	mov    -0x600(%rbp),%esi
   61d9a:	test   %esi,%esi
   61d9c:	jne    5c77d <_IO_vfscanf+0x25d>
   61da2:	cmpl   $0x0,-0x5ec(%rbp)
   61da9:	je     61dea <_IO_vfscanf+0x58ca>
   61dab:	mov    -0x608(%rbp),%rbx
   61db2:	mov    -0x640(%rbp),%rsi
   61db9:	mov    (%rbx),%rdi
   61dbc:	sub    %rdi,%rsi
   61dbf:	mov    %rsi,%rax
   61dc2:	sar    $0x2,%rax
   61dc6:	cmp    %rax,-0x658(%rbp)
   61dcd:	je     61dea <_IO_vfscanf+0x58ca>
   61dcf:	mov    %r10d,-0x5ec(%rbp)
   61dd6:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   61ddb:	test   %rax,%rax
   61dde:	mov    -0x5ec(%rbp),%r10d
   61de5:	je     61dea <_IO_vfscanf+0x58ca>
   61de7:	mov    %rax,(%rbx)
   61dea:	addl   $0x1,-0x5e8(%rbp)
   61df1:	movq   $0x0,-0x608(%rbp)
   61dfc:	jmpq   5c832 <_IO_vfscanf+0x312>
   61e01:	nopl   0x0(%rax)
   61e08:	mov    %r13,%rdi
   61e0b:	callq  7d720 <__uflow>
   61e10:	cmp    $0xffffffff,%eax
   61e13:	mov    %eax,%r10d
   61e16:	jne    5db10 <_IO_vfscanf+0x15f0>
   61e1c:	mov    %r13,%r15
   61e1f:	mov    $0x2,%r13d
   61e25:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   61e2a:	mov    %r13,%r15
   61e2d:	mov    $0x2,%r13d
   61e33:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   61e38:	pxor   %xmm0,%xmm0
   61e3c:	movaps %xmm0,-0x450(%rbp)
   61e43:	jmpq   5d847 <_IO_vfscanf+0x1327>
   61e48:	sub    $0x120,%rsp
   61e4f:	mov    -0x660(%rbp),%rdi
   61e56:	mov    $0x1,%esi
   61e5b:	lea    0xf(%rsp),%rcx
   61e60:	and    $0xfffffffffffffff0,%rcx
   61e64:	movq   $0x0,(%rcx)
   61e6b:	mov    %rdi,0x8(%rcx)
   61e6f:	mov    %rcx,-0x660(%rbp)
   61e76:	xor    %ecx,%ecx
   61e78:	jmpq   5d655 <_IO_vfscanf+0x1135>
   61e7d:	mov    -0x5ec(%rbp),%r12d
   61e84:	mov    %r13,%r15
   61e87:	mov    $0xffffffff,%eax
   61e8c:	and    $0x2000,%r12d
   61e93:	cmp    $0x1,%r12d
   61e97:	sbb    %r13d,%r13d
   61e9a:	and    $0x2,%r13d
   61e9e:	test   %r12d,%r12d
   61ea1:	cmove  -0x5e8(%rbp),%eax
   61ea8:	mov    %eax,-0x5e8(%rbp)
   61eae:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   61eb3:	mov    -0x5ec(%rbp),%r12d
   61eba:	mov    %r13,%r15
   61ebd:	mov    $0xffffffff,%eax
   61ec2:	and    $0x2000,%r12d
   61ec9:	cmp    $0x1,%r12d
   61ecd:	sbb    %r13d,%r13d
   61ed0:	and    $0x2,%r13d
   61ed4:	test   %r12d,%r12d
   61ed7:	cmove  -0x5e8(%rbp),%eax
   61ede:	mov    %eax,-0x5e8(%rbp)
   61ee4:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   61ee9:	pxor   %xmm0,%xmm0
   61eed:	mov    %r13,%r15
   61ef0:	movaps %xmm0,-0x450(%rbp)
   61ef7:	jmpq   5f972 <_IO_vfscanf+0x3452>
   61efc:	mov    %r13,%rdi
   61eff:	callq  7d720 <__uflow>
   61f04:	cmp    $0xffffffff,%eax
   61f07:	mov    %eax,%r10d
   61f0a:	jne    5e813 <_IO_vfscanf+0x22f3>
   61f10:	cmpl   $0x6e,0x3fc(%rbx)
   61f17:	mov    0x35df4a(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   61f1e:	mov    %r13,%r15
   61f21:	mov    %fs:(%rax),%edx
   61f24:	jne    61ba3 <_IO_vfscanf+0x5683>
   61f2a:	mov    -0x5f8(%rbp),%rdi
   61f31:	mov    %edx,%fs:(%rax)
   61f34:	mov    0x70(%rdi),%rcx
   61f38:	mov    0x3fc(%rcx),%ecx
   61f3e:	cmp    $0x69,%ecx
   61f41:	jne    61654 <_IO_vfscanf+0x5134>
   61f47:	mov    %edx,%fs:(%rax)
   61f4a:	jmpq   61bf6 <_IO_vfscanf+0x56d6>
   61f4f:	pxor   %xmm0,%xmm0
   61f53:	movaps %xmm0,-0x450(%rbp)
   61f5a:	jmpq   5d7db <_IO_vfscanf+0x12bb>
   61f5f:	mov    -0x650(%rbp),%rsi
   61f66:	mov    -0x630(%rbp),%rdi
   61f6d:	xor    %ebx,%ebx
   61f6f:	mov    (%rsi),%rdx
   61f72:	mov    %rdx,(%rdi)
   61f75:	mov    0x8(%rsi),%rcx
   61f79:	mov    %rcx,0x8(%rdi)
   61f7d:	mov    0x10(%rsi),%rsi
   61f81:	mov    %rsi,0x10(%rdi)
   61f85:	mov    %edx,%esi
   61f87:	xor    %edi,%edi
   61f89:	subl   $0x1,-0x638(%rbp)
   61f90:	je     632c5 <_IO_vfscanf+0x6da5>
   61f96:	cmp    $0x2f,%esi
   61f99:	ja     6228b <_IO_vfscanf+0x5d6b>
   61f9f:	add    $0x8,%esi
   61fa2:	mov    $0x1,%ebx
   61fa7:	jmp    61f89 <_IO_vfscanf+0x5a69>
   61fa9:	nopl   0x0(%rax)
   61fb0:	mov    %r13,%r15
   61fb3:	mov    $0x2,%r13d
   61fb9:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   61fbe:	mov    -0x610(%rbp),%rdi
   61fc5:	xor    %esi,%esi
   61fc7:	mov    %r10d,-0x600(%rbp)
   61fce:	callq  5c4c0 <char_buffer_add_slow>
   61fd3:	mov    -0x600(%rbp),%r10d
   61fda:	jmpq   5eb42 <_IO_vfscanf+0x2622>
   61fdf:	mov    %r13,%r15
   61fe2:	mov    $0x2,%r13d
   61fe8:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   61fed:	mov    %r13,%rdi
   61ff0:	callq  7d720 <__uflow>
   61ff5:	cmp    $0xffffffff,%eax
   61ff8:	mov    %eax,%r10d
   61ffb:	jne    6202d <_IO_vfscanf+0x5b0d>
   61ffd:	mov    %r13,%r15
   62000:	mov    $0x2,%r13d
   62006:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   6200b:	mov    %r13,%r15
   6200e:	mov    $0x2,%r13d
   62014:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   62019:	mov    -0x610(%rbp),%rdi
   62020:	movsbl %al,%esi
   62023:	callq  5c4c0 <char_buffer_add_slow>
   62028:	jmpq   5fa28 <_IO_vfscanf+0x3508>
   6202d:	add    $0x2,%r14
   62031:	jmpq   5fa4f <_IO_vfscanf+0x352f>
   62036:	lea    0x2(%r14),%rbx
   6203a:	jmpq   5fd9f <_IO_vfscanf+0x387f>
   6203f:	mov    -0x5a0(%rbp),%rax
   62046:	lea    0x8(%rax),%rdx
   6204a:	mov    %rdx,-0x5a0(%rbp)
   62051:	jmpq   5f8a1 <_IO_vfscanf+0x3381>
   62056:	add    $0x8,%rdx
   6205a:	mov    $0x1,%esi
   6205f:	jmpq   60f4a <_IO_vfscanf+0x4a2a>
   62064:	test   %dil,%dil
   62067:	je     62071 <_IO_vfscanf+0x5b51>
   62069:	mov    %ecx,-0x520(%rbp)
   6206f:	mov    %ecx,%eax
   62071:	test   %sil,%sil
   62074:	je     6207d <_IO_vfscanf+0x5b5d>
   62076:	mov    %rdx,-0x518(%rbp)
   6207d:	cmp    $0x2f,%eax
   62080:	ja     62112 <_IO_vfscanf+0x5bf2>
   62086:	mov    %eax,%edx
   62088:	add    -0x510(%rbp),%rdx
   6208f:	add    $0x8,%eax
   62092:	mov    %eax,-0x520(%rbp)
   62098:	mov    (%rdx),%rax
   6209b:	jmpq   5d57f <_IO_vfscanf+0x105f>
   620a0:	mov    %r13,%r15
   620a3:	mov    $0x2,%r13d
   620a9:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   620ae:	add    $0x8,%rdx
   620b2:	mov    $0x1,%esi
   620b7:	jmpq   6151b <_IO_vfscanf+0x4ffb>
   620bc:	test   %dil,%dil
   620bf:	je     620c9 <_IO_vfscanf+0x5ba9>
   620c1:	mov    %ecx,-0x520(%rbp)
   620c7:	mov    %ecx,%eax
   620c9:	test   %sil,%sil
   620cc:	je     620d5 <_IO_vfscanf+0x5bb5>
   620ce:	mov    %rdx,-0x518(%rbp)
   620d5:	cmp    $0x2f,%eax
   620d8:	ja     62129 <_IO_vfscanf+0x5c09>
   620da:	mov    %eax,%edx
   620dc:	add    -0x510(%rbp),%rdx
   620e3:	add    $0x8,%eax
   620e6:	mov    %eax,-0x520(%rbp)
   620ec:	mov    (%rdx),%rax
   620ef:	mov    %rax,-0x668(%rbp)
   620f6:	jmpq   60c11 <_IO_vfscanf+0x46f1>
   620fb:	mov    -0x5a0(%rbp),%rax
   62102:	lea    0x8(%rax),%rdx
   62106:	mov    %rdx,-0x5a0(%rbp)
   6210d:	jmpq   5d00b <_IO_vfscanf+0xaeb>
   62112:	mov    -0x518(%rbp),%rdx
   62119:	lea    0x8(%rdx),%rax
   6211d:	mov    %rax,-0x518(%rbp)
   62124:	jmpq   62098 <_IO_vfscanf+0x5b78>
   62129:	mov    -0x518(%rbp),%rdx
   62130:	lea    0x8(%rdx),%rax
   62134:	mov    %rax,-0x518(%rbp)
   6213b:	jmp    620ec <_IO_vfscanf+0x5bcc>
   6213d:	mov    %r12d,%r10d
   62140:	mov    %r15d,%r12d
   62143:	mov    -0x698(%rbp),%r15
   6214a:	cmp    $0xffffffff,%r10d
   6214e:	je     5eadd <_IO_vfscanf+0x25bd>
   62154:	movzbl %r10b,%esi
   62158:	mov    %r13,%rdi
   6215b:	mov    %r10d,-0x628(%rbp)
   62162:	sub    $0x1,%r14
   62166:	callq  7e5a0 <_IO_sputbackc>
   6216b:	mov    -0x628(%rbp),%r10d
   62172:	jmpq   5eadd <_IO_vfscanf+0x25bd>
   62177:	add    $0x8,%rcx
   6217b:	mov    $0x1,%edi
   62180:	jmpq   6109d <_IO_vfscanf+0x4b7d>
   62185:	mov    %r13,%r15
   62188:	mov    $0x2,%r13d
   6218e:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   62193:	add    $0x8,%rcx
   62197:	mov    $0x1,%edi
   6219c:	jmpq   61a8a <_IO_vfscanf+0x556a>
   621a1:	mov    -0x608(%rbp),%rax
   621a8:	add    $0x1,%r15
   621ac:	mov    %rdx,-0x688(%rbp)
   621b3:	mov    %r15,%rsi
   621b6:	mov    %ecx,-0x678(%rbp)
   621bc:	mov    %r8d,-0x668(%rbp)
   621c3:	mov    (%rax),%rdi
   621c6:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   621cb:	test   %rax,%rax
   621ce:	mov    -0x668(%rbp),%r8d
   621d5:	mov    -0x678(%rbp),%ecx
   621db:	mov    -0x688(%rbp),%rdx
   621e2:	je     62226 <_IO_vfscanf+0x5d06>
   621e4:	mov    -0x608(%rbp),%rdi
   621eb:	mov    -0x658(%rbp),%rsi
   621f2:	mov    %rax,(%rdi)
   621f5:	add    %rax,%rsi
   621f8:	jmpq   5e04b <_IO_vfscanf+0x1b2b>
   621fd:	add    $0x1,%r14
   62201:	test   %r12d,%r12d
   62204:	jg     5dad1 <_IO_vfscanf+0x15b1>
   6220a:	lea    -0x2b(%rax),%eax
   6220d:	and    $0xfffffffd,%eax
   62210:	jne    5f1b4 <_IO_vfscanf+0x2c94>
   62216:	cmp    $0x2d,%r10d
   6221a:	sete   -0x6a0(%rbp)
   62221:	jmpq   5daf6 <_IO_vfscanf+0x15d6>
   62226:	mov    -0x5ec(%rbp),%r12d
   6222d:	mov    %r13,%r15
   62230:	and    $0x2000,%r12d
   62237:	jne    62299 <_IO_vfscanf+0x5d79>
   62239:	mov    -0x608(%rbp),%rax
   62240:	mov    -0x658(%rbp),%rsi
   62247:	mov    $0x2,%r13d
   6224d:	addl   $0x1,-0x5e8(%rbp)
   62254:	movq   $0x0,-0x608(%rbp)
   6225f:	mov    (%rax),%rax
   62262:	movb   $0x0,-0x1(%rax,%rsi,1)
   62267:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   6226c:	mov    %r13,%rdi
   6226f:	callq  7d720 <__uflow>
   62274:	cmp    $0xffffffff,%eax
   62277:	jne    5f9e4 <_IO_vfscanf+0x34c4>
   6227d:	mov    %r13,%r15
   62280:	mov    $0x2,%r13d
   62286:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   6228b:	add    $0x8,%rcx
   6228f:	mov    $0x1,%edi
   62294:	jmpq   61f89 <_IO_vfscanf+0x5a69>
   62299:	xor    %r13d,%r13d
   6229c:	movl   $0xffffffff,-0x5e8(%rbp)
   622a6:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   622ab:	mov    -0x5a0(%rbp),%rdx
   622b2:	lea    0x8(%rdx),%rcx
   622b6:	mov    %rcx,-0x5a0(%rbp)
   622bd:	jmpq   614d9 <_IO_vfscanf+0x4fb9>
   622c2:	mov    %r13,%r15
   622c5:	mov    $0x2,%r13d
   622cb:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   622d0:	cmpl   $0x0,-0x600(%rbp)
   622d7:	jne    5eafd <_IO_vfscanf+0x25dd>
   622dd:	cmp    %rax,-0x440(%rbp)
   622e4:	je     622f3 <_IO_vfscanf+0x5dd3>
   622e6:	testb  $0x1,-0x678(%rbp)
   622ed:	je     5eafd <_IO_vfscanf+0x25dd>
   622f3:	lea    0x127753(%rip),%rdi        # 189a4d <null+0xf>
   622fa:	mov    %r10d,-0x628(%rbp)
   62301:	callq  10b870 <wctrans>
   62306:	test   %rax,%rax
   62309:	mov    %rax,-0x6b0(%rbp)
   62310:	mov    -0x628(%rbp),%r10d
   62317:	je     624e8 <_IO_vfscanf+0x5fc8>
   6231d:	cmp    $0xffffffff,%r10d
   62321:	je     62575 <_IO_vfscanf+0x6055>
   62327:	mov    0x8(%r13),%rax
   6232b:	cmp    0x10(%r13),%rax
   6232f:	jae    6254c <_IO_vfscanf+0x602c>
   62335:	lea    0x1(%rax),%rdx
   62339:	mov    %rdx,0x8(%r13)
   6233d:	movzbl (%rax),%r10d
   62341:	add    $0x1,%r14
   62345:	mov    -0x6b0(%rbp),%rsi
   6234c:	mov    $0x2e,%edi
   62351:	mov    %r10d,-0x628(%rbp)
   62358:	callq  10b900 <__towctrans>
   6235d:	mov    -0x440(%rbp),%rdi
   62364:	cmp    %rdi,-0x450(%rbp)
   6236b:	lea    -0x5c0(%rbp),%rsi
   62372:	mov    -0x680(%rbp),%rdi
   62379:	mov    %eax,-0x544(%rbp)
   6237f:	mov    %rsi,-0x698(%rbp)
   62386:	mov    %rsi,%rdx
   62389:	mov    %eax,%esi
   6238b:	movq   $0x0,-0x5c0(%rbp)
   62396:	sete   %bl
   62399:	callq  ac610 <c32rtomb>
   6239e:	cmp    $0xffffffffffffffff,%rax
   623a2:	mov    %rax,%rsi
   623a5:	mov    -0x628(%rbp),%r10d
   623ac:	je     624cd <_IO_vfscanf+0x5fad>
   623b2:	mov    -0x670(%rbp),%rdi
   623b9:	movb   $0x0,-0x465(%rbp,%rax,1)
   623c1:	or     $0xffffffffffffffff,%rcx
   623c5:	xor    %eax,%eax
   623c7:	repnz scas %es:(%rdi),%al
   623c9:	mov    %rcx,%rax
   623cc:	mov    -0x450(%rbp),%rcx
   623d3:	sub    -0x440(%rbp),%rcx
   623da:	not    %rax
   623dd:	lea    -0x1(%rax),%rdx
   623e1:	xor    %eax,%eax
   623e3:	cmp    %rcx,%rdx
   623e6:	jne    62407 <_IO_vfscanf+0x5ee7>
   623e8:	mov    -0x680(%rbp),%rsi
   623ef:	mov    -0x670(%rbp),%rdi
   623f6:	callq  8b5b0 <__GI_strcmp>
   623fb:	mov    -0x628(%rbp),%r10d
   62402:	test   %eax,%eax
   62404:	sete   %al
   62407:	or     %ebx,%eax
   62409:	test   %al,%al
   6240b:	je     624e8 <_IO_vfscanf+0x5fc8>
   62411:	mov    -0x630(%rbp),%rax
   62418:	xor    %ebx,%ebx
   6241a:	mov    %r10d,-0x6c0(%rbp)
   62421:	mov    %rax,-0x6b8(%rbp)
   62428:	movzbl -0x6c8(%rbp),%eax
   6242f:	mov    %al,-0x6d0(%rbp)
   62435:	lea    -0x570(%rbp),%rax
   6243c:	mov    %rax,-0x628(%rbp)
   62443:	cmp    $0xa,%rbx
   62447:	mov    %ebx,-0x6a8(%rbp)
   6244d:	je     62596 <_IO_vfscanf+0x6076>
   62453:	mov    -0x6b0(%rbp),%rsi
   6245a:	lea    0x30(%rbx),%edi
   6245d:	callq  10b900 <__towctrans>
   62462:	mov    -0x698(%rbp),%rdi
   62469:	mov    -0x628(%rbp),%rsi
   62470:	movq   $0x0,(%rdi)
   62477:	mov    %rdi,%rdx
   6247a:	mov    -0x6b8(%rbp),%rdi
   62481:	mov    %eax,(%rsi,%rbx,4)
   62484:	mov    %eax,%esi
   62486:	callq  ac610 <c32rtomb>
   6248b:	cmp    $0xffffffffffffffff,%rax
   6248f:	je     6258a <_IO_vfscanf+0x606a>
   62495:	movslq -0x6a8(%rbp),%rdx
   6249c:	lea    -0x30(%rbp),%rdi
   624a0:	add    $0x1,%rbx
   624a4:	addq   $0x11,-0x6b8(%rbp)
   624ac:	imul   $0x11,%rdx,%rdx
   624b0:	add    %rdi,%rdx
   624b3:	cmp    $0xb,%rbx
   624b7:	movb   $0x0,-0x4f0(%rax,%rdx,1)
   624bf:	jne    62443 <_IO_vfscanf+0x5f23>
   624c1:	mov    -0x6c0(%rbp),%r10d
   624c8:	jmpq   62632 <_IO_vfscanf+0x6112>
   624cd:	mov    -0x670(%rbp),%rdi
   624d4:	xor    %eax,%eax
   624d6:	mov    %rsi,%rcx
   624d9:	repnz scas %es:(%rdi),%al
   624db:	not    %rcx
   624de:	lea    -0x1(%rcx),%rdx
   624e2:	cmp    $0x10,%rdx
   624e6:	jbe    6251f <_IO_vfscanf+0x5fff>
   624e8:	mov    -0x450(%rbp),%rax
   624ef:	test   %rax,%rax
   624f2:	jne    5eafd <_IO_vfscanf+0x25dd>
   624f8:	mov    0x35d969(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   624ff:	mov    %r13,%r15
   62502:	movl   $0xffffffff,-0x5e8(%rbp)
   6250c:	mov    -0x600(%rbp),%r13d
   62513:	movl   $0xc,%fs:(%rax)
   6251a:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   6251f:	mov    -0x450(%rbp),%rax
   62526:	sub    -0x440(%rbp),%rax
   6252d:	mov    %ecx,%ecx
   6252f:	mov    -0x680(%rbp),%rdi
   62536:	mov    -0x670(%rbp),%rsi
   6253d:	rep movsb %ds:(%rsi),%es:(%rdi)
   6253f:	cmp    %rdx,%rax
   62542:	sete   %al
   62545:	or     %ebx,%eax
   62547:	jmpq   62409 <_IO_vfscanf+0x5ee9>
   6254c:	mov    %r13,%rdi
   6254f:	callq  7d720 <__uflow>
   62554:	cmp    $0xffffffff,%eax
   62557:	mov    %eax,%r10d
   6255a:	jne    62341 <_IO_vfscanf+0x5e21>
   62560:	mov    0x35d901(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   62567:	mov    %fs:(%rax),%eax
   6256a:	mov    %eax,-0x5e4(%rbp)
   62570:	jmpq   62345 <_IO_vfscanf+0x5e25>
   62575:	mov    0x35d8ec(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   6257c:	mov    -0x5e4(%rbp),%esi
   62582:	mov    %esi,%fs:(%rax)
   62585:	jmpq   62345 <_IO_vfscanf+0x5e25>
   6258a:	mov    -0x6c0(%rbp),%r10d
   62591:	jmpq   624e8 <_IO_vfscanf+0x5fc8>
   62596:	mov    -0x6b0(%rbp),%rsi
   6259d:	mov    $0x2c,%edi
   625a2:	callq  10b900 <__towctrans>
   625a7:	mov    -0x628(%rbp),%rdi
   625ae:	test   %eax,%eax
   625b0:	mov    %eax,-0x548(%rbp)
   625b6:	setne  %al
   625b9:	and    %al,-0x6d0(%rbp)
   625bf:	mov    -0x698(%rbp),%rax
   625c6:	mov    0x28(%rdi),%esi
   625c9:	mov    -0x6b8(%rbp),%rdi
   625d0:	movq   $0x0,(%rax)
   625d7:	mov    %rax,%rdx
   625da:	callq  ac610 <c32rtomb>
   625df:	cmp    $0xffffffffffffffff,%rax
   625e3:	jne    62495 <_IO_vfscanf+0x5f75>
   625e9:	cmpb   $0x0,-0x6d0(%rbp)
   625f0:	mov    %rax,%rsi
   625f3:	mov    -0x6c0(%rbp),%r10d
   625fa:	je     62632 <_IO_vfscanf+0x6112>
   625fc:	mov    -0x620(%rbp),%rdi
   62603:	xor    %eax,%eax
   62605:	mov    %rsi,%rcx
   62608:	repnz scas %es:(%rdi),%al
   6260a:	not    %rcx
   6260d:	lea    -0x1(%rcx),%rax
   62611:	cmp    $0x10,%rax
   62615:	ja     62632 <_IO_vfscanf+0x6112>
   62617:	mov    -0x630(%rbp),%rax
   6261e:	mov    %ecx,%ecx
   62620:	mov    -0x620(%rbp),%rsi
   62627:	add    $0xaa,%rax
   6262d:	mov    %rax,%rdi
   62630:	rep movsb %ds:(%rsi),%es:(%rdi)
   62632:	mov    %r15,-0x698(%rbp)
   62639:	mov    %r10d,%r15d
   6263c:	mov    -0x450(%rbp),%rax
   62643:	test   %rax,%rax
   62646:	je     62a53 <_IO_vfscanf+0x6533>
   6264c:	cmpb   $0x0,-0x690(%rbp)
   62653:	je     629f5 <_IO_vfscanf+0x64d5>
   62659:	movzbl -0x688(%rbp),%edi
   62660:	cmp    -0x1(%rax),%dil
   62664:	je     62cd8 <_IO_vfscanf+0x67b8>
   6266a:	test   %r12d,%r12d
   6266d:	mov    $0x7fffffff,%ebx
   62672:	mov    -0x630(%rbp),%rcx
   62679:	cmovg  %r12d,%ebx
   6267d:	mov    %r12d,-0x6b0(%rbp)
   62684:	mov    %r13,%r12
   62687:	mov    %ebx,-0x6b8(%rbp)
   6268d:	xor    %ebx,%ebx
   6268f:	mov    %r14,%r13
   62692:	mov    %ebx,-0x628(%rbp)
   62698:	mov    %rcx,%rbx
   6269b:	movzbl (%rbx),%esi
   6269e:	cmp    %r15d,%esi
   626a1:	jne    62963 <_IO_vfscanf+0x6443>
   626a7:	cmpb   $0x0,0x1(%rbx)
   626ab:	lea    0x1(%rbx),%r14
   626af:	je     6296c <_IO_vfscanf+0x644c>
   626b5:	mov    -0x6b8(%rbp),%esi
   626bb:	jmp    626f6 <_IO_vfscanf+0x61d6>
   626bd:	nopl   (%rax)
   626c0:	lea    0x1(%rax),%rdx
   626c4:	mov    %rdx,0x8(%r12)
   626c9:	movzbl (%rax),%eax
   626cc:	movzbl (%r14),%r15d
   626d0:	add    $0x1,%r13
   626d4:	sub    $0x1,%esi
   626d7:	cmp    %eax,%r15d
   626da:	jne    6276a <_IO_vfscanf+0x624a>
   626e0:	add    $0x1,%r14
   626e4:	cmpb   $0x0,(%r14)
   626e8:	je     6282c <_IO_vfscanf+0x630c>
   626ee:	test   %esi,%esi
   626f0:	je     62777 <_IO_vfscanf+0x6257>
   626f6:	mov    0x8(%r12),%rax
   626fb:	cmp    0x10(%r12),%rax
   62700:	jb     626c0 <_IO_vfscanf+0x61a0>
   62702:	mov    %r12,%rdi
   62705:	mov    %esi,-0x6c0(%rbp)
   6270b:	callq  7d720 <__uflow>
   62710:	cmp    $0xffffffff,%eax
   62713:	mov    -0x6c0(%rbp),%esi
   62719:	jne    626cc <_IO_vfscanf+0x61ac>
   6271b:	mov    0x35d746(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   62722:	mov    $0xffffffff,%r15d
   62728:	mov    %fs:(%rax),%eax
   6272b:	mov    %eax,-0x5e4(%rbp)
   62731:	jmp    6276d <_IO_vfscanf+0x624d>
   62733:	pxor   %xmm0,%xmm0
   62737:	test   %r15d,%r15d
   6273a:	movaps %xmm0,-0x450(%rbp)
   62741:	jne    5dc52 <_IO_vfscanf+0x1732>
   62747:	mov    0x35d71a(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   6274e:	mov    %r13,%r15
   62751:	movl   $0xffffffff,-0x5e8(%rbp)
   6275b:	xor    %r13d,%r13d
   6275e:	movl   $0xc,%fs:(%rax)
   62765:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   6276a:	mov    %eax,%r15d
   6276d:	cmpb   $0x0,(%r14)
   62771:	je     6282c <_IO_vfscanf+0x630c>
   62777:	cmp    %rbx,%r14
   6277a:	jbe    627d5 <_IO_vfscanf+0x62b5>
   6277c:	cmp    $0xffffffff,%r15d
   62780:	je     62792 <_IO_vfscanf+0x6272>
   62782:	movzbl %r15b,%esi
   62786:	mov    %r12,%rdi
   62789:	sub    $0x1,%r13
   6278d:	callq  7e5a0 <_IO_sputbackc>
   62792:	lea    -0x1(%r14),%r15
   62796:	cmp    %rbx,%r15
   62799:	jbe    627d1 <_IO_vfscanf+0x62b1>
   6279b:	mov    %r15,%r8
   6279e:	movzbl (%r8),%esi
   627a2:	mov    %r12,%rdi
   627a5:	mov    %r8,-0x6c0(%rbp)
   627ac:	callq  7e5a0 <_IO_sputbackc>
   627b1:	mov    -0x6c0(%rbp),%r8
   627b8:	sub    $0x1,%r8
   627bc:	cmp    %r8,%rbx
   627bf:	jne    6279e <_IO_vfscanf+0x627e>
   627c1:	mov    %rbx,%rax
   627c4:	sub    %r14,%rax
   627c7:	add    $0x1,%rax
   627cb:	add    %rax,%r15
   627ce:	add    %rax,%r13
   627d1:	movzbl (%r15),%r15d
   627d5:	addl   $0x1,-0x628(%rbp)
   627dc:	add    $0x11,%rbx
   627e0:	mov    -0x628(%rbp),%eax
   627e6:	cmp    $0xc,%eax
   627e9:	jne    6269b <_IO_vfscanf+0x617b>
   627ef:	mov    %r15d,%r10d
   627f2:	mov    -0x698(%rbp),%r15
   627f9:	mov    %r13,%r14
   627fc:	mov    %r12,%r13
   627ff:	cmp    $0xffffffff,%r10d
   62803:	je     624e8 <_IO_vfscanf+0x5fc8>
   62809:	movzbl %r10b,%esi
   6280d:	mov    %r13,%rdi
   62810:	mov    %r10d,-0x628(%rbp)
   62817:	sub    $0x1,%r14
   6281b:	callq  7e5a0 <_IO_sputbackc>
   62820:	mov    -0x628(%rbp),%r10d
   62827:	jmpq   624e8 <_IO_vfscanf+0x5fc8>
   6282c:	mov    %r13,%r14
   6282f:	mov    -0x628(%rbp),%ebx
   62835:	mov    %r12,%r13
   62838:	mov    -0x6b0(%rbp),%r12d
   6283f:	test   %r12d,%r12d
   62842:	cmovg  %esi,%r12d
   62846:	cmp    $0x9,%ebx
   62849:	jg     62919 <_IO_vfscanf+0x63f9>
   6284f:	mov    -0x450(%rbp),%rax
   62856:	cmp    -0x448(%rbp),%rax
   6285d:	lea    0x30(%rbx),%edx
   62860:	movzbl %dl,%esi
   62863:	je     62908 <_IO_vfscanf+0x63e8>
   62869:	lea    0x1(%rax),%rcx
   6286d:	mov    %rcx,-0x450(%rbp)
   62874:	mov    %dl,(%rax)
   62876:	test   %r12d,%r12d
   62879:	je     628f9 <_IO_vfscanf+0x63d9>
   6287b:	cmp    $0xffffffff,%r15d
   6287f:	je     628da <_IO_vfscanf+0x63ba>
   62881:	mov    0x8(%r13),%rax
   62885:	cmp    0x10(%r13),%rax
   62889:	jae    628ab <_IO_vfscanf+0x638b>
   6288b:	lea    0x1(%rax),%rdx
   6288f:	mov    %rdx,0x8(%r13)
   62893:	movzbl (%rax),%r15d
   62897:	xor    %eax,%eax
   62899:	add    $0x1,%r14
   6289d:	test   %r12d,%r12d
   628a0:	setg   %al
   628a3:	sub    %eax,%r12d
   628a6:	jmpq   6263c <_IO_vfscanf+0x611c>
   628ab:	mov    %r13,%rdi
   628ae:	callq  7d720 <__uflow>
   628b3:	cmp    $0xffffffff,%eax
   628b6:	mov    %eax,%r15d
   628b9:	jne    62897 <_IO_vfscanf+0x6377>
   628bb:	mov    %eax,%r10d
   628be:	mov    0x35d5a3(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   628c5:	mov    -0x698(%rbp),%r15
   628cc:	mov    %fs:(%rax),%eax
   628cf:	mov    %eax,-0x5e4(%rbp)
   628d5:	jmpq   624e8 <_IO_vfscanf+0x5fc8>
   628da:	mov    0x35d587(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   628e1:	mov    -0x5e4(%rbp),%esi
   628e7:	mov    %r15d,%r10d
   628ea:	mov    -0x698(%rbp),%r15
   628f1:	mov    %esi,%fs:(%rax)
   628f4:	jmpq   624e8 <_IO_vfscanf+0x5fc8>
   628f9:	mov    %r15d,%r10d
   628fc:	mov    -0x698(%rbp),%r15
   62903:	jmpq   624e8 <_IO_vfscanf+0x5fc8>
   62908:	mov    -0x610(%rbp),%rdi
   6290f:	callq  5c4c0 <char_buffer_add_slow>
   62914:	jmpq   62876 <_IO_vfscanf+0x6356>
   62919:	movzbl -0x678(%rbp),%eax
   62920:	xor    $0x1,%eax
   62923:	and    $0x1,%eax
   62926:	cmp    $0xb,%ebx
   62929:	jne    629a4 <_IO_vfscanf+0x6484>
   6292b:	test   %al,%al
   6292d:	je     629a4 <_IO_vfscanf+0x6484>
   6292f:	mov    -0x670(%rbp),%rbx
   62936:	movzbl (%rbx),%eax
   62939:	test   %al,%al
   6293b:	je     62998 <_IO_vfscanf+0x6478>
   6293d:	mov    -0x450(%rbp),%rdx
   62944:	cmp    -0x448(%rbp),%rdx
   6294b:	movsbl %al,%esi
   6294e:	je     6298a <_IO_vfscanf+0x646a>
   62950:	lea    0x1(%rdx),%rcx
   62954:	mov    %rcx,-0x450(%rbp)
   6295b:	mov    %al,(%rdx)
   6295d:	add    $0x1,%rbx
   62961:	jmp    62936 <_IO_vfscanf+0x6416>
   62963:	test   %sil,%sil
   62966:	jne    627d5 <_IO_vfscanf+0x62b5>
   6296c:	mov    %r13,%r14
   6296f:	mov    -0x628(%rbp),%ebx
   62975:	mov    %r12,%r13
   62978:	mov    -0x6b8(%rbp),%esi
   6297e:	mov    -0x6b0(%rbp),%r12d
   62985:	jmpq   6283f <_IO_vfscanf+0x631f>
   6298a:	mov    -0x610(%rbp),%rdi
   62991:	callq  5c4c0 <char_buffer_add_slow>
   62996:	jmp    6295d <_IO_vfscanf+0x643d>
   62998:	movb   $0x1,-0x678(%rbp)
   6299f:	jmpq   62876 <_IO_vfscanf+0x6356>
   629a4:	test   %al,-0x6c8(%rbp)
   629aa:	je     62d15 <_IO_vfscanf+0x67f5>
   629b0:	cmp    $0xa,%ebx
   629b3:	jne    62d15 <_IO_vfscanf+0x67f5>
   629b9:	mov    -0x620(%rbp),%rbx
   629c0:	movzbl (%rbx),%eax
   629c3:	test   %al,%al
   629c5:	je     62d09 <_IO_vfscanf+0x67e9>
   629cb:	mov    -0x450(%rbp),%rdx
   629d2:	cmp    -0x448(%rbp),%rdx
   629d9:	movsbl %al,%esi
   629dc:	je     62d24 <_IO_vfscanf+0x6804>
   629e2:	lea    0x1(%rdx),%rcx
   629e6:	mov    %rcx,-0x450(%rbp)
   629ed:	mov    %al,(%rdx)
   629ef:	add    $0x1,%rbx
   629f3:	jmp    629c0 <_IO_vfscanf+0x64a0>
   629f5:	cmp    -0x440(%rbp),%rax
   629fc:	je     6266a <_IO_vfscanf+0x614a>
   62a02:	mov    -0x5f8(%rbp),%rsi
   62a09:	movzbl %r15b,%edx
   62a0d:	movzbl -0x688(%rbp),%edi
   62a14:	mov    0x70(%rsi),%rcx
   62a18:	cmp    (%rcx,%rdx,4),%dil
   62a1c:	jne    6266a <_IO_vfscanf+0x614a>
   62a22:	cmp    -0x448(%rbp),%rax
   62a29:	je     62a7a <_IO_vfscanf+0x655a>
   62a2b:	movzbl -0x688(%rbp),%esi
   62a32:	lea    0x1(%rax),%rdx
   62a36:	movb   $0x1,-0x690(%rbp)
   62a3d:	movb   $0x1,-0x678(%rbp)
   62a44:	mov    %rdx,-0x450(%rbp)
   62a4b:	mov    %sil,(%rax)
   62a4e:	jmpq   62876 <_IO_vfscanf+0x6356>
   62a53:	mov    0x35d40e(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   62a5a:	mov    %r13,%r15
   62a5d:	movl   $0xffffffff,-0x5e8(%rbp)
   62a67:	mov    -0x600(%rbp),%r13d
   62a6e:	movl   $0xc,%fs:(%rax)
   62a75:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   62a7a:	mov    -0x6a4(%rbp),%esi
   62a80:	mov    -0x610(%rbp),%rdi
   62a87:	callq  5c4c0 <char_buffer_add_slow>
   62a8c:	movb   $0x1,-0x690(%rbp)
   62a93:	movb   $0x1,-0x678(%rbp)
   62a9a:	jmpq   62876 <_IO_vfscanf+0x6356>
   62a9f:	mov    -0x620(%rbp),%r15
   62aa6:	jmpq   6071f <_IO_vfscanf+0x41ff>
   62aab:	xor    %eax,%eax
   62aad:	test   %r12d,%r12d
   62ab0:	movsbl %r10b,%esi
   62ab4:	setg   %al
   62ab7:	sub    %eax,%r12d
   62aba:	mov    -0x450(%rbp),%rax
   62ac1:	cmp    -0x448(%rbp),%rax
   62ac8:	je     639bf <_IO_vfscanf+0x749f>
   62ace:	lea    0x1(%rax),%rdx
   62ad2:	mov    %rdx,-0x450(%rbp)
   62ad9:	mov    %r10b,(%rax)
   62adc:	test   %r12d,%r12d
   62adf:	je     639b1 <_IO_vfscanf+0x7491>
   62ae5:	mov    0x8(%r13),%rax
   62ae9:	cmp    0x10(%r13),%rax
   62aed:	jae    63992 <_IO_vfscanf+0x7472>
   62af3:	lea    0x1(%rax),%rdx
   62af7:	mov    %rdx,0x8(%r13)
   62afb:	movzbl (%rax),%eax
   62afe:	mov    -0x5f8(%rbp),%rsi
   62b05:	movzbl %al,%edx
   62b08:	mov    0x70(%rsi),%rcx
   62b0c:	cmpl   $0x6e,(%rcx,%rdx,4)
   62b10:	jne    63984 <_IO_vfscanf+0x7464>
   62b16:	xor    %edx,%edx
   62b18:	test   %r12d,%r12d
   62b1b:	movsbl %al,%esi
   62b1e:	setg   %dl
   62b21:	sub    %edx,%r12d
   62b24:	mov    -0x450(%rbp),%rdx
   62b2b:	cmp    -0x448(%rbp),%rdx
   62b32:	je     63973 <_IO_vfscanf+0x7453>
   62b38:	lea    0x1(%rdx),%rcx
   62b3c:	mov    %rcx,-0x450(%rbp)
   62b43:	mov    %al,(%rdx)
   62b45:	test   %r12d,%r12d
   62b48:	je     63965 <_IO_vfscanf+0x7445>
   62b4e:	mov    0x8(%r13),%rax
   62b52:	cmp    0x10(%r13),%rax
   62b56:	jae    63946 <_IO_vfscanf+0x7426>
   62b5c:	lea    0x1(%rax),%rdx
   62b60:	mov    %rdx,0x8(%r13)
   62b64:	movzbl (%rax),%eax
   62b67:	mov    -0x5f8(%rbp),%rdi
   62b6e:	movzbl %al,%edx
   62b71:	mov    0x70(%rdi),%rcx
   62b75:	cmpl   $0x69,(%rcx,%rdx,4)
   62b79:	jne    63938 <_IO_vfscanf+0x7418>
   62b7f:	xor    %edx,%edx
   62b81:	test   %r12d,%r12d
   62b84:	movsbl %al,%esi
   62b87:	setg   %dl
   62b8a:	sub    %edx,%r12d
   62b8d:	mov    -0x450(%rbp),%rdx
   62b94:	cmp    -0x448(%rbp),%rdx
   62b9b:	je     63927 <_IO_vfscanf+0x7407>
   62ba1:	lea    0x1(%rdx),%rcx
   62ba5:	mov    %rcx,-0x450(%rbp)
   62bac:	mov    %al,(%rdx)
   62bae:	test   %r12d,%r12d
   62bb1:	je     63919 <_IO_vfscanf+0x73f9>
   62bb7:	mov    0x8(%r13),%rax
   62bbb:	cmp    0x10(%r13),%rax
   62bbf:	jae    638fa <_IO_vfscanf+0x73da>
   62bc5:	lea    0x1(%rax),%rdx
   62bc9:	mov    %rdx,0x8(%r13)
   62bcd:	movzbl (%rax),%eax
   62bd0:	mov    -0x5f8(%rbp),%rsi
   62bd7:	movzbl %al,%edx
   62bda:	mov    0x70(%rsi),%rcx
   62bde:	cmpl   $0x74,(%rcx,%rdx,4)
   62be2:	jne    638ec <_IO_vfscanf+0x73cc>
   62be8:	xor    %edx,%edx
   62bea:	test   %r12d,%r12d
   62bed:	movsbl %al,%esi
   62bf0:	setg   %dl
   62bf3:	sub    %edx,%r12d
   62bf6:	mov    -0x450(%rbp),%rdx
   62bfd:	cmp    -0x448(%rbp),%rdx
   62c04:	je     638cd <_IO_vfscanf+0x73ad>
   62c0a:	lea    0x1(%rdx),%rcx
   62c0e:	mov    %rcx,-0x450(%rbp)
   62c15:	mov    %al,(%rdx)
   62c17:	test   %r12d,%r12d
   62c1a:	je     638bf <_IO_vfscanf+0x739f>
   62c20:	mov    0x8(%r13),%rax
   62c24:	cmp    0x10(%r13),%rax
   62c28:	jae    638a6 <_IO_vfscanf+0x7386>
   62c2e:	lea    0x1(%rax),%rdx
   62c32:	add    $0x7,%r14
   62c36:	mov    %rdx,0x8(%r13)
   62c3a:	movzbl (%rax),%r10d
   62c3e:	mov    -0x5f8(%rbp),%rdi
   62c45:	movzbl %r10b,%eax
   62c49:	mov    0x70(%rdi),%rdx
   62c4d:	cmpl   $0x79,(%rdx,%rax,4)
   62c51:	jne    63898 <_IO_vfscanf+0x7378>
   62c57:	mov    -0x450(%rbp),%rax
   62c5e:	cmp    -0x448(%rbp),%rax
   62c65:	movsbl %r10b,%esi
   62c69:	jne    5fa80 <_IO_vfscanf+0x3560>
   62c6f:	mov    -0x610(%rbp),%rdi
   62c76:	mov    %r10d,-0x600(%rbp)
   62c7d:	callq  5c4c0 <char_buffer_add_slow>
   62c82:	mov    -0x450(%rbp),%rax
   62c89:	mov    -0x600(%rbp),%r10d
   62c90:	jmpq   5eb27 <_IO_vfscanf+0x2607>
   62c95:	add    $0x8,%rsi
   62c99:	mov    $0x1,%r12d
   62c9f:	jmpq   61cce <_IO_vfscanf+0x57ae>
   62ca4:	test   %bl,%bl
   62ca6:	je     62cb0 <_IO_vfscanf+0x6790>
   62ca8:	mov    %edi,-0x520(%rbp)
   62cae:	mov    %edi,%eax
   62cb0:	test   %r12b,%r12b
   62cb3:	je     62cbc <_IO_vfscanf+0x679c>
   62cb5:	mov    %rsi,-0x518(%rbp)
   62cbc:	cmp    $0x2f,%eax
   62cbf:	ja     62d35 <_IO_vfscanf+0x6815>
   62cc1:	mov    %eax,%esi
   62cc3:	add    $0x8,%eax
   62cc6:	add    -0x510(%rbp),%rsi
   62ccd:	mov    %eax,-0x520(%rbp)
   62cd3:	jmpq   60cb0 <_IO_vfscanf+0x4790>
   62cd8:	lea    -0x2b(%r15),%edx
   62cdc:	and    $0xfffffffd,%edx
   62cdf:	jne    6266a <_IO_vfscanf+0x614a>
   62ce5:	cmp    -0x448(%rbp),%rax
   62cec:	movsbl %r15b,%esi
   62cf0:	je     62908 <_IO_vfscanf+0x63e8>
   62cf6:	lea    0x1(%rax),%rdx
   62cfa:	mov    %rdx,-0x450(%rbp)
   62d01:	mov    %r15b,(%rax)
   62d04:	jmpq   62876 <_IO_vfscanf+0x6356>
   62d09:	movb   $0x0,-0x678(%rbp)
   62d10:	jmpq   62876 <_IO_vfscanf+0x6356>
   62d15:	mov    %r15d,%r10d
   62d18:	mov    -0x698(%rbp),%r15
   62d1f:	jmpq   627ff <_IO_vfscanf+0x62df>
   62d24:	mov    -0x610(%rbp),%rdi
   62d2b:	callq  5c4c0 <char_buffer_add_slow>
   62d30:	jmpq   629ef <_IO_vfscanf+0x64cf>
   62d35:	mov    -0x518(%rbp),%rsi
   62d3c:	lea    0x8(%rsi),%rax
   62d40:	mov    %rax,-0x518(%rbp)
   62d47:	jmpq   60cb0 <_IO_vfscanf+0x4790>
   62d4c:	mov    -0x600(%rbp),%eax
   62d52:	xor    %ebx,%ebx
   62d54:	movl   $0x30,-0x678(%rbp)
   62d5e:	mov    %r15,-0x688(%rbp)
   62d65:	mov    %r12d,-0x690(%rbp)
   62d6c:	mov    %r10d,-0x6a4(%rbp)
   62d73:	mov    %r13,-0x6b8(%rbp)
   62d7a:	mov    %eax,-0x6b0(%rbp)
   62d80:	lea    -0x570(%rbp),%rax
   62d87:	mov    %rax,-0x628(%rbp)
   62d8e:	lea    -0x5d0(%rbp),%rax
   62d95:	mov    %rax,-0x6c0(%rbp)
   62d9c:	lea    -0x5c0(%rbp),%rax
   62da3:	mov    %rax,-0x698(%rbp)
   62daa:	mov    -0x648(%rbp),%rax
   62db1:	mov    -0x6a0(%rbp),%rsi
   62db8:	mov    -0x678(%rbp),%edi
   62dbe:	mov    0xe0(%rax,%rbx,1),%r15
   62dc6:	mov    -0x628(%rbp),%rax
   62dcd:	mov    %r15,(%rax,%rbx,1)
   62dd1:	callq  10b900 <__towctrans>
   62dd6:	mov    -0x6c0(%rbp),%rsi
   62ddd:	mov    -0x698(%rbp),%rdi
   62de4:	movq   $0x0,(%rsi)
   62deb:	mov    %rsi,%rdx
   62dee:	mov    %eax,%esi
   62df0:	callq  ac610 <c32rtomb>
   62df5:	cmp    $0xffffffffffffffff,%rax
   62df9:	mov    %rax,%r12
   62dfc:	je     62ebc <_IO_vfscanf+0x699c>
   62e02:	mov    -0x600(%rbp),%r9d
   62e09:	xor    %r13d,%r13d
   62e0c:	mov    %r15,%rdi
   62e0f:	test   %r9d,%r9d
   62e12:	jle    62e2c <_IO_vfscanf+0x690c>
   62e14:	xor    %esi,%esi
   62e16:	add    $0x1,%r13d
   62e1a:	callq  97340 <__rawmemchr>
   62e1f:	cmp    -0x600(%rbp),%r13d
   62e26:	lea    0x1(%rax),%rdi
   62e2a:	jne    62e14 <_IO_vfscanf+0x68f4>
   62e2c:	sub    %r15,%rdi
   62e2f:	mov    %r15,%rsi
   62e32:	add    $0x8,%rbx
   62e36:	lea    0x1f(%r12,%rdi,1),%rax
   62e3b:	mov    %rdi,%rdx
   62e3e:	and    $0xfffffffffffffff0,%rax
   62e42:	sub    %rax,%rsp
   62e45:	lea    0xf(%rsp),%rcx
   62e4a:	and    $0xfffffffffffffff0,%rcx
   62e4e:	mov    %rcx,%rdi
   62e51:	mov    %rcx,-0x6c8(%rbp)
   62e58:	callq  90920 <__GI___mempcpy>
   62e5d:	mov    -0x698(%rbp),%rsi
   62e64:	mov    %r12,%rdx
   62e67:	mov    %rax,%rdi
   62e6a:	callq  90920 <__GI___mempcpy>
   62e6f:	mov    -0x6c8(%rbp),%rcx
   62e76:	movb   $0x0,(%rax)
   62e79:	mov    -0x630(%rbp),%rax
   62e80:	addl   $0x1,-0x678(%rbp)
   62e87:	mov    %rcx,-0x8(%rbx,%rax,1)
   62e8c:	mov    -0x678(%rbp),%eax
   62e92:	cmp    $0x3a,%eax
   62e95:	jne    62daa <_IO_vfscanf+0x688a>
   62e9b:	mov    -0x688(%rbp),%r15
   62ea2:	mov    -0x690(%rbp),%r12d
   62ea9:	mov    -0x6a4(%rbp),%r10d
   62eb0:	mov    -0x6b8(%rbp),%r13
   62eb7:	jmpq   600c6 <_IO_vfscanf+0x3ba6>
   62ebc:	mov    -0x688(%rbp),%r15
   62ec3:	mov    -0x690(%rbp),%r12d
   62eca:	mov    -0x6a4(%rbp),%r10d
   62ed1:	mov    -0x6b8(%rbp),%r13
   62ed8:	movq   $0x0,-0x6a0(%rbp)
   62ee3:	jmpq   600c6 <_IO_vfscanf+0x3ba6>
   62ee8:	mov    -0x6a4(%rbp),%esi
   62eee:	mov    -0x610(%rbp),%rdi
   62ef5:	callq  5c4c0 <char_buffer_add_slow>
   62efa:	movzbl -0x628(%rbp),%eax
   62f01:	mov    %al,-0x690(%rbp)
   62f07:	mov    %al,-0x678(%rbp)
   62f0d:	jmpq   5eaad <_IO_vfscanf+0x258d>
   62f12:	mov    %r13,%r15
   62f15:	mov    $0x2,%r13d
   62f1b:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   62f20:	mov    -0x5a0(%rbp),%rax
   62f27:	lea    0x8(%rax),%rcx
   62f2b:	mov    %rcx,-0x5a0(%rbp)
   62f32:	jmpq   5f0b1 <_IO_vfscanf+0x2b91>
   62f37:	movl   $0x70,-0x6a4(%rbp)
   62f41:	movb   $0x70,-0x688(%rbp)
   62f48:	xor    %edx,%edx
   62f4a:	jmpq   5dbd2 <_IO_vfscanf+0x16b2>
   62f4f:	mov    %r13,%rdi
   62f52:	callq  7d720 <__uflow>
   62f57:	cmp    $0xffffffff,%eax
   62f5a:	mov    %eax,%r10d
   62f5d:	jne    619e7 <_IO_vfscanf+0x54c7>
   62f63:	mov    0x35cefe(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   62f6a:	mov    %fs:(%rax),%eax
   62f6d:	mov    %eax,-0x5e4(%rbp)
   62f73:	jmpq   619eb <_IO_vfscanf+0x54cb>
   62f78:	mov    0x35cee9(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   62f7f:	mov    -0x5e4(%rbp),%edi
   62f85:	mov    %edi,%fs:(%rax)
   62f88:	jmpq   619eb <_IO_vfscanf+0x54cb>
   62f8d:	mov    -0x610(%rbp),%rdi
   62f94:	movsbl %r10b,%esi
   62f98:	mov    %r10d,-0x600(%rbp)
   62f9f:	callq  5c4c0 <char_buffer_add_slow>
   62fa4:	mov    -0x600(%rbp),%r10d
   62fab:	jmpq   619b2 <_IO_vfscanf+0x5492>
   62fb0:	mov    %r13,%r15
   62fb3:	mov    $0x2,%r13d
   62fb9:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   62fbe:	mov    -0x5a0(%rbp),%rax
   62fc5:	lea    0x8(%rax),%rdx
   62fc9:	mov    %rdx,-0x5a0(%rbp)
   62fd0:	jmpq   5d40a <_IO_vfscanf+0xeea>
   62fd5:	mov    -0x608(%rbp),%r15
   62fdc:	lea    0x4(%rdx),%rsi
   62fe0:	addq   $0x1,-0x658(%rbp)
   62fe8:	mov    (%r15),%rdi
   62feb:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   62ff0:	test   %rax,%rax
   62ff3:	je     63016 <_IO_vfscanf+0x6af6>
   62ff5:	mov    -0x640(%rbp),%rdx
   62ffc:	mov    %rax,(%r15)
   62fff:	add    %rdx,%rax
   63002:	mov    %rax,-0x640(%rbp)
   63009:	jmpq   5d334 <_IO_vfscanf+0xe14>
   6300e:	mov    %r13,%r15
   63011:	jmpq   5e82e <_IO_vfscanf+0x230e>
   63016:	mov    %r13,%r15
   63019:	movl   $0xffffffff,-0x5e8(%rbp)
   63023:	mov    -0x600(%rbp),%r13d
   6302a:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   6302f:	mov    -0x5a0(%rbp),%rax
   63036:	lea    0x8(%rax),%rcx
   6303a:	mov    %rcx,-0x5a0(%rbp)
   63041:	jmpq   60bb1 <_IO_vfscanf+0x4691>
   63046:	mov    (%r12),%rdi
   6304a:	add    $0x1,%rbx
   6304e:	mov    %r10d,-0x658(%rbp)
   63055:	mov    %rbx,%rsi
   63058:	mov    %rcx,-0x638(%rbp)
   6305f:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   63064:	test   %rax,%rax
   63067:	je     630b7 <_IO_vfscanf+0x6b97>
   63069:	mov    -0x638(%rbp),%rcx
   63070:	mov    %rax,(%r12)
   63074:	mov    -0x658(%rbp),%r10d
   6307b:	add    %rcx,%rax
   6307e:	jmpq   60d93 <_IO_vfscanf+0x4873>
   63083:	mov    -0x610(%rbp),%rdi
   6308a:	movsbl %r12b,%esi
   6308e:	callq  5c4c0 <char_buffer_add_slow>
   63093:	movb   $0x1,-0x628(%rbp)
   6309a:	jmpq   5eaad <_IO_vfscanf+0x258d>
   6309f:	mov    %r12,%rdx
   630a2:	mov    %ebx,%r10d
   630a5:	mov    %r15d,%r12d
   630a8:	mov    %rax,%rbx
   630ab:	mov    -0x6a0(%rbp),%r15
   630b2:	jmpq   5e49e <_IO_vfscanf+0x1f7e>
   630b7:	mov    %r13,%r15
   630ba:	movl   $0xffffffff,-0x5e8(%rbp)
   630c4:	xor    %r13d,%r13d
   630c7:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   630cc:	add    $0x8,%rdx
   630d0:	mov    $0x1,%esi
   630d5:	jmpq   5ff15 <_IO_vfscanf+0x39f5>
   630da:	test   %dil,%dil
   630dd:	je     630e7 <_IO_vfscanf+0x6bc7>
   630df:	mov    %ecx,-0x520(%rbp)
   630e5:	mov    %ecx,%eax
   630e7:	test   %sil,%sil
   630ea:	je     630f3 <_IO_vfscanf+0x6bd3>
   630ec:	mov    %rdx,-0x518(%rbp)
   630f3:	cmp    $0x2f,%eax
   630f6:	ja     6315c <_IO_vfscanf+0x6c3c>
   630f8:	mov    %eax,%edx
   630fa:	add    -0x510(%rbp),%rdx
   63101:	add    $0x8,%eax
   63104:	mov    %eax,-0x520(%rbp)
   6310a:	mov    (%rdx),%rax
   6310d:	mov    %rax,-0x640(%rbp)
   63114:	jmpq   5f589 <_IO_vfscanf+0x3069>
   63119:	add    $0x8,%rsi
   6311d:	mov    $0x1,%r12d
   63123:	jmpq   61966 <_IO_vfscanf+0x5446>
   63128:	test   %bl,%bl
   6312a:	je     63134 <_IO_vfscanf+0x6c14>
   6312c:	mov    %edi,-0x520(%rbp)
   63132:	mov    %edi,%eax
   63134:	test   %r12b,%r12b
   63137:	je     63140 <_IO_vfscanf+0x6c20>
   63139:	mov    %rsi,-0x518(%rbp)
   63140:	cmp    $0x2f,%eax
   63143:	ja     63170 <_IO_vfscanf+0x6c50>
   63145:	mov    %eax,%esi
   63147:	add    $0x8,%eax
   6314a:	add    -0x510(%rbp),%rsi
   63151:	mov    %eax,-0x520(%rbp)
   63157:	jmpq   5ebe6 <_IO_vfscanf+0x26c6>
   6315c:	mov    -0x518(%rbp),%rdx
   63163:	lea    0x8(%rdx),%rax
   63167:	mov    %rax,-0x518(%rbp)
   6316e:	jmp    6310a <_IO_vfscanf+0x6bea>
   63170:	mov    -0x518(%rbp),%rsi
   63177:	lea    0x8(%rsi),%rax
   6317b:	mov    %rax,-0x518(%rbp)
   63182:	jmpq   5ebe6 <_IO_vfscanf+0x26c6>
   63187:	mov    %r13,%r15
   6318a:	mov    $0x2,%r13d
   63190:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   63195:	mov    -0x5a0(%rbp),%rax
   6319c:	lea    0x8(%rax),%rcx
   631a0:	mov    %rcx,-0x5a0(%rbp)
   631a7:	jmpq   5d5ec <_IO_vfscanf+0x10cc>
   631ac:	add    $0x8,%rcx
   631b0:	mov    $0x1,%ebx
   631b5:	jmpq   615da <_IO_vfscanf+0x50ba>
   631ba:	test   %dil,%dil
   631bd:	je     631c7 <_IO_vfscanf+0x6ca7>
   631bf:	mov    %esi,-0x520(%rbp)
   631c5:	mov    %esi,%eax
   631c7:	test   %bl,%bl
   631c9:	je     631d2 <_IO_vfscanf+0x6cb2>
   631cb:	mov    %rcx,-0x518(%rbp)
   631d2:	cmp    $0x2f,%eax
   631d5:	ja     632ae <_IO_vfscanf+0x6d8e>
   631db:	mov    %eax,%ecx
   631dd:	add    -0x510(%rbp),%rcx
   631e4:	add    $0x8,%eax
   631e7:	mov    %eax,-0x520(%rbp)
   631ed:	mov    (%rcx),%rax
   631f0:	mov    %rax,-0x668(%rbp)
   631f7:	jmpq   60bbb <_IO_vfscanf+0x469b>
   631fc:	add    $0x1,%rbx
   63200:	jmpq   5e8b8 <_IO_vfscanf+0x2398>
   63205:	mov    -0x678(%rbp),%r15
   6320c:	mov    %ebx,%r10d
   6320f:	jmpq   61d94 <_IO_vfscanf+0x5874>
   63214:	movl   $0xffffffff,-0x5e8(%rbp)
   6321e:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   63223:	add    $0x8,%rdx
   63227:	mov    $0x1,%esi
   6322c:	jmpq   5fcd1 <_IO_vfscanf+0x37b1>
   63231:	test   %dil,%dil
   63234:	je     6323e <_IO_vfscanf+0x6d1e>
   63236:	mov    %ecx,-0x520(%rbp)
   6323c:	mov    %ecx,%eax
   6323e:	test   %sil,%sil
   63241:	je     6324a <_IO_vfscanf+0x6d2a>
   63243:	mov    %rdx,-0x518(%rbp)
   6324a:	cmp    $0x2f,%eax
   6324d:	ja     632fe <_IO_vfscanf+0x6dde>
   63253:	mov    %eax,%edx
   63255:	add    -0x510(%rbp),%rdx
   6325c:	add    $0x8,%eax
   6325f:	mov    %eax,-0x520(%rbp)
   63265:	mov    (%rdx),%rax
   63268:	mov    %rax,-0x608(%rbp)
   6326f:	mov    %rax,%rbx
   63272:	jmpq   5d1f1 <_IO_vfscanf+0xcd1>
   63277:	add    $0x8,%rcx
   6327b:	mov    $0x1,%edi
   63280:	jmpq   61702 <_IO_vfscanf+0x51e2>
   63285:	mov    %r13,%rdi
   63288:	callq  7d720 <__uflow>
   6328d:	cmp    $0xffffffff,%eax
   63290:	mov    %eax,%r10d
   63293:	jne    5db92 <_IO_vfscanf+0x1672>
   63299:	mov    0x35cbc8(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   632a0:	mov    %fs:(%rax),%eax
   632a3:	mov    %eax,-0x5e4(%rbp)
   632a9:	jmpq   5db96 <_IO_vfscanf+0x1676>
   632ae:	mov    -0x518(%rbp),%rcx
   632b5:	lea    0x8(%rcx),%rax
   632b9:	mov    %rax,-0x518(%rbp)
   632c0:	jmpq   631ed <_IO_vfscanf+0x6ccd>
   632c5:	test   %bl,%bl
   632c7:	je     632d1 <_IO_vfscanf+0x6db1>
   632c9:	mov    %esi,-0x520(%rbp)
   632cf:	mov    %esi,%edx
   632d1:	test   %dil,%dil
   632d4:	je     632dd <_IO_vfscanf+0x6dbd>
   632d6:	mov    %rcx,-0x518(%rbp)
   632dd:	cmp    $0x2f,%edx
   632e0:	ja     63315 <_IO_vfscanf+0x6df5>
   632e2:	mov    %edx,%ecx
   632e4:	add    -0x510(%rbp),%rcx
   632eb:	add    $0x8,%edx
   632ee:	mov    %edx,-0x520(%rbp)
   632f4:	mov    (%rcx),%rdx
   632f7:	mov    %al,(%rdx)
   632f9:	jmpq   5da60 <_IO_vfscanf+0x1540>
   632fe:	mov    -0x518(%rbp),%rdx
   63305:	lea    0x8(%rdx),%rax
   63309:	mov    %rax,-0x518(%rbp)
   63310:	jmpq   63265 <_IO_vfscanf+0x6d45>
   63315:	mov    -0x518(%rbp),%rcx
   6331c:	lea    0x8(%rcx),%rdx
   63320:	mov    %rdx,-0x518(%rbp)
   63327:	jmp    632f4 <_IO_vfscanf+0x6dd4>
   63329:	mov    -0x5a0(%rbp),%rdx
   63330:	lea    0x8(%rdx),%rcx
   63334:	mov    %rcx,-0x5a0(%rbp)
   6333b:	jmpq   5f85a <_IO_vfscanf+0x333a>
   63340:	add    $0x8,%rdx
   63344:	mov    $0x1,%esi
   63349:	jmpq   6135b <_IO_vfscanf+0x4e3b>
   6334e:	test   %dil,%dil
   63351:	je     6335b <_IO_vfscanf+0x6e3b>
   63353:	mov    %ecx,-0x520(%rbp)
   63359:	mov    %ecx,%eax
   6335b:	test   %sil,%sil
   6335e:	je     63367 <_IO_vfscanf+0x6e47>
   63360:	mov    %rdx,-0x518(%rbp)
   63367:	cmp    $0x2f,%eax
   6336a:	ja     633fc <_IO_vfscanf+0x6edc>
   63370:	mov    %eax,%edx
   63372:	add    -0x510(%rbp),%rdx
   63379:	add    $0x8,%eax
   6337c:	mov    %eax,-0x520(%rbp)
   63382:	mov    (%rdx),%rax
   63385:	jmpq   5f8a4 <_IO_vfscanf+0x3384>
   6338a:	mov    -0x5a0(%rbp),%rax
   63391:	lea    0x8(%rax),%rdx
   63395:	mov    %rdx,-0x5a0(%rbp)
   6339c:	jmpq   5f57f <_IO_vfscanf+0x305f>
   633a1:	add    $0x8,%rdx
   633a5:	mov    $0x1,%esi
   633aa:	jmpq   61586 <_IO_vfscanf+0x5066>
   633af:	test   %dil,%dil
   633b2:	je     633bc <_IO_vfscanf+0x6e9c>
   633b4:	mov    %ecx,-0x520(%rbp)
   633ba:	mov    %ecx,%eax
   633bc:	test   %sil,%sil
   633bf:	je     633c8 <_IO_vfscanf+0x6ea8>
   633c1:	mov    %rdx,-0x518(%rbp)
   633c8:	cmp    $0x2f,%eax
   633cb:	ja     63413 <_IO_vfscanf+0x6ef3>
   633cd:	mov    %eax,%edx
   633cf:	add    -0x510(%rbp),%rdx
   633d6:	add    $0x8,%eax
   633d9:	mov    %eax,-0x520(%rbp)
   633df:	mov    (%rdx),%rax
   633e2:	mov    %rax,-0x608(%rbp)
   633e9:	jmpq   5d414 <_IO_vfscanf+0xef4>
   633ee:	mov    %r13,%r15
   633f1:	mov    $0x2,%r13d
   633f7:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   633fc:	mov    -0x518(%rbp),%rdx
   63403:	lea    0x8(%rdx),%rax
   63407:	mov    %rax,-0x518(%rbp)
   6340e:	jmpq   63382 <_IO_vfscanf+0x6e62>
   63413:	mov    -0x518(%rbp),%rdx
   6341a:	lea    0x8(%rdx),%rax
   6341e:	mov    %rax,-0x518(%rbp)
   63425:	jmp    633df <_IO_vfscanf+0x6ebf>
   63427:	mov    -0x658(%rbp),%rax
   6342e:	lea    0x0(,%rax,8),%rsi
   63436:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   6343b:	test   %rax,%rax
   6343e:	je     6347d <_IO_vfscanf+0x6f5d>
   63440:	mov    -0x608(%rbp),%rdi
   63447:	mov    -0x658(%rbp),%rsi
   6344e:	mov    %rax,(%rdi)
   63451:	add    %rbx,%rax
   63454:	mov    %rax,-0x640(%rbp)
   6345b:	mov    %rsi,%rax
   6345e:	add    %rsi,%rax
   63461:	mov    %rax,-0x658(%rbp)
   63468:	jmpq   5ed70 <_IO_vfscanf+0x2850>
   6346d:	fstp   %st(0)
   6346f:	mov    %r13,%r15
   63472:	mov    $0x2,%r13d
   63478:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   6347d:	mov    -0x608(%rbp),%rax
   63484:	lea    0x4(%rbx),%rsi
   63488:	addq   $0x1,-0x658(%rbp)
   63490:	mov    (%rax),%rdi
   63493:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   63498:	test   %rax,%rax
   6349b:	je     63502 <_IO_vfscanf+0x6fe2>
   6349d:	mov    -0x608(%rbp),%rsi
   634a4:	mov    %rax,(%rsi)
   634a7:	add    %rbx,%rax
   634aa:	mov    %rax,-0x640(%rbp)
   634b1:	jmpq   5ed70 <_IO_vfscanf+0x2850>
   634b6:	add    $0x8,%rcx
   634ba:	mov    $0x1,%ebx
   634bf:	jmpq   61752 <_IO_vfscanf+0x5232>
   634c4:	test   %dil,%dil
   634c7:	je     634d1 <_IO_vfscanf+0x6fb1>
   634c9:	mov    %esi,-0x520(%rbp)
   634cf:	mov    %esi,%eax
   634d1:	test   %bl,%bl
   634d3:	je     634dc <_IO_vfscanf+0x6fbc>
   634d5:	mov    %rcx,-0x518(%rbp)
   634dc:	cmp    $0x2f,%eax
   634df:	ja     6354b <_IO_vfscanf+0x702b>
   634e1:	mov    %eax,%ecx
   634e3:	add    -0x510(%rbp),%rcx
   634ea:	add    $0x8,%eax
   634ed:	mov    %eax,-0x520(%rbp)
   634f3:	mov    (%rcx),%rax
   634f6:	mov    %rax,-0x640(%rbp)
   634fd:	jmpq   60eaa <_IO_vfscanf+0x498a>
   63502:	mov    -0x5ec(%rbp),%r12d
   63509:	mov    %r13,%r15
   6350c:	mov    -0x600(%rbp),%r13d
   63513:	and    $0x2000,%r12d
   6351a:	jne    6355f <_IO_vfscanf+0x703f>
   6351c:	mov    -0x608(%rbp),%rax
   63523:	addl   $0x1,-0x5e8(%rbp)
   6352a:	mov    $0x2,%r13d
   63530:	movq   $0x0,-0x608(%rbp)
   6353b:	mov    (%rax),%rax
   6353e:	movl   $0x0,-0x4(%rax,%rbx,1)
   63546:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   6354b:	mov    -0x518(%rbp),%rcx
   63552:	lea    0x8(%rcx),%rax
   63556:	mov    %rax,-0x518(%rbp)
   6355d:	jmp    634f3 <_IO_vfscanf+0x6fd3>
   6355f:	movl   $0xffffffff,-0x5e8(%rbp)
   63569:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   6356e:	add    $0x8,%rcx
   63572:	mov    $0x1,%ebx
   63577:	jmpq   611d6 <_IO_vfscanf+0x4cb6>
   6357c:	test   %dil,%dil
   6357f:	je     63589 <_IO_vfscanf+0x7069>
   63581:	mov    %esi,-0x520(%rbp)
   63587:	mov    %esi,%eax
   63589:	test   %bl,%bl
   6358b:	je     63594 <_IO_vfscanf+0x7074>
   6358d:	mov    %rcx,-0x518(%rbp)
   63594:	cmp    $0x2f,%eax
   63597:	ja     635e2 <_IO_vfscanf+0x70c2>
   63599:	mov    %eax,%ecx
   6359b:	add    -0x510(%rbp),%rcx
   635a2:	add    $0x8,%eax
   635a5:	mov    %eax,-0x520(%rbp)
   635ab:	mov    (%rcx),%rax
   635ae:	mov    %rax,-0x608(%rbp)
   635b5:	mov    %rax,%rbx
   635b8:	jmpq   5f0be <_IO_vfscanf+0x2b9e>
   635bd:	mov    -0x5a0(%rbp),%rdx
   635c4:	lea    0x8(%rdx),%rcx
   635c8:	mov    %rcx,-0x5a0(%rbp)
   635cf:	jmpq   5da5a <_IO_vfscanf+0x153a>
   635d4:	add    $0x8,%rcx
   635d8:	mov    $0x1,%edi
   635dd:	jmpq   613aa <_IO_vfscanf+0x4e8a>
   635e2:	mov    -0x518(%rbp),%rcx
   635e9:	lea    0x8(%rcx),%rax
   635ed:	mov    %rax,-0x518(%rbp)
   635f4:	jmp    635ab <_IO_vfscanf+0x708b>
   635f6:	mov    -0x5a0(%rbp),%rax
   635fd:	lea    0x8(%rax),%rdx
   63601:	mov    %rdx,-0x5a0(%rbp)
   63608:	jmpq   60c07 <_IO_vfscanf+0x46e7>
   6360d:	mov    %r13,%rdi
   63610:	callq  7d720 <__uflow>
   63615:	cmp    $0xffffffff,%eax
   63618:	jne    5fd34 <_IO_vfscanf+0x3814>
   6361e:	mov    %r13,%r15
   63621:	mov    $0x2,%r13d
   63627:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   6362c:	add    $0x8,%rsi
   63630:	mov    $0x1,%r12d
   63636:	jmpq   61c7e <_IO_vfscanf+0x575e>
   6363b:	test   %bl,%bl
   6363d:	je     63647 <_IO_vfscanf+0x7127>
   6363f:	mov    %edi,-0x520(%rbp)
   63645:	mov    %edi,%eax
   63647:	test   %r12b,%r12b
   6364a:	je     63653 <_IO_vfscanf+0x7133>
   6364c:	mov    %rsi,-0x518(%rbp)
   63653:	cmp    $0x2f,%eax
   63656:	ja     636a5 <_IO_vfscanf+0x7185>
   63658:	mov    %eax,%esi
   6365a:	add    $0x8,%eax
   6365d:	add    -0x510(%rbp),%rsi
   63664:	mov    %eax,-0x520(%rbp)
   6366a:	jmpq   608ea <_IO_vfscanf+0x43ca>
   6366f:	mov    -0x620(%rbp),%rsi
   63676:	jmpq   5f1d9 <_IO_vfscanf+0x2cb9>
   6367b:	mov    -0x5a0(%rbp),%rax
   63682:	lea    0x8(%rax),%rdx
   63686:	mov    %rdx,-0x5a0(%rbp)
   6368d:	jmpq   61493 <_IO_vfscanf+0x4f73>
   63692:	mov    %rax,%r14
   63695:	jmpq   5c832 <_IO_vfscanf+0x312>
   6369a:	mov    %rbx,%rsi
   6369d:	mov    %eax,%r12d
   636a0:	jmpq   5f1d9 <_IO_vfscanf+0x2cb9>
   636a5:	mov    -0x518(%rbp),%rsi
   636ac:	lea    0x8(%rsi),%rax
   636b0:	mov    %rax,-0x518(%rbp)
   636b7:	jmpq   608ea <_IO_vfscanf+0x43ca>
   636bc:	mov    -0x610(%rbp),%rdi
   636c3:	movsbl %r10b,%esi
   636c7:	callq  5c4c0 <char_buffer_add_slow>
   636cc:	jmpq   5fd12 <_IO_vfscanf+0x37f2>
   636d1:	add    $0x8,%rcx
   636d5:	mov    $0x1,%edi
   636da:	jmpq   60cf6 <_IO_vfscanf+0x47d6>
   636df:	test   %bl,%bl
   636e1:	je     636eb <_IO_vfscanf+0x71cb>
   636e3:	mov    %esi,-0x520(%rbp)
   636e9:	mov    %esi,%edx
   636eb:	test   %dil,%dil
   636ee:	je     636f7 <_IO_vfscanf+0x71d7>
   636f0:	mov    %rcx,-0x518(%rbp)
   636f7:	cmp    $0x2f,%edx
   636fa:	ja     6371f <_IO_vfscanf+0x71ff>
   636fc:	mov    %edx,%ecx
   636fe:	add    -0x510(%rbp),%rcx
   63705:	add    $0x8,%edx
   63708:	mov    %edx,-0x520(%rbp)
   6370e:	mov    (%rcx),%rdx
   63711:	jmpq   5da5d <_IO_vfscanf+0x153d>
   63716:	add    $0x1,%r14
   6371a:	jmpq   5cc8d <_IO_vfscanf+0x76d>
   6371f:	mov    -0x518(%rbp),%rcx
   63726:	lea    0x8(%rcx),%rdx
   6372a:	mov    %rdx,-0x518(%rbp)
   63731:	jmp    6370e <_IO_vfscanf+0x71ee>
   63733:	mov    %r13,%r15
   63736:	mov    $0x2,%r13d
   6373c:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   63741:	mov    -0x5a0(%rbp),%rax
   63748:	lea    0x8(%rax),%rdx
   6374c:	mov    %rdx,-0x5a0(%rbp)
   63753:	jmpq   5d1e4 <_IO_vfscanf+0xcc4>
   63758:	add    $0x8,%rdx
   6375c:	mov    $0x1,%esi
   63761:	jmpq   5fc79 <_IO_vfscanf+0x3759>
   63766:	test   %dil,%dil
   63769:	je     63773 <_IO_vfscanf+0x7253>
   6376b:	mov    %ecx,-0x520(%rbp)
   63771:	mov    %ecx,%eax
   63773:	test   %sil,%sil
   63776:	je     6377f <_IO_vfscanf+0x725f>
   63778:	mov    %rdx,-0x518(%rbp)
   6377f:	cmp    $0x2f,%eax
   63782:	ja     63865 <_IO_vfscanf+0x7345>
   63788:	mov    %eax,%edx
   6378a:	add    -0x510(%rbp),%rdx
   63791:	add    $0x8,%eax
   63794:	mov    %eax,-0x520(%rbp)
   6379a:	mov    (%rdx),%rax
   6379d:	mov    %rax,-0x608(%rbp)
   637a4:	mov    %rax,%rbx
   637a7:	jmpq   5d018 <_IO_vfscanf+0xaf8>
   637ac:	test   %bl,%bl
   637ae:	je     637b8 <_IO_vfscanf+0x7298>
   637b0:	mov    %esi,-0x520(%rbp)
   637b6:	mov    %esi,%edx
   637b8:	test   %dil,%dil
   637bb:	je     637c4 <_IO_vfscanf+0x72a4>
   637bd:	mov    %rcx,-0x518(%rbp)
   637c4:	cmp    $0x2f,%edx
   637c7:	ja     63ac1 <_IO_vfscanf+0x75a1>
   637cd:	mov    %edx,%ecx
   637cf:	add    -0x510(%rbp),%rcx
   637d6:	add    $0x8,%edx
   637d9:	mov    %edx,-0x520(%rbp)
   637df:	mov    (%rcx),%rdx
   637e2:	jmpq   5f85d <_IO_vfscanf+0x333d>
   637e7:	mov    -0x670(%rbp),%rbx
   637ee:	jmpq   5dd70 <_IO_vfscanf+0x1850>
   637f3:	mov    %r13,%r15
   637f6:	mov    $0x2,%r13d
   637fc:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   63801:	mov    -0x610(%rbp),%rdi
   63808:	movsbl %al,%esi
   6380b:	callq  5c4c0 <char_buffer_add_slow>
   63810:	jmpq   5fd78 <_IO_vfscanf+0x3858>
   63815:	mov    %r13,%r15
   63818:	mov    $0x2,%r13d
   6381e:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   63823:	lea    0x1(%r14),%rbx
   63827:	jmpq   5e87e <_IO_vfscanf+0x235e>
   6382c:	mov    -0x5a0(%rbp),%rsi
   63833:	lea    0x8(%rsi),%rax
   63837:	mov    %rax,-0x5a0(%rbp)
   6383e:	jmpq   608ea <_IO_vfscanf+0x43ca>
   63843:	mov    -0x5a0(%rbp),%rsi
   6384a:	lea    0x8(%rsi),%rax
   6384e:	mov    %rax,-0x5a0(%rbp)
   63855:	jmpq   60cb0 <_IO_vfscanf+0x4790>
   6385a:	movslq %eax,%rdx
   6385d:	add    %rdx,%rdx
   63860:	jmpq   5e667 <_IO_vfscanf+0x2147>
   63865:	mov    -0x518(%rbp),%rdx
   6386c:	lea    0x8(%rdx),%rax
   63870:	mov    %rax,-0x518(%rbp)
   63877:	jmpq   6379a <_IO_vfscanf+0x727a>
   6387c:	mov    -0x620(%rbp),%rsi
   63883:	xor    %eax,%eax
   63885:	jmpq   5fba6 <_IO_vfscanf+0x3686>
   6388a:	add    $0x8,%rcx
   6388e:	mov    $0x1,%edi
   63893:	jmpq   5f8fc <_IO_vfscanf+0x33dc>
   63898:	mov    %r13,%r15
   6389b:	mov    $0x2,%r13d
   638a1:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   638a6:	mov    %r13,%rdi
   638a9:	callq  7d720 <__uflow>
   638ae:	cmp    $0xffffffff,%eax
   638b1:	mov    %eax,%r10d
   638b4:	je     638de <_IO_vfscanf+0x73be>
   638b6:	add    $0x7,%r14
   638ba:	jmpq   62c3e <_IO_vfscanf+0x671e>
   638bf:	mov    %r13,%r15
   638c2:	mov    $0x2,%r13d
   638c8:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   638cd:	mov    -0x610(%rbp),%rdi
   638d4:	callq  5c4c0 <char_buffer_add_slow>
   638d9:	jmpq   62c17 <_IO_vfscanf+0x66f7>
   638de:	mov    %r13,%r15
   638e1:	mov    $0x2,%r13d
   638e7:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   638ec:	mov    %r13,%r15
   638ef:	mov    $0x2,%r13d
   638f5:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   638fa:	mov    %r13,%rdi
   638fd:	callq  7d720 <__uflow>
   63902:	cmp    $0xffffffff,%eax
   63905:	jne    62bd0 <_IO_vfscanf+0x66b0>
   6390b:	mov    %r13,%r15
   6390e:	mov    $0x2,%r13d
   63914:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   63919:	mov    %r13,%r15
   6391c:	mov    $0x2,%r13d
   63922:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   63927:	mov    -0x610(%rbp),%rdi
   6392e:	callq  5c4c0 <char_buffer_add_slow>
   63933:	jmpq   62bae <_IO_vfscanf+0x668e>
   63938:	mov    %r13,%r15
   6393b:	mov    $0x2,%r13d
   63941:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   63946:	mov    %r13,%rdi
   63949:	callq  7d720 <__uflow>
   6394e:	cmp    $0xffffffff,%eax
   63951:	jne    62b67 <_IO_vfscanf+0x6647>
   63957:	mov    %r13,%r15
   6395a:	mov    $0x2,%r13d
   63960:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   63965:	mov    %r13,%r15
   63968:	mov    $0x2,%r13d
   6396e:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   63973:	mov    -0x610(%rbp),%rdi
   6397a:	callq  5c4c0 <char_buffer_add_slow>
   6397f:	jmpq   62b45 <_IO_vfscanf+0x6625>
   63984:	mov    %r13,%r15
   63987:	mov    $0x2,%r13d
   6398d:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   63992:	mov    %r13,%rdi
   63995:	callq  7d720 <__uflow>
   6399a:	cmp    $0xffffffff,%eax
   6399d:	jne    62afe <_IO_vfscanf+0x65de>
   639a3:	mov    %r13,%r15
   639a6:	mov    $0x2,%r13d
   639ac:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   639b1:	mov    %r13,%r15
   639b4:	mov    $0x2,%r13d
   639ba:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   639bf:	mov    -0x610(%rbp),%rdi
   639c6:	callq  5c4c0 <char_buffer_add_slow>
   639cb:	jmpq   62adc <_IO_vfscanf+0x65bc>
   639d0:	mov    -0x5a0(%rbp),%rax
   639d7:	lea    0x8(%rax),%rdx
   639db:	mov    %rdx,-0x5a0(%rbp)
   639e2:	jmpq   5d57c <_IO_vfscanf+0x105c>
   639e7:	mov    %r15,%rcx
   639ea:	mov    %r13d,%r10d
   639ed:	mov    -0x6b8(%rbp),%r15
   639f4:	mov    %r12,%r13
   639f7:	mov    -0x6a4(%rbp),%r12d
   639fe:	mov    -0x620(%rbp),%rax
   63a05:	cmp    %rax,%rcx
   63a08:	jbe    60b3c <_IO_vfscanf+0x461c>
   63a0e:	mov    %rcx,%rdi
   63a11:	sub    %rax,%rdi
   63a14:	sub    %rdi,%rbx
   63a17:	cmp    $0xffffffff,%r10d
   63a1b:	mov    %rbx,-0x450(%rbp)
   63a22:	je     63a42 <_IO_vfscanf+0x7522>
   63a24:	movzbl %r10b,%esi
   63a28:	mov    %r13,%rdi
   63a2b:	mov    %rcx,-0x600(%rbp)
   63a32:	callq  7e5a0 <_IO_sputbackc>
   63a37:	mov    -0x600(%rbp),%rcx
   63a3e:	sub    $0x1,%r14
   63a42:	lea    -0x1(%rcx),%rdx
   63a46:	cmp    %rdx,-0x620(%rbp)
   63a4d:	jae    63a9a <_IO_vfscanf+0x757a>
   63a4f:	mov    %rdx,%rbx
   63a52:	movzbl (%rbx),%esi
   63a55:	mov    %r13,%rdi
   63a58:	mov    %rdx,-0x628(%rbp)
   63a5f:	mov    %rcx,-0x600(%rbp)
   63a66:	sub    $0x1,%rbx
   63a6a:	callq  7e5a0 <_IO_sputbackc>
   63a6f:	cmp    %rbx,-0x620(%rbp)
   63a76:	mov    -0x600(%rbp),%rcx
   63a7d:	mov    -0x628(%rbp),%rdx
   63a84:	jne    63a52 <_IO_vfscanf+0x7532>
   63a86:	mov    -0x620(%rbp),%rax
   63a8d:	sub    %rcx,%rax
   63a90:	add    $0x1,%rax
   63a94:	add    %rax,%rdx
   63a97:	add    %rax,%r14
   63a9a:	movzbl (%rdx),%r10d
   63a9e:	mov    -0x450(%rbp),%rbx
   63aa5:	jmpq   60b3c <_IO_vfscanf+0x461c>
   63aaa:	mov    -0x5a0(%rbp),%rax
   63ab1:	lea    0x8(%rax),%rdx
   63ab5:	mov    %rdx,-0x5a0(%rbp)
   63abc:	jmpq   60ab8 <_IO_vfscanf+0x4598>
   63ac1:	mov    -0x518(%rbp),%rcx
   63ac8:	lea    0x8(%rcx),%rdx
   63acc:	mov    %rdx,-0x518(%rbp)
   63ad3:	jmpq   637df <_IO_vfscanf+0x72bf>
   63ad8:	mov    %r13,%rdi
   63adb:	callq  7d720 <__uflow>
   63ae0:	cmp    $0xffffffff,%eax
   63ae3:	mov    %eax,%r10d
   63ae6:	jne    5f95c <_IO_vfscanf+0x343c>
   63aec:	mov    0x35c375(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   63af3:	movl   $0x10,-0x600(%rbp)
   63afd:	mov    %fs:(%rax),%eax
   63b00:	mov    %eax,-0x5e4(%rbp)
   63b06:	jmpq   5d8b4 <_IO_vfscanf+0x1394>
   63b0b:	mov    -0x5a0(%rbp),%rax
   63b12:	lea    0x8(%rax),%rdx
   63b16:	mov    %rdx,-0x5a0(%rbp)
   63b1d:	jmpq   5f5d7 <_IO_vfscanf+0x30b7>
   63b22:	mov    -0x638(%rbp),%r15
   63b29:	mov    %r12d,%r10d
   63b2c:	jmpq   5ede6 <_IO_vfscanf+0x28c6>
   63b31:	mov    -0x5a0(%rbp),%rsi
   63b38:	lea    0x8(%rsi),%rax
   63b3c:	mov    %rax,-0x5a0(%rbp)
   63b43:	jmpq   5ebe6 <_IO_vfscanf+0x26c6>
   63b48:	add    $0x8,%rdx
   63b4c:	mov    $0x1,%esi
   63b51:	jmpq   5ffa7 <_IO_vfscanf+0x3a87>
   63b56:	test   %dil,%dil
   63b59:	je     63b63 <_IO_vfscanf+0x7643>
   63b5b:	mov    %ecx,-0x520(%rbp)
   63b61:	mov    %ecx,%eax
   63b63:	test   %sil,%sil
   63b66:	je     63b6f <_IO_vfscanf+0x764f>
   63b68:	mov    %rdx,-0x518(%rbp)
   63b6f:	cmp    $0x2f,%eax
   63b72:	ja     63be2 <_IO_vfscanf+0x76c2>
   63b74:	mov    %eax,%edx
   63b76:	add    -0x510(%rbp),%rdx
   63b7d:	add    $0x8,%eax
   63b80:	mov    %eax,-0x520(%rbp)
   63b86:	mov    (%rdx),%rax
   63b89:	mov    %rax,-0x640(%rbp)
   63b90:	jmpq   5f5e1 <_IO_vfscanf+0x30c1>
   63b95:	add    $0x8,%rdx
   63b99:	mov    $0x1,%edi
   63b9e:	jmpq   612ca <_IO_vfscanf+0x4daa>
   63ba3:	test   %sil,%sil
   63ba6:	je     63bb0 <_IO_vfscanf+0x7690>
   63ba8:	mov    %ecx,-0x520(%rbp)
   63bae:	mov    %ecx,%eax
   63bb0:	test   %dil,%dil
   63bb3:	je     63bbc <_IO_vfscanf+0x769c>
   63bb5:	mov    %rdx,-0x518(%rbp)
   63bbc:	cmp    $0x2f,%eax
   63bbf:	ja     63bf6 <_IO_vfscanf+0x76d6>
   63bc1:	mov    %eax,%edx
   63bc3:	add    -0x510(%rbp),%rdx
   63bca:	add    $0x8,%eax
   63bcd:	mov    %eax,-0x520(%rbp)
   63bd3:	mov    (%rdx),%rax
   63bd6:	mov    %rax,-0x668(%rbp)
   63bdd:	jmpq   60ac2 <_IO_vfscanf+0x45a2>
   63be2:	mov    -0x518(%rbp),%rdx
   63be9:	lea    0x8(%rdx),%rax
   63bed:	mov    %rax,-0x518(%rbp)
   63bf4:	jmp    63b86 <_IO_vfscanf+0x7666>
   63bf6:	mov    -0x518(%rbp),%rdx
   63bfd:	lea    0x8(%rdx),%rax
   63c01:	mov    %rax,-0x518(%rbp)
   63c08:	jmp    63bd3 <_IO_vfscanf+0x76b3>
   63c0a:	add    $0x8,%rdx
   63c0e:	mov    $0x1,%edi
   63c13:	jmpq   6127a <_IO_vfscanf+0x4d5a>
   63c18:	test   %sil,%sil
   63c1b:	je     63c25 <_IO_vfscanf+0x7705>
   63c1d:	mov    %ecx,-0x520(%rbp)
   63c23:	mov    %ecx,%eax
   63c25:	test   %dil,%dil
   63c28:	je     63c31 <_IO_vfscanf+0x7711>
   63c2a:	mov    %rdx,-0x518(%rbp)
   63c31:	cmp    $0x2f,%eax
   63c34:	ja     63cbe <_IO_vfscanf+0x779e>
   63c3a:	mov    %eax,%edx
   63c3c:	add    -0x510(%rbp),%rdx
   63c43:	add    $0x8,%eax
   63c46:	mov    %eax,-0x520(%rbp)
   63c4c:	mov    (%rdx),%rax
   63c4f:	mov    %rax,-0x608(%rbp)
   63c56:	jmpq   5df38 <_IO_vfscanf+0x1a18>
   63c5b:	mov    -0x608(%rbp),%rax
   63c62:	lea    0x4(%rdx),%rsi
   63c66:	mov    %r10d,-0x640(%rbp)
   63c6d:	addq   $0x1,-0x658(%rbp)
   63c75:	mov    %rdx,-0x600(%rbp)
   63c7c:	mov    (%rax),%rdi
   63c7f:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   63c84:	test   %rax,%rax
   63c87:	mov    -0x600(%rbp),%rdx
   63c8e:	mov    -0x640(%rbp),%r10d
   63c95:	je     63cd5 <_IO_vfscanf+0x77b5>
   63c97:	mov    -0x608(%rbp),%rsi
   63c9e:	mov    %rax,(%rsi)
   63ca1:	add    %rdx,%rax
   63ca4:	mov    %rax,-0x640(%rbp)
   63cab:	jmpq   5e8df <_IO_vfscanf+0x23bf>
   63cb0:	add    $0x8,%rcx
   63cb4:	mov    $0x1,%edi
   63cb9:	jmpq   5efde <_IO_vfscanf+0x2abe>
   63cbe:	mov    -0x518(%rbp),%rdx
   63cc5:	lea    0x8(%rdx),%rax
   63cc9:	mov    %rax,-0x518(%rbp)
   63cd0:	jmpq   63c4c <_IO_vfscanf+0x772c>
   63cd5:	mov    -0x5ec(%rbp),%r12d
   63cdc:	mov    %r13,%r15
   63cdf:	and    $0x2000,%r12d
   63ce6:	jne    63d9b <_IO_vfscanf+0x787b>
   63cec:	mov    -0x608(%rbp),%rax
   63cf3:	addl   $0x1,-0x5e8(%rbp)
   63cfa:	mov    $0x2,%r13d
   63d00:	movq   $0x0,-0x608(%rbp)
   63d0b:	mov    (%rax),%rax
   63d0e:	movl   $0x0,-0x4(%rax,%rdx,1)
   63d16:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   63d1b:	mov    -0x610(%rbp),%rdi
   63d22:	movsbl %r10b,%esi
   63d26:	mov    %r10d,-0x600(%rbp)
   63d2d:	callq  5c4c0 <char_buffer_add_slow>
   63d32:	mov    -0x600(%rbp),%r10d
   63d39:	jmpq   5fde5 <_IO_vfscanf+0x38c5>
   63d3e:	add    $0x8,%rdx
   63d42:	mov    $0x1,%esi
   63d47:	jmpq   61a3a <_IO_vfscanf+0x551a>
   63d4c:	test   %dil,%dil
   63d4f:	je     63d59 <_IO_vfscanf+0x7839>
   63d51:	mov    %ecx,-0x520(%rbp)
   63d57:	mov    %ecx,%eax
   63d59:	test   %sil,%sil
   63d5c:	je     63d65 <_IO_vfscanf+0x7845>
   63d5e:	mov    %rdx,-0x518(%rbp)
   63d65:	cmp    $0x2f,%eax
   63d68:	ja     63dad <_IO_vfscanf+0x788d>
   63d6a:	mov    %eax,%edx
   63d6c:	add    -0x510(%rbp),%rdx
   63d73:	add    $0x8,%eax
   63d76:	mov    %eax,-0x520(%rbp)
   63d7c:	mov    (%rdx),%rax
   63d7f:	jmpq   60fb5 <_IO_vfscanf+0x4a95>
   63d84:	mov    -0x5a0(%rbp),%rax
   63d8b:	lea    0x8(%rax),%rdx
   63d8f:	mov    %rdx,-0x5a0(%rbp)
   63d96:	jmpq   60fb2 <_IO_vfscanf+0x4a92>
   63d9b:	xor    %r13d,%r13d
   63d9e:	movl   $0xffffffff,-0x5e8(%rbp)
   63da8:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   63dad:	mov    -0x518(%rbp),%rdx
   63db4:	lea    0x8(%rdx),%rax
   63db8:	mov    %rax,-0x518(%rbp)
   63dbf:	jmp    63d7c <_IO_vfscanf+0x785c>
   63dc1:	mov    %eax,%esi
   63dc3:	jmpq   5dd0b <_IO_vfscanf+0x17eb>
   63dc8:	add    $0x1,%r14
   63dcc:	jmpq   5c72c <_IO_vfscanf+0x20c>
   63dd1:	add    $0x8,%rcx
   63dd5:	mov    $0x1,%ebx
   63dda:	jmpq   61107 <_IO_vfscanf+0x4be7>
   63ddf:	test   %dil,%dil
   63de2:	je     63dec <_IO_vfscanf+0x78cc>
   63de4:	mov    %esi,-0x520(%rbp)
   63dea:	mov    %esi,%eax
   63dec:	test   %bl,%bl
   63dee:	je     63df7 <_IO_vfscanf+0x78d7>
   63df0:	mov    %rcx,-0x518(%rbp)
   63df7:	cmp    $0x2f,%eax
   63dfa:	ja     63e53 <_IO_vfscanf+0x7933>
   63dfc:	mov    %eax,%ecx
   63dfe:	add    -0x510(%rbp),%rcx
   63e05:	add    $0x8,%eax
   63e08:	mov    %eax,-0x520(%rbp)
   63e0e:	mov    (%rcx),%rax
   63e11:	mov    %rax,-0x608(%rbp)
   63e18:	mov    %rax,%rbx
   63e1b:	jmpq   5d5f9 <_IO_vfscanf+0x10d9>
   63e20:	mov    %r13,%r15
   63e23:	mov    $0x2,%r13d
   63e29:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   63e2e:	pxor   %xmm0,%xmm0
   63e32:	movaps %xmm0,-0x450(%rbp)
   63e39:	jmpq   60648 <_IO_vfscanf+0x4128>
   63e3e:	mov    -0x610(%rbp),%rdi
   63e45:	movsbl %r12b,%esi
   63e49:	callq  5c4c0 <char_buffer_add_slow>
   63e4e:	jmpq   5eaad <_IO_vfscanf+0x258d>
   63e53:	mov    -0x518(%rbp),%rcx
   63e5a:	lea    0x8(%rcx),%rax
   63e5e:	mov    %rax,-0x518(%rbp)
   63e65:	jmp    63e0e <_IO_vfscanf+0x78ee>
   63e67:	movl   $0xffffffff,-0x5e8(%rbp)
   63e71:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   63e76:	mov    -0x5a0(%rbp),%rdx
   63e7d:	lea    0x8(%rdx),%rcx
   63e81:	mov    %rcx,-0x5a0(%rbp)
   63e88:	jmpq   60a7f <_IO_vfscanf+0x455f>
   63e8d:	mov    %r13,%r15
   63e90:	mov    $0x2,%r13d
   63e96:	jmpq   5c9b8 <_IO_vfscanf+0x498>
   63e9b:	mov    -0x5a0(%rbp),%rax
   63ea2:	lea    0x8(%rax),%rdx
   63ea6:	mov    %rdx,-0x5a0(%rbp)
   63ead:	jmpq   5df2e <_IO_vfscanf+0x1a0e>
   63eb2:	test   %bl,%bl
   63eb4:	je     63ebe <_IO_vfscanf+0x799e>
   63eb6:	mov    %esi,-0x520(%rbp)
   63ebc:	mov    %esi,%edx
   63ebe:	test   %dil,%dil
   63ec1:	je     63eca <_IO_vfscanf+0x79aa>
   63ec3:	mov    %rcx,-0x518(%rbp)
   63eca:	cmp    $0x2f,%edx
   63ecd:	ja     63f02 <_IO_vfscanf+0x79e2>
   63ecf:	mov    %edx,%ecx
   63ed1:	add    -0x510(%rbp),%rcx
   63ed8:	add    $0x8,%edx
   63edb:	mov    %edx,-0x520(%rbp)
   63ee1:	mov    (%rcx),%rdx
   63ee4:	mov    %eax,(%rdx)
   63ee6:	jmpq   5da60 <_IO_vfscanf+0x1540>
   63eeb:	mov    -0x5a0(%rbp),%rax
   63ef2:	lea    0x8(%rax),%rcx
   63ef6:	mov    %rcx,-0x5a0(%rbp)
   63efd:	jmpq   60ea0 <_IO_vfscanf+0x4980>
   63f02:	mov    -0x518(%rbp),%rcx
   63f09:	lea    0x8(%rcx),%rdx
   63f0d:	mov    %rdx,-0x518(%rbp)
   63f14:	jmp    63ee1 <_IO_vfscanf+0x79c1>
   63f16:	add    $0x8,%rdx
   63f1a:	mov    $0x1,%esi
   63f1f:	jmpq   61c2b <_IO_vfscanf+0x570b>
   63f24:	test   %dil,%dil
   63f27:	je     63f31 <_IO_vfscanf+0x7a11>
   63f29:	mov    %ecx,-0x520(%rbp)
   63f2f:	mov    %ecx,%eax
   63f31:	test   %sil,%sil
   63f34:	je     63f3d <_IO_vfscanf+0x7a1d>
   63f36:	mov    %rdx,-0x518(%rbp)
   63f3d:	cmp    $0x2f,%eax
   63f40:	ja     63f5c <_IO_vfscanf+0x7a3c>
   63f42:	mov    %eax,%edx
   63f44:	add    -0x510(%rbp),%rdx
   63f4b:	add    $0x8,%eax
   63f4e:	mov    %eax,-0x520(%rbp)
   63f54:	mov    (%rdx),%rax
   63f57:	jmpq   61496 <_IO_vfscanf+0x4f76>
   63f5c:	mov    -0x518(%rbp),%rdx
   63f63:	lea    0x8(%rdx),%rax
   63f67:	mov    %rax,-0x518(%rbp)
   63f6e:	jmp    63f54 <_IO_vfscanf+0x7a34>

0000000000063fe0 <_IO_vfwscanf>:
   63fe0:	push   %rbp
   63fe1:	mov    %rsp,%rbp
   63fe4:	push   %r15
   63fe6:	push   %r14
   63fe8:	lea    -0x450(%rbp),%rax
   63fef:	push   %r13
   63ff1:	push   %r12
   63ff3:	push   %rbx
   63ff4:	mov    %rsi,%r13
   63ff7:	mov    $0x1,%esi
   63ffc:	mov    %rdi,%r15
   63fff:	sub    $0x588,%rsp
   64006:	mov    %rax,-0x528(%rbp)
   6400d:	add    $0x20,%rax
   64011:	mov    %rax,-0x440(%rbp)
   64018:	mov    (%rdx),%rax
   6401b:	mov    %rdx,-0x580(%rbp)
   64022:	mov    %rcx,-0x540(%rbp)
   64029:	movq   $0x400,-0x438(%rbp)
   64034:	mov    %rax,-0x4d8(%rbp)
   6403b:	mov    0x8(%rdx),%rax
   6403f:	mov    %rax,-0x4d0(%rbp)
   64046:	mov    0x10(%rdx),%rax
   6404a:	mov    %rax,-0x4c8(%rbp)
   64051:	callq  76d20 <_IO_fwide>
   64056:	cmp    $0x1,%eax
   64059:	mov    %eax,-0x508(%rbp)
   6405f:	jne    648c0 <_IO_vfwscanf+0x8e0>
   64065:	mov    (%r15),%eax
   64068:	test   $0x4,%al
   6406a:	jne    660d9 <_IO_vfwscanf+0x20f9>
   64070:	test   %r13,%r13
   64073:	je     67167 <_IO_vfwscanf+0x3187>
   64079:	mov    0x35bd30(%rip),%rsi        # 3bfdb0 <_DYNAMIC+0x250>
   64080:	mov    %fs:(%rsi),%rdx
   64084:	mov    0x8(%rdx),%rdx
   64088:	mov    0x60(%rdx),%edi
   6408b:	mov    0x58(%rdx),%esi
   6408e:	mov    %edi,-0x518(%rbp)
   64094:	mov    0x361656(%rip),%edi        # 3c56f0 <__libc_pthread_functions_init>
   6409a:	mov    %esi,-0x548(%rbp)
   640a0:	test   %edi,%edi
   640a2:	mov    %edi,-0x544(%rbp)
   640a8:	jne    64728 <_IO_vfwscanf+0x748>
   640ae:	mov    0x35beb3(%rip),%rdx        # 3bff68 <_DYNAMIC+0x408>
   640b5:	mov    %r15,-0x4b8(%rbp)
   640bc:	mov    %rdx,-0x4c0(%rbp)
   640c3:	and    $0x8000,%eax
   640c8:	je     64340 <_IO_vfwscanf+0x360>
   640ce:	lea    -0x4f0(%rbp),%rax
   640d5:	xor    %r14d,%r14d
   640d8:	xor    %r8d,%r8d
   640db:	mov    %r14,-0x510(%rbp)
   640e2:	movl   $0x0,-0x500(%rbp)
   640ec:	mov    %r15,%r14
   640ef:	mov    %rax,-0x590(%rbp)
   640f6:	lea    -0x4a0(%rbp),%rax
   640fd:	movl   $0x0,-0x514(%rbp)
   64107:	movq   $0x0,-0x550(%rbp)
   64112:	movq   $0x0,-0x520(%rbp)
   6411d:	mov    %r8d,%r15d
   64120:	movq   $0x0,-0x578(%rbp)
   6412b:	movq   $0x0,-0x570(%rbp)
   64136:	movq   $0x0,-0x4f8(%rbp)
   64141:	movl   $0x0,-0x504(%rbp)
   6414b:	mov    %rax,-0x588(%rbp)
   64152:	mov    0x0(%r13),%r12d
   64156:	test   %r12d,%r12d
   64159:	je     66080 <_IO_vfwscanf+0x20a0>
   6415f:	cmp    $0x25,%r12d
   64163:	lea    0x4(%r13),%rbx
   64167:	je     64208 <_IO_vfwscanf+0x228>
   6416d:	mov    %r12d,%edi
   64170:	callq  10b4f0 <iswspace>
   64175:	test   %eax,%eax
   64177:	jne    641f0 <_IO_vfwscanf+0x210>
   64179:	cmp    $0xffffffff,%r15d
   6417d:	je     64760 <_IO_vfwscanf+0x780>
   64183:	mov    0xa0(%r14),%rax
   6418a:	test   %rax,%rax
   6418d:	je     64890 <_IO_vfwscanf+0x8b0>
   64193:	mov    (%rax),%rdx
   64196:	cmp    0x8(%rax),%rdx
   6419a:	jae    64890 <_IO_vfwscanf+0x8b0>
   641a0:	mov    (%rdx),%r15d
   641a3:	lea    0x4(%rdx),%rcx
   641a7:	mov    %rcx,(%rax)
   641aa:	cmp    $0xffffffff,%r15d
   641ae:	je     648a8 <_IO_vfwscanf+0x8c8>
   641b4:	addq   $0x1,-0x4f8(%rbp)
   641bc:	mov    -0x500(%rbp),%edx
   641c2:	mov    -0x4f8(%rbp),%rax
   641c9:	test   %edx,%edx
   641cb:	mov    %rax,%r13
   641ce:	jne    642e0 <_IO_vfwscanf+0x300>
   641d4:	cmp    %r12d,%r15d
   641d7:	jne    64a10 <_IO_vfwscanf+0xa30>
   641dd:	movl   $0x0,-0x500(%rbp)
   641e7:	jmp    641fa <_IO_vfwscanf+0x21a>
   641e9:	nopl   0x0(%rax)
   641f0:	movl   $0x1,-0x500(%rbp)
   641fa:	mov    %rbx,%r13
   641fd:	jmpq   64152 <_IO_vfwscanf+0x172>
   64202:	nopw   0x0(%rax,%rax,1)
   64208:	mov    -0x438(%rbp),%rdx
   6420f:	mov    -0x440(%rbp),%rax
   64216:	and    $0xfffffffffffffffc,%rdx
   6421a:	mov    %rax,-0x450(%rbp)
   64221:	add    %rdx,%rax
   64224:	mov    %rax,-0x448(%rbp)
   6422b:	mov    0x4(%r13),%eax
   6422f:	sub    $0x30,%eax
   64232:	cmp    $0x9,%eax
   64235:	mov    %eax,%esi
   64237:	mov    %eax,-0x530(%rbp)
   6423d:	jbe    643f0 <_IO_vfwscanf+0x410>
   64243:	movl   $0x0,-0x530(%rbp)
   6424d:	mov    -0x518(%rbp),%eax
   64253:	xor    %r13d,%r13d
   64256:	movabs $0x400000009,%rcx
   64260:	test   %eax,%eax
   64262:	jne    643a4 <_IO_vfwscanf+0x3c4>
   64268:	nopl   0x0(%rax,%rax,1)
   64270:	mov    (%rbx),%edx
   64272:	lea    -0x27(%rdx),%eax
   64275:	cmp    $0x22,%eax
   64278:	jbe    64648 <_IO_vfwscanf+0x668>
   6427e:	lea    -0x30(%rdx),%eax
   64281:	mov    $0xffffffff,%r12d
   64287:	cmp    $0x9,%eax
   6428a:	ja     642b2 <_IO_vfwscanf+0x2d2>
   6428c:	xor    %r12d,%r12d
   6428f:	nop
   64290:	lea    (%r12,%r12,4),%edx
   64294:	add    $0x4,%rbx
   64298:	lea    (%rax,%rdx,2),%r12d
   6429c:	mov    (%rbx),%edx
   6429e:	lea    -0x30(%rdx),%eax
   642a1:	cmp    $0x9,%eax
   642a4:	jbe    64290 <_IO_vfwscanf+0x2b0>
   642a6:	test   %r12d,%r12d
   642a9:	mov    $0xffffffff,%eax
   642ae:	cmove  %eax,%r12d
   642b2:	lea    0x4(%rbx),%rax
   642b6:	mov    %rax,-0x558(%rbp)
   642bd:	lea    -0x4c(%rdx),%eax
   642c0:	cmp    $0x2e,%eax
   642c3:	ja     64a40 <_IO_vfwscanf+0xa60>
   642c9:	lea    0x11f958(%rip),%rcx        # 183c28 <jump_table+0x468>
   642d0:	movslq (%rcx,%rax,4),%rax
   642d4:	add    %rcx,%rax
   642d7:	jmpq   *%rax
   642d9:	nopl   0x0(%rax)
   642e0:	mov    %r15d,%edi
   642e3:	callq  10b4f0 <iswspace>
   642e8:	test   %eax,%eax
   642ea:	je     6432d <_IO_vfwscanf+0x34d>
   642ec:	mov    0xa0(%r14),%rax
   642f3:	test   %rax,%rax
   642f6:	je     646d0 <_IO_vfwscanf+0x6f0>
   642fc:	mov    (%rax),%rdx
   642ff:	cmp    0x8(%rax),%rdx
   64303:	jae    646d0 <_IO_vfwscanf+0x6f0>
   64309:	lea    0x4(%rdx),%rcx
   6430d:	mov    (%rdx),%r15d
   64310:	mov    %rcx,(%rax)
   64313:	cmp    $0xffffffff,%r15d
   64317:	je     64690 <_IO_vfwscanf+0x6b0>
   6431d:	mov    %r15d,%edi
   64320:	add    $0x1,%r13
   64324:	callq  10b4f0 <iswspace>
   64329:	test   %eax,%eax
   6432b:	jne    642ec <_IO_vfwscanf+0x30c>
   6432d:	mov    %r13,-0x4f8(%rbp)
   64334:	jmpq   641d4 <_IO_vfwscanf+0x1f4>
   64339:	nopl   0x0(%rax)
   64340:	mov    0x88(%r15),%rdx
   64347:	mov    %fs:0x10,%r8
   64350:	cmp    0x8(%rdx),%r8
   64354:	je     64392 <_IO_vfwscanf+0x3b2>
   64356:	mov    $0x1,%esi
   6435b:	cmpl   $0x0,0x36139e(%rip)        # 3c5700 <__libc_multiple_threads>
   64362:	je     6436c <_IO_vfwscanf+0x38c>
   64364:	lock cmpxchg %esi,(%rdx)
   64368:	jne    64371 <_IO_vfwscanf+0x391>
   6436a:	jmp    64387 <_IO_vfwscanf+0x3a7>
   6436c:	cmpxchg %esi,(%rdx)
   6436f:	je     64387 <_IO_vfwscanf+0x3a7>
   64371:	lea    (%rdx),%rdi
   64374:	sub    $0x80,%rsp
   6437b:	callq  115f40 <__lll_lock_wait_private>
   64380:	add    $0x80,%rsp
   64387:	mov    0x88(%r15),%rdx
   6438e:	mov    %r8,0x8(%rdx)
   64392:	addl   $0x1,0x4(%rdx)
   64396:	jmpq   640ce <_IO_vfwscanf+0xee>
   6439b:	nopl   0x0(%rax,%rax,1)
   643a0:	or     $0x8,%r13d
   643a4:	mov    (%rbx),%edx
   643a6:	lea    -0x27(%rdx),%eax
   643a9:	cmp    $0x22,%eax
   643ac:	ja     6427e <_IO_vfwscanf+0x29e>
   643b2:	bt     %rax,%rcx
   643b6:	jae    6427e <_IO_vfwscanf+0x29e>
   643bc:	add    $0x4,%rbx
   643c0:	cmp    $0x2a,%edx
   643c3:	je     643a0 <_IO_vfwscanf+0x3c0>
   643c5:	cmp    $0x49,%edx
   643c8:	je     64670 <_IO_vfwscanf+0x690>
   643ce:	mov    %r13d,%eax
   643d1:	or     $0x80,%al
   643d3:	cmp    $0x27,%edx
   643d6:	mov    (%rbx),%edx
   643d8:	cmove  %eax,%r13d
   643dc:	lea    -0x27(%rdx),%eax
   643df:	cmp    $0x22,%eax
   643e2:	ja     6427e <_IO_vfwscanf+0x29e>
   643e8:	jmp    643b2 <_IO_vfwscanf+0x3d2>
   643ea:	nopw   0x0(%rax,%rax,1)
   643f0:	mov    0x8(%r13),%eax
   643f4:	lea    0x8(%r13),%rbx
   643f8:	lea    -0x30(%rax),%ecx
   643fb:	mov    %eax,%edx
   643fd:	cmp    $0x9,%ecx
   64400:	ja     64425 <_IO_vfwscanf+0x445>
   64402:	mov    %esi,%ecx
   64404:	nopl   0x0(%rax)
   64408:	lea    (%rcx,%rcx,4),%edx
   6440b:	add    $0x4,%rbx
   6440f:	lea    -0x30(%rax,%rdx,2),%ecx
   64413:	mov    (%rbx),%eax
   64415:	lea    -0x30(%rax),%esi
   64418:	mov    %eax,%edx
   6441a:	cmp    $0x9,%esi
   6441d:	jbe    64408 <_IO_vfwscanf+0x428>
   6441f:	mov    %ecx,-0x530(%rbp)
   64425:	cmp    $0x24,%eax
   64428:	je     648d0 <_IO_vfwscanf+0x8f0>
   6442e:	mov    -0x530(%rbp),%r12d
   64435:	xor    %r13d,%r13d
   64438:	movl   $0x0,-0x530(%rbp)
   64442:	jmpq   642a6 <_IO_vfwscanf+0x2c6>
   64447:	nopw   0x0(%rax,%rax,1)
   64450:	mov    0x4(%rbx),%edx
   64453:	or     $0x1,%r13d
   64457:	test   %edx,%edx
   64459:	je     649f0 <_IO_vfwscanf+0xa10>
   6445f:	mov    -0x558(%rbp),%rax
   64466:	lea    0x4(%rax),%rbx
   6446a:	mov    -0x500(%rbp),%eax
   64470:	test   %eax,%eax
   64472:	jne    64480 <_IO_vfwscanf+0x4a0>
   64474:	lea    -0x43(%rdx),%eax
   64477:	cmp    $0x2b,%eax
   6447a:	jbe    647fe <_IO_vfwscanf+0x81e>
   64480:	mov    0x35b9e1(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   64487:	mov    %rbx,-0x500(%rbp)
   6448e:	mov    %r12d,-0x560(%rbp)
   64495:	mov    -0x4f8(%rbp),%rbx
   6449c:	mov    %r15d,%r12d
   6449f:	mov    %edx,-0x568(%rbp)
   644a5:	mov    %fs:(%rax),%esi
   644a8:	mov    %rax,-0x538(%rbp)
   644af:	movl   $0x0,%fs:(%rax)
   644b6:	mov    %esi,-0x598(%rbp)
   644bc:	jmp    644d7 <_IO_vfwscanf+0x4f7>
   644be:	xchg   %ax,%ax
   644c0:	mov    %r12d,%edi
   644c3:	lea    0x1(%rbx),%r15
   644c7:	callq  10b4f0 <iswspace>
   644cc:	test   %eax,%eax
   644ce:	je     648e0 <_IO_vfwscanf+0x900>
   644d4:	mov    %r15,%rbx
   644d7:	cmp    $0xffffffff,%r12d
   644db:	je     64790 <_IO_vfwscanf+0x7b0>
   644e1:	mov    0xa0(%r14),%rax
   644e8:	test   %rax,%rax
   644eb:	je     646c0 <_IO_vfwscanf+0x6e0>
   644f1:	mov    (%rax),%rdx
   644f4:	cmp    0x8(%rax),%rdx
   644f8:	jae    646c0 <_IO_vfwscanf+0x6e0>
   644fe:	lea    0x4(%rdx),%rcx
   64502:	mov    (%rdx),%r12d
   64505:	mov    %rcx,(%rax)
   64508:	cmp    $0xffffffff,%r12d
   6450c:	jne    644c0 <_IO_vfwscanf+0x4e0>
   6450e:	mov    -0x538(%rbp),%rax
   64515:	mov    %rbx,-0x4f8(%rbp)
   6451c:	mov    -0x560(%rbp),%r12d
   64523:	mov    -0x500(%rbp),%rbx
   6452a:	mov    -0x568(%rbp),%edx
   64530:	mov    %fs:(%rax),%eax
   64533:	cmp    $0x4,%eax
   64536:	mov    %eax,-0x514(%rbp)
   6453c:	je     6456b <_IO_vfwscanf+0x58b>
   6453e:	mov    $0xffffffff,%edi
   64543:	mov    %edx,-0x500(%rbp)
   64549:	callq  10b4f0 <iswspace>
   6454e:	test   %eax,%eax
   64550:	mov    -0x500(%rbp),%edx
   64556:	je     649a0 <_IO_vfwscanf+0x9c0>
   6455c:	mov    -0x538(%rbp),%rax
   64563:	mov    %fs:(%rax),%eax
   64566:	cmp    $0x4,%eax
   64569:	jne    6453e <_IO_vfwscanf+0x55e>
   6456b:	mov    -0x504(%rbp),%eax
   64571:	mov    %r14,%r15
   64574:	mov    -0x510(%rbp),%r14
   6457b:	test   %eax,%eax
   6457d:	mov    %eax,%ebx
   6457f:	jne    64590 <_IO_vfwscanf+0x5b0>
   64581:	mov    $0xffffffff,%ebx
   64586:	mov    %ebx,-0x504(%rbp)
   6458c:	nopl   0x0(%rax)
   64590:	testl  $0x8000,(%r15)
   64597:	jne    645d8 <_IO_vfwscanf+0x5f8>
   64599:	mov    0x88(%r15),%rdx
   645a0:	subl   $0x1,0x4(%rdx)
   645a4:	jne    645d8 <_IO_vfwscanf+0x5f8>
   645a6:	movq   $0x0,0x8(%rdx)
   645ae:	cmpl   $0x0,0x36114b(%rip)        # 3c5700 <__libc_multiple_threads>
   645b5:	je     645be <_IO_vfwscanf+0x5de>
   645b7:	lock decl (%rdx)
   645ba:	jne    645c2 <_IO_vfwscanf+0x5e2>
   645bc:	jmp    645d8 <_IO_vfwscanf+0x5f8>
   645be:	decl   (%rdx)
   645c0:	je     645d8 <_IO_vfwscanf+0x5f8>
   645c2:	lea    (%rdx),%rdi
   645c5:	sub    $0x80,%rsp
   645cc:	callq  115f70 <__lll_unlock_wake_private>
   645d1:	add    $0x80,%rsp
   645d8:	mov    -0x544(%rbp),%eax
   645de:	test   %eax,%eax
   645e0:	jne    64700 <_IO_vfwscanf+0x720>
   645e6:	mov    -0x528(%rbp),%rax
   645ed:	mov    -0x440(%rbp),%rdi
   645f4:	add    $0x20,%rax
   645f8:	cmp    %rax,%rdi
   645fb:	je     64602 <_IO_vfwscanf+0x622>
   645fd:	callq  1f9c0 <*ABS*+0x911b0@plt+0x40>
   64602:	mov    -0x540(%rbp),%rax
   64609:	test   %rax,%rax
   6460c:	je     64616 <_IO_vfwscanf+0x636>
   6460e:	mov    -0x508(%rbp),%edi
   64614:	or     %edi,(%rax)
   64616:	cmpl   $0xffffffff,-0x504(%rbp)
   6461d:	je     64950 <_IO_vfwscanf+0x970>
   64623:	cmpq   $0x0,-0x520(%rbp)
   6462b:	jne    649d0 <_IO_vfwscanf+0x9f0>
   64631:	lea    -0x28(%rbp),%rsp
   64635:	mov    %ebx,%eax
   64637:	pop    %rbx
   64638:	pop    %r12
   6463a:	pop    %r13
   6463c:	pop    %r14
   6463e:	pop    %r15
   64640:	pop    %rbp
   64641:	retq   
   64642:	nopw   0x0(%rax,%rax,1)
   64648:	bt     %rax,%rcx
   6464c:	jae    6427e <_IO_vfwscanf+0x29e>
   64652:	add    $0x4,%rbx
   64656:	cmp    $0x2a,%edx
   64659:	je     64680 <_IO_vfwscanf+0x6a0>
   6465b:	mov    %r13d,%eax
   6465e:	or     $0x4,%ah
   64661:	cmp    $0x49,%edx
   64664:	cmove  %eax,%r13d
   64668:	jmpq   64270 <_IO_vfwscanf+0x290>
   6466d:	nopl   (%rax)
   64670:	or     $0x400,%r13d
   64677:	jmpq   643a4 <_IO_vfwscanf+0x3c4>
   6467c:	nopl   0x0(%rax)
   64680:	or     $0x8,%r13d
   64684:	jmpq   64270 <_IO_vfwscanf+0x290>
   64689:	nopl   0x0(%rax)
   64690:	mov    -0x504(%rbp),%eax
   64696:	mov    %r15d,%r13d
   64699:	mov    %r14,%r15
   6469c:	mov    -0x510(%rbp),%r14
   646a3:	test   %eax,%eax
   646a5:	je     646e0 <_IO_vfwscanf+0x700>
   646a7:	mov    %eax,%ebx
   646a9:	mov    -0x500(%rbp),%eax
   646af:	mov    %eax,-0x508(%rbp)
   646b5:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   646ba:	nopw   0x0(%rax,%rax,1)
   646c0:	mov    %r14,%rdi
   646c3:	callq  73620 <__wuflow>
   646c8:	mov    %eax,%r12d
   646cb:	jmpq   64508 <_IO_vfwscanf+0x528>
   646d0:	mov    %r14,%rdi
   646d3:	callq  73620 <__wuflow>
   646d8:	mov    %eax,%r15d
   646db:	jmpq   64313 <_IO_vfwscanf+0x333>
   646e0:	mov    -0x500(%rbp),%eax
   646e6:	mov    %r13d,%ebx
   646e9:	mov    %r13d,-0x504(%rbp)
   646f0:	mov    %eax,-0x508(%rbp)
   646f6:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   646fb:	nopl   0x0(%rax,%rax,1)
   64700:	mov    0x360fb1(%rip),%rax        # 3c56b8 <__libc_pthread_functions+0x178>
   64707:	lea    -0x4c0(%rbp),%rdi
   6470e:	xor    %esi,%esi
   64710:	ror    $0x11,%rax
   64714:	xor    %fs:0x30,%rax
   6471d:	callq  *%rax
   6471f:	jmpq   645e6 <_IO_vfwscanf+0x606>
   64724:	nopl   0x0(%rax)
   64728:	mov    0x360f81(%rip),%rax        # 3c56b0 <__libc_pthread_functions+0x170>
   6472f:	lea    -0x4c0(%rbp),%rdi
   64736:	mov    %r15,%rdx
   64739:	ror    $0x11,%rax
   6473d:	xor    %fs:0x30,%rax
   64746:	mov    0x35b81b(%rip),%rsi        # 3bff68 <_DYNAMIC+0x408>
   6474d:	callq  *%rax
   6474f:	mov    (%r15),%eax
   64752:	jmpq   640c3 <_IO_vfwscanf+0xe3>
   64757:	nopw   0x0(%rax,%rax,1)
   64760:	mov    0x35b701(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   64767:	mov    -0x514(%rbp),%esi
   6476d:	mov    %r14,%r15
   64770:	mov    -0x510(%rbp),%r14
   64777:	mov    %esi,%fs:(%rax)
   6477a:	mov    -0x504(%rbp),%eax
   64780:	test   %eax,%eax
   64782:	je     647b0 <_IO_vfwscanf+0x7d0>
   64784:	mov    -0x504(%rbp),%ebx
   6478a:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6478f:	nop
   64790:	mov    %rbx,-0x4f8(%rbp)
   64797:	mov    -0x560(%rbp),%r12d
   6479e:	mov    -0x500(%rbp),%rbx
   647a5:	mov    -0x568(%rbp),%edx
   647ab:	jmpq   6455c <_IO_vfwscanf+0x57c>
   647b0:	mov    $0xffffffff,%ebx
   647b5:	mov    %ebx,-0x504(%rbp)
   647bb:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   647c0:	mov    0x4(%rbx),%eax
   647c3:	mov    %eax,%ecx
   647c5:	and    $0xfffffff7,%ecx
   647c8:	cmp    $0x53,%ecx
   647cb:	je     660b0 <_IO_vfwscanf+0x20d0>
   647d1:	cmp    $0x73,%eax
   647d4:	je     660b0 <_IO_vfwscanf+0x20d0>
   647da:	mov    -0x500(%rbp),%ecx
   647e0:	mov    %rbx,%rax
   647e3:	mov    -0x558(%rbp),%rbx
   647ea:	mov    %rax,-0x558(%rbp)
   647f1:	test   %ecx,%ecx
   647f3:	jne    64480 <_IO_vfwscanf+0x4a0>
   647f9:	mov    $0x1e,%eax
   647fe:	movabs $0x80101000001,%rcx
   64808:	bt     %rax,%rcx
   6480c:	jae    64480 <_IO_vfwscanf+0x4a0>
   64812:	sub    $0x43,%edx
   64815:	cmp    $0x2b,%edx
   64818:	ja     65942 <_IO_vfwscanf+0x1962>
   6481e:	lea    0x11f4bf(%rip),%rcx        # 183ce4 <jump_table+0x524>
   64825:	movslq (%rcx,%rdx,4),%rax
   64829:	add    %rcx,%rax
   6482c:	jmpq   *%rax
   6482e:	xchg   %ax,%ax
   64830:	mov    0x4(%rbx),%edx
   64833:	cmp    $0x6c,%edx
   64836:	je     66476 <_IO_vfwscanf+0x2496>
   6483c:	or     $0x2000,%r13d
   64843:	jmpq   64457 <_IO_vfwscanf+0x477>
   64848:	nopl   0x0(%rax,%rax,1)
   64850:	mov    0x4(%rbx),%edx
   64853:	cmp    $0x6c,%edx
   64856:	je     6645f <_IO_vfwscanf+0x247f>
   6485c:	or     $0x1,%r13d
   64860:	jmpq   64457 <_IO_vfwscanf+0x477>
   64865:	nopl   (%rax)
   64868:	mov    0x4(%rbx),%edx
   6486b:	cmp    $0x68,%edx
   6486e:	je     66445 <_IO_vfwscanf+0x2465>
   64874:	or     $0x4,%r13d
   64878:	jmpq   64457 <_IO_vfwscanf+0x477>
   6487d:	nopl   (%rax)
   64880:	or     $0x3,%r13d
   64884:	mov    0x4(%rbx),%edx
   64887:	jmpq   64457 <_IO_vfwscanf+0x477>
   6488c:	nopl   0x0(%rax)
   64890:	mov    %r14,%rdi
   64893:	callq  73620 <__wuflow>
   64898:	mov    %eax,%r15d
   6489b:	cmp    $0xffffffff,%r15d
   6489f:	jne    641b4 <_IO_vfwscanf+0x1d4>
   648a5:	nopl   (%rax)
   648a8:	mov    %r14,%r15
   648ab:	mov    -0x510(%rbp),%r14
   648b2:	jmpq   6477a <_IO_vfwscanf+0x79a>
   648b7:	nopw   0x0(%rax,%rax,1)
   648c0:	mov    $0xffffffff,%ebx
   648c5:	jmpq   64631 <_IO_vfwscanf+0x651>
   648ca:	nopw   0x0(%rax,%rax,1)
   648d0:	add    $0x4,%rbx
   648d4:	jmpq   6424d <_IO_vfwscanf+0x26d>
   648d9:	nopl   0x0(%rax)
   648e0:	mov    -0x598(%rbp),%edi
   648e6:	mov    %rbx,-0x4f8(%rbp)
   648ed:	mov    -0x500(%rbp),%rbx
   648f4:	mov    %eax,-0x500(%rbp)
   648fa:	mov    -0x538(%rbp),%rax
   64901:	mov    -0x568(%rbp),%edx
   64907:	mov    %r15,-0x568(%rbp)
   6490e:	mov    %r12d,%r15d
   64911:	mov    -0x560(%rbp),%r12d
   64918:	mov    %r15d,%esi
   6491b:	mov    %edi,%fs:(%rax)
   6491e:	mov    %r14,%rdi
   64921:	mov    %edx,-0x560(%rbp)
   64927:	callq  74430 <_IO_sputbackwc>
   6492c:	mov    -0x560(%rbp),%edx
   64932:	sub    $0x25,%edx
   64935:	cmp    $0x53,%edx
   64938:	ja     65e09 <_IO_vfwscanf+0x1e29>
   6493e:	lea    0x11f44f(%rip),%rcx        # 183d94 <jump_table+0x5d4>
   64945:	movslq (%rcx,%rdx,4),%rax
   64949:	add    %rcx,%rax
   6494c:	jmpq   *%rax
   6494e:	xchg   %ax,%ax
   64950:	test   %r14,%r14
   64953:	je     64631 <_IO_vfwscanf+0x651>
   64959:	nopl   0x0(%rax)
   64960:	xor    %r12d,%r12d
   64963:	cmpq   $0x0,(%r14)
   64967:	je     64992 <_IO_vfwscanf+0x9b2>
   64969:	nopl   0x0(%rax)
   64970:	mov    0x10(%r14,%r12,8),%rax
   64975:	mov    (%rax),%rdi
   64978:	callq  1f9c0 <*ABS*+0x911b0@plt+0x40>
   6497d:	mov    0x10(%r14,%r12,8),%rax
   64982:	add    $0x1,%r12
   64986:	cmp    %r12,(%r14)
   64989:	movq   $0x0,(%rax)
   64990:	ja     64970 <_IO_vfwscanf+0x990>
   64992:	mov    0x8(%r14),%r14
   64996:	test   %r14,%r14
   64999:	jne    64960 <_IO_vfwscanf+0x980>
   6499b:	jmpq   64631 <_IO_vfwscanf+0x651>
   649a0:	mov    -0x538(%rbp),%rax
   649a7:	mov    -0x598(%rbp),%edi
   649ad:	sub    $0x25,%edx
   649b0:	cmp    $0x53,%edx
   649b3:	mov    %edi,%fs:(%rax)
   649b6:	ja     65dea <_IO_vfwscanf+0x1e0a>
   649bc:	lea    0x11f521(%rip),%rcx        # 183ee4 <jump_table+0x724>
   649c3:	movslq (%rcx,%rdx,4),%rax
   649c7:	add    %rcx,%rax
   649ca:	jmpq   *%rax
   649cc:	nopl   0x0(%rax)
   649d0:	mov    -0x520(%rbp),%r14
   649d7:	mov    (%r14),%rdi
   649da:	callq  1f9c0 <*ABS*+0x911b0@plt+0x40>
   649df:	movq   $0x0,(%r14)
   649e6:	jmpq   64631 <_IO_vfwscanf+0x651>
   649eb:	nopl   0x0(%rax,%rax,1)
   649f0:	mov    %r14,%r15
   649f3:	mov    -0x504(%rbp),%ebx
   649f9:	mov    -0x510(%rbp),%r14
   64a00:	movl   $0x2,-0x508(%rbp)
   64a0a:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   64a0f:	nop
   64a10:	mov    %r15d,%r13d
   64a13:	mov    %r14,%r15
   64a16:	mov    -0x510(%rbp),%r14
   64a1d:	mov    %r13d,%esi
   64a20:	mov    %r15,%rdi
   64a23:	callq  74430 <_IO_sputbackwc>
   64a28:	mov    -0x504(%rbp),%ebx
   64a2e:	movl   $0x2,-0x508(%rbp)
   64a38:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   64a3d:	nopl   (%rax)
   64a40:	mov    %rbx,-0x558(%rbp)
   64a47:	jmpq   64457 <_IO_vfwscanf+0x477>
   64a4c:	mov    %r14,%r15
   64a4f:	mov    -0x538(%rbp),%rax
   64a56:	mov    -0x510(%rbp),%r14
   64a5d:	mov    -0x514(%rbp),%edi
   64a63:	mov    %edi,%fs:(%rax)
   64a66:	mov    -0x504(%rbp),%r10d
   64a6d:	test   %r10d,%r10d
   64a70:	je     660c9 <_IO_vfwscanf+0x20e9>
   64a76:	mov    -0x504(%rbp),%ebx
   64a7c:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   64a81:	mov    $0xffffffff,%r15d
   64a87:	mov    %r13d,%eax
   64a8a:	and    $0x8,%eax
   64a8d:	mov    %eax,-0x500(%rbp)
   64a93:	jne    64b55 <_IO_vfwscanf+0xb75>
   64a99:	test   $0x2100,%r13d
   64aa0:	je     66d26 <_IO_vfwscanf+0x2d46>
   64aa6:	mov    -0x530(%rbp),%r10d
   64aad:	test   %r10d,%r10d
   64ab0:	jne    677b0 <_IO_vfwscanf+0x37d0>
   64ab6:	mov    -0x4d8(%rbp),%edx
   64abc:	cmp    $0x2f,%edx
   64abf:	ja     6b2e0 <_IO_vfwscanf+0x7300>
   64ac5:	mov    %edx,%eax
   64ac7:	add    -0x4c8(%rbp),%rax
   64ace:	add    $0x8,%edx
   64ad1:	mov    %edx,-0x4d8(%rbp)
   64ad7:	mov    (%rax),%rax
   64ada:	mov    %rax,-0x520(%rbp)
   64ae1:	cmpq   $0x0,-0x520(%rbp)
   64ae9:	je     6b2c1 <_IO_vfwscanf+0x72e1>
   64aef:	mov    $0x190,%edi
   64af4:	callq  1f998 <*ABS*+0x911b0@plt+0x18>
   64af9:	mov    -0x520(%rbp),%rsi
   64b00:	test   %rax,%rax
   64b03:	mov    %rax,(%rsi)
   64b06:	je     68b88 <_IO_vfwscanf+0x4ba8>
   64b0c:	mov    -0x510(%rbp),%rcx
   64b13:	test   %rcx,%rcx
   64b16:	je     6837b <_IO_vfwscanf+0x439b>
   64b1c:	mov    (%rcx),%rdx
   64b1f:	cmp    $0x20,%rdx
   64b23:	lea    0x1(%rdx),%rcx
   64b27:	je     6837b <_IO_vfwscanf+0x439b>
   64b2d:	mov    -0x510(%rbp),%rdi
   64b34:	mov    %rax,-0x578(%rbp)
   64b3b:	movq   $0x64,-0x550(%rbp)
   64b46:	mov    %rcx,(%rdi)
   64b49:	mov    -0x520(%rbp),%rcx
   64b50:	mov    %rcx,0x10(%rdi,%rdx,8)
   64b55:	cmp    $0xffffffff,%r15d
   64b59:	je     66b50 <_IO_vfwscanf+0x2b70>
   64b5f:	mov    0xa0(%r14),%rax
   64b66:	test   %rax,%rax
   64b69:	je     6730f <_IO_vfwscanf+0x332f>
   64b6f:	mov    (%rax),%rdx
   64b72:	cmp    0x8(%rax),%rdx
   64b76:	jae    6730f <_IO_vfwscanf+0x332f>
   64b7c:	lea    0x4(%rdx),%rcx
   64b80:	mov    (%rdx),%r15d
   64b83:	mov    %rcx,(%rax)
   64b86:	cmp    $0xffffffff,%r15d
   64b8a:	je     66edd <_IO_vfwscanf+0x2efd>
   64b90:	addq   $0x1,-0x4f8(%rbp)
   64b98:	mov    %r13d,%edi
   64b9b:	mov    %rbx,-0x538(%rbp)
   64ba2:	mov    -0x4f8(%rbp),%rax
   64ba9:	and    $0x2100,%edi
   64baf:	mov    %r13d,-0x4f8(%rbp)
   64bb6:	mov    %edi,-0x530(%rbp)
   64bbc:	mov    %r15d,%edi
   64bbf:	mov    -0x578(%rbp),%r13
   64bc6:	mov    %rax,%rbx
   64bc9:	callq  10b4f0 <iswspace>
   64bce:	test   %eax,%eax
   64bd0:	jne    64c7f <_IO_vfwscanf+0xc9f>
   64bd6:	nopw   %cs:0x0(%rax,%rax,1)
   64be0:	mov    -0x500(%rbp),%r8d
   64be7:	test   %r8d,%r8d
   64bea:	jne    64c2b <_IO_vfwscanf+0xc4b>
   64bec:	mov    -0x530(%rbp),%edi
   64bf2:	lea    0x4(%r13),%rax
   64bf6:	mov    %r15d,0x0(%r13)
   64bfa:	test   %edi,%edi
   64bfc:	je     65f98 <_IO_vfwscanf+0x1fb8>
   64c02:	mov    -0x520(%rbp),%rsi
   64c09:	mov    %rax,%r13
   64c0c:	mov    (%rsi),%rdi
   64c0f:	mov    -0x550(%rbp),%rsi
   64c16:	lea    0x0(,%rsi,4),%rcx
   64c1e:	lea    (%rdi,%rcx,1),%rsi
   64c22:	cmp    %rsi,%rax
   64c25:	je     66eec <_IO_vfwscanf+0x2f0c>
   64c2b:	test   %r12d,%r12d
   64c2e:	jle    64c3a <_IO_vfwscanf+0xc5a>
   64c30:	sub    $0x1,%r12d
   64c34:	je     6717f <_IO_vfwscanf+0x319f>
   64c3a:	mov    0xa0(%r14),%rax
   64c41:	test   %rax,%rax
   64c44:	je     65fa0 <_IO_vfwscanf+0x1fc0>
   64c4a:	mov    (%rax),%rdx
   64c4d:	cmp    0x8(%rax),%rdx
   64c51:	jae    65fa0 <_IO_vfwscanf+0x1fc0>
   64c57:	lea    0x4(%rdx),%rcx
   64c5b:	mov    (%rdx),%r15d
   64c5e:	mov    %rcx,(%rax)
   64c61:	cmp    $0xffffffff,%r15d
   64c65:	je     65f68 <_IO_vfwscanf+0x1f88>
   64c6b:	mov    %r15d,%edi
   64c6e:	add    $0x1,%rbx
   64c72:	callq  10b4f0 <iswspace>
   64c77:	test   %eax,%eax
   64c79:	je     64be0 <_IO_vfwscanf+0xc00>
   64c7f:	mov    %rbx,%rax
   64c82:	mov    %r15d,%esi
   64c85:	mov    %r14,%rdi
   64c88:	sub    $0x1,%rax
   64c8c:	mov    -0x538(%rbp),%rbx
   64c93:	mov    %r13,-0x578(%rbp)
   64c9a:	mov    %rax,-0x4f8(%rbp)
   64ca1:	callq  74430 <_IO_sputbackwc>
   64ca6:	nopw   %cs:0x0(%rax,%rax,1)
   64cb0:	mov    -0x500(%rbp),%esi
   64cb6:	test   %esi,%esi
   64cb8:	jne    641dd <_IO_vfwscanf+0x1fd>
   64cbe:	mov    -0x530(%rbp),%ecx
   64cc4:	mov    -0x578(%rbp),%rax
   64ccb:	test   %ecx,%ecx
   64ccd:	lea    0x4(%rax),%r13
   64cd1:	movl   $0x0,(%rax)
   64cd7:	je     64d08 <_IO_vfwscanf+0xd28>
   64cd9:	mov    -0x520(%rbp),%r12
   64ce0:	mov    %r13,%rsi
   64ce3:	mov    (%r12),%rdi
   64ce7:	sub    %rdi,%rsi
   64cea:	mov    %rsi,%rax
   64ced:	sar    $0x2,%rax
   64cf1:	cmp    %rax,-0x550(%rbp)
   64cf8:	je     64d08 <_IO_vfwscanf+0xd28>
   64cfa:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   64cff:	test   %rax,%rax
   64d02:	je     64d08 <_IO_vfwscanf+0xd28>
   64d04:	mov    %rax,(%r12)
   64d08:	addl   $0x1,-0x504(%rbp)
   64d0f:	mov    %r13,-0x578(%rbp)
   64d16:	movq   $0x0,-0x520(%rbp)
   64d21:	jmpq   641fa <_IO_vfwscanf+0x21a>
   64d26:	mov    $0xffffffff,%r15d
   64d2c:	cmp    $0xffffffff,%r12d
   64d30:	mov    $0x1,%eax
   64d35:	cmove  %eax,%r12d
   64d39:	mov    %r13d,%eax
   64d3c:	and    $0x8,%eax
   64d3f:	mov    %eax,-0x500(%rbp)
   64d45:	jne    64e16 <_IO_vfwscanf+0xe36>
   64d4b:	test   $0x2100,%r13d
   64d52:	je     66dcc <_IO_vfwscanf+0x2dec>
   64d58:	mov    -0x530(%rbp),%esi
   64d5e:	test   %esi,%esi
   64d60:	jne    678a8 <_IO_vfwscanf+0x38c8>
   64d66:	mov    -0x4d8(%rbp),%edx
   64d6c:	cmp    $0x2f,%edx
   64d6f:	ja     6b1ea <_IO_vfwscanf+0x720a>
   64d75:	mov    %edx,%eax
   64d77:	add    -0x4c8(%rbp),%rax
   64d7e:	add    $0x8,%edx
   64d81:	mov    %edx,-0x4d8(%rbp)
   64d87:	mov    (%rax),%rax
   64d8a:	mov    %rax,-0x520(%rbp)
   64d91:	cmpq   $0x0,-0x520(%rbp)
   64d99:	je     6b17a <_IO_vfwscanf+0x719a>
   64d9f:	cmp    $0x400,%r12d
   64da6:	mov    $0x400,%eax
   64dab:	cmovle %r12d,%eax
   64daf:	cltq   
   64db1:	lea    0x0(,%rax,4),%rdi
   64db9:	mov    %rax,-0x550(%rbp)
   64dc0:	callq  1f998 <*ABS*+0x911b0@plt+0x18>
   64dc5:	mov    -0x520(%rbp),%rsi
   64dcc:	test   %rax,%rax
   64dcf:	mov    %rax,(%rsi)
   64dd2:	je     687b0 <_IO_vfwscanf+0x47d0>
   64dd8:	mov    -0x510(%rbp),%rcx
   64ddf:	test   %rcx,%rcx
   64de2:	je     682f0 <_IO_vfwscanf+0x4310>
   64de8:	mov    (%rcx),%rdx
   64deb:	cmp    $0x20,%rdx
   64def:	lea    0x1(%rdx),%rcx
   64df3:	je     682f0 <_IO_vfwscanf+0x4310>
   64df9:	mov    -0x510(%rbp),%rsi
   64e00:	mov    %rax,-0x578(%rbp)
   64e07:	mov    %rcx,(%rsi)
   64e0a:	mov    -0x520(%rbp),%rcx
   64e11:	mov    %rcx,0x10(%rsi,%rdx,8)
   64e16:	cmp    $0xffffffff,%r15d
   64e1a:	je     66ba1 <_IO_vfwscanf+0x2bc1>
   64e20:	mov    0xa0(%r14),%rax
   64e27:	test   %rax,%rax
   64e2a:	je     67524 <_IO_vfwscanf+0x3544>
   64e30:	mov    (%rax),%rdx
   64e33:	cmp    0x8(%rax),%rdx
   64e37:	jae    67524 <_IO_vfwscanf+0x3544>
   64e3d:	lea    0x4(%rdx),%rcx
   64e41:	mov    (%rdx),%r15d
   64e44:	mov    %rcx,(%rax)
   64e47:	cmp    $0xffffffff,%r15d
   64e4b:	je     66e5f <_IO_vfwscanf+0x2e7f>
   64e51:	mov    -0x4f8(%rbp),%rax
   64e58:	mov    -0x500(%rbp),%edx
   64e5e:	add    $0x1,%rax
   64e62:	test   %edx,%edx
   64e64:	je     664d8 <_IO_vfwscanf+0x24f8>
   64e6a:	cmp    $0x1,%r12d
   64e6e:	jle    6901e <_IO_vfwscanf+0x503e>
   64e74:	mov    -0x4f8(%rbp),%rdi
   64e7b:	lea    -0x2(%r12),%edx
   64e80:	mov    %rax,%r13
   64e83:	lea    0x2(%rdi,%rdx,1),%r12
   64e88:	jmp    64e9d <_IO_vfwscanf+0xebd>
   64e8a:	nopw   0x0(%rax,%rax,1)
   64e90:	add    $0x1,%r13
   64e94:	cmp    %r12,%r13
   64e97:	je     67534 <_IO_vfwscanf+0x3554>
   64e9d:	mov    0xa0(%r14),%rax
   64ea4:	test   %rax,%rax
   64ea7:	je     660f1 <_IO_vfwscanf+0x2111>
   64ead:	mov    (%rax),%rdx
   64eb0:	cmp    0x8(%rax),%rdx
   64eb4:	jae    660f1 <_IO_vfwscanf+0x2111>
   64eba:	lea    0x4(%rdx),%rcx
   64ebe:	mov    %rcx,(%rax)
   64ec1:	mov    (%rdx),%eax
   64ec3:	cmp    $0xffffffff,%eax
   64ec6:	jne    64e90 <_IO_vfwscanf+0xeb0>
   64ec8:	mov    %eax,%r15d
   64ecb:	mov    0x35af96(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   64ed2:	mov    %r13,-0x4f8(%rbp)
   64ed9:	movl   $0x0,-0x500(%rbp)
   64ee3:	mov    %fs:(%rax),%eax
   64ee6:	mov    %eax,-0x514(%rbp)
   64eec:	jmpq   641fa <_IO_vfwscanf+0x21a>
   64ef1:	mov    $0xffffffff,%r15d
   64ef7:	mov    %r13d,%eax
   64efa:	and    $0x1,%eax
   64efd:	mov    %eax,-0x500(%rbp)
   64f03:	jne    64d2c <_IO_vfwscanf+0xd4c>
   64f09:	cmp    $0xffffffff,%r12d
   64f0d:	mov    $0x1,%eax
   64f12:	cmove  %eax,%r12d
   64f16:	mov    %r13d,%eax
   64f19:	and    $0x8,%eax
   64f1c:	mov    %eax,-0x560(%rbp)
   64f22:	jne    64fe0 <_IO_vfwscanf+0x1000>
   64f28:	test   $0x2100,%r13d
   64f2f:	je     6808f <_IO_vfwscanf+0x40af>
   64f35:	mov    -0x530(%rbp),%r9d
   64f3c:	test   %r9d,%r9d
   64f3f:	jne    685d0 <_IO_vfwscanf+0x45f0>
   64f45:	mov    -0x4d8(%rbp),%edx
   64f4b:	cmp    $0x2f,%edx
   64f4e:	ja     6ad0d <_IO_vfwscanf+0x6d2d>
   64f54:	mov    %edx,%eax
   64f56:	add    -0x4c8(%rbp),%rax
   64f5d:	add    $0x8,%edx
   64f60:	mov    %edx,-0x4d8(%rbp)
   64f66:	mov    (%rax),%rax
   64f69:	mov    %rax,-0x520(%rbp)
   64f70:	cmpq   $0x0,-0x520(%rbp)
   64f78:	je     6acee <_IO_vfwscanf+0x6d0e>
   64f7e:	mov    $0x64,%edi
   64f83:	callq  1f998 <*ABS*+0x911b0@plt+0x18>
   64f88:	mov    -0x520(%rbp),%rcx
   64f8f:	test   %rax,%rax
   64f92:	mov    %rax,(%rcx)
   64f95:	je     692e3 <_IO_vfwscanf+0x5303>
   64f9b:	mov    -0x510(%rbp),%rsi
   64fa2:	test   %rsi,%rsi
   64fa5:	je     692a7 <_IO_vfwscanf+0x52c7>
   64fab:	mov    (%rsi),%rdx
   64fae:	cmp    $0x20,%rdx
   64fb2:	je     692a7 <_IO_vfwscanf+0x52c7>
   64fb8:	lea    0x1(%rdx),%rcx
   64fbc:	mov    %rsi,%rdi
   64fbf:	mov    %rcx,(%rdi)
   64fc2:	mov    -0x520(%rbp),%rcx
   64fc9:	mov    %rax,-0x570(%rbp)
   64fd0:	movq   $0x64,-0x550(%rbp)
   64fdb:	mov    %rcx,0x10(%rdi,%rdx,8)
   64fe0:	cmp    $0xffffffff,%r15d
   64fe4:	je     67f34 <_IO_vfwscanf+0x3f54>
   64fea:	mov    0xa0(%r14),%rax
   64ff1:	test   %rax,%rax
   64ff4:	je     68b2b <_IO_vfwscanf+0x4b4b>
   64ffa:	mov    (%rax),%rdx
   64ffd:	cmp    0x8(%rax),%rdx
   65001:	jae    68b2b <_IO_vfwscanf+0x4b4b>
   65007:	lea    0x4(%rdx),%rcx
   6500b:	mov    (%rdx),%r15d
   6500e:	mov    %rcx,(%rax)
   65011:	cmp    $0xffffffff,%r15d
   65015:	je     68520 <_IO_vfwscanf+0x4540>
   6501b:	mov    -0x590(%rbp),%rax
   65022:	addq   $0x1,-0x4f8(%rbp)
   6502a:	mov    %rbx,-0x538(%rbp)
   65031:	mov    %r13d,-0x558(%rbp)
   65038:	mov    %r12d,%ebx
   6503b:	mov    -0x570(%rbp),%r12
   65042:	movq   $0x0,(%rax)
   65049:	mov    %r13d,%eax
   6504c:	and    $0x2008,%eax
   65051:	mov    -0x560(%rbp),%r13d
   65058:	mov    %eax,-0x530(%rbp)
   6505e:	cmpl   $0x2000,-0x530(%rbp)
   65068:	je     650e8 <_IO_vfwscanf+0x1108>
   6506a:	nopw   0x0(%rax,%rax,1)
   65070:	mov    -0x590(%rbp),%rdx
   65077:	test   %r13d,%r13d
   6507a:	mov    $0x0,%edi
   6507f:	cmove  %r12,%rdi
   65083:	mov    %r15d,%esi
   65086:	callq  ac610 <c32rtomb>
   6508b:	cmp    $0xffffffffffffffff,%rax
   6508f:	je     66e38 <_IO_vfwscanf+0x2e58>
   65095:	sub    $0x1,%ebx
   65098:	add    %rax,%r12
   6509b:	test   %ebx,%ebx
   6509d:	jle    69689 <_IO_vfwscanf+0x56a9>
   650a3:	mov    0xa0(%r14),%rax
   650aa:	test   %rax,%rax
   650ad:	je     66a7d <_IO_vfwscanf+0x2a9d>
   650b3:	mov    (%rax),%rdx
   650b6:	cmp    0x8(%rax),%rdx
   650ba:	jae    66a7d <_IO_vfwscanf+0x2a9d>
   650c0:	lea    0x4(%rdx),%rcx
   650c4:	mov    (%rdx),%r15d
   650c7:	mov    %rcx,(%rax)
   650ca:	cmp    $0xffffffff,%r15d
   650ce:	je     66490 <_IO_vfwscanf+0x24b0>
   650d4:	addq   $0x1,-0x4f8(%rbp)
   650dc:	cmpl   $0x2000,-0x530(%rbp)
   650e6:	jne    65070 <_IO_vfwscanf+0x1090>
   650e8:	mov    -0x520(%rbp),%rax
   650ef:	mov    -0x550(%rbp),%rsi
   650f6:	mov    (%rax),%rdi
   650f9:	mov    0x35acb0(%rip),%rax        # 3bfdb0 <_DYNAMIC+0x250>
   65100:	mov    %fs:(%rax),%rax
   65104:	lea    (%rdi,%rsi,1),%rdx
   65108:	mov    (%rax),%rax
   6510b:	mov    0xa8(%rax),%eax
   65111:	add    %r12,%rax
   65114:	cmp    %rdx,%rax
   65117:	jb     65070 <_IO_vfwscanf+0x1090>
   6511d:	shlq   -0x550(%rbp)
   65124:	sub    %rdi,%r12
   65127:	mov    -0x550(%rbp),%rax
   6512e:	mov    %rax,%rsi
   65131:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   65136:	test   %rax,%rax
   65139:	je     6b3b9 <_IO_vfwscanf+0x73d9>
   6513f:	mov    -0x520(%rbp),%rcx
   65146:	add    %rax,%r12
   65149:	mov    %rax,(%rcx)
   6514c:	jmpq   65070 <_IO_vfwscanf+0x1090>
   65151:	mov    $0xffffffff,%r15d
   65157:	mov    %r13d,%eax
   6515a:	and    $0x1,%eax
   6515d:	mov    %eax,-0x538(%rbp)
   65163:	mov    %r13d,%eax
   65166:	je     669b4 <_IO_vfwscanf+0x29d4>
   6516c:	and    $0x8,%eax
   6516f:	mov    %eax,-0x500(%rbp)
   65175:	jne    65233 <_IO_vfwscanf+0x1253>
   6517b:	test   $0x2100,%r13d
   65182:	je     672a7 <_IO_vfwscanf+0x32c7>
   65188:	mov    -0x530(%rbp),%r11d
   6518f:	test   %r11d,%r11d
   65192:	jne    683b0 <_IO_vfwscanf+0x43d0>
   65198:	mov    -0x4d8(%rbp),%edx
   6519e:	cmp    $0x2f,%edx
   651a1:	ja     6a76a <_IO_vfwscanf+0x678a>
   651a7:	mov    %edx,%eax
   651a9:	add    -0x4c8(%rbp),%rax
   651b0:	add    $0x8,%edx
   651b3:	mov    %edx,-0x4d8(%rbp)
   651b9:	mov    (%rax),%rax
   651bc:	mov    %rax,-0x520(%rbp)
   651c3:	cmpq   $0x0,-0x520(%rbp)
   651cb:	je     6a74b <_IO_vfwscanf+0x676b>
   651d1:	mov    $0x190,%edi
   651d6:	callq  1f998 <*ABS*+0x911b0@plt+0x18>
   651db:	mov    -0x520(%rbp),%rcx
   651e2:	test   %rax,%rax
   651e5:	mov    %rax,(%rcx)
   651e8:	je     6909d <_IO_vfwscanf+0x50bd>
   651ee:	mov    -0x510(%rbp),%rsi
   651f5:	test   %rsi,%rsi
   651f8:	je     68721 <_IO_vfwscanf+0x4741>
   651fe:	mov    (%rsi),%rdx
   65201:	cmp    $0x20,%rdx
   65205:	je     68721 <_IO_vfwscanf+0x4741>
   6520b:	lea    0x1(%rdx),%rcx
   6520f:	mov    %rsi,%rdi
   65212:	mov    -0x520(%rbp),%rsi
   65219:	mov    %rcx,(%rdi)
   6521c:	mov    %rax,-0x578(%rbp)
   65223:	movq   $0x64,-0x550(%rbp)
   6522e:	mov    %rsi,0x10(%rdi,%rdx,8)
   65233:	mov    -0x558(%rbp),%rax
   6523a:	cmpl   $0x5e,0x4(%rax)
   6523e:	jne    6b6d8 <_IO_vfwscanf+0x76f8>
   65244:	add    $0x8,%rax
   65248:	movl   $0x1,-0x530(%rbp)
   65252:	mov    %rax,%r8
   65255:	test   %r12d,%r12d
   65258:	mov    $0x7fffffff,%eax
   6525d:	mov    %r8,-0x4e0(%rbp)
   65264:	cmovs  %eax,%r12d
   65268:	cmpl   $0x5d,(%r8)
   6526c:	lea    0x4(%r8),%rax
   65270:	cmove  %rax,%r8
   65274:	jmp    65282 <_IO_vfwscanf+0x12a2>
   65276:	cmp    $0x5d,%eax
   65279:	je     6888d <_IO_vfwscanf+0x48ad>
   6527f:	mov    %rbx,%r8
   65282:	lea    0x4(%r8),%rbx
   65286:	mov    -0x4(%rbx),%eax
   65289:	test   %eax,%eax
   6528b:	jne    65276 <_IO_vfwscanf+0x1296>
   6528d:	mov    %r14,%r15
   65290:	mov    -0x504(%rbp),%ebx
   65296:	mov    -0x510(%rbp),%r14
   6529d:	movl   $0x2,-0x508(%rbp)
   652a7:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   652ac:	mov    $0xffffffff,%r15d
   652b2:	mov    %r13d,%eax
   652b5:	and    $0x8,%eax
   652b8:	mov    %eax,-0x500(%rbp)
   652be:	jne    641dd <_IO_vfwscanf+0x1fd>
   652c4:	test   $0x1,%r13b
   652c8:	je     67110 <_IO_vfwscanf+0x3130>
   652ce:	mov    -0x530(%rbp),%r13d
   652d5:	test   %r13d,%r13d
   652d8:	jne    684d0 <_IO_vfwscanf+0x44f0>
   652de:	mov    -0x4d8(%rbp),%edx
   652e4:	cmp    $0x2f,%edx
   652e7:	ja     6abaf <_IO_vfwscanf+0x6bcf>
   652ed:	mov    %edx,%eax
   652ef:	add    -0x4c8(%rbp),%rax
   652f6:	add    $0x8,%edx
   652f9:	mov    %edx,-0x4d8(%rbp)
   652ff:	mov    (%rax),%rax
   65302:	mov    -0x4f8(%rbp),%rcx
   65309:	mov    %rcx,(%rax)
   6530c:	jmpq   641fa <_IO_vfwscanf+0x21a>
   65311:	mov    -0x4f8(%rbp),%rsi
   65318:	mov    $0x10,%r8d
   6531e:	cmp    $0xffffffff,%r15d
   65322:	je     662ad <_IO_vfwscanf+0x22cd>
   65328:	mov    0xa0(%r14),%rax
   6532f:	test   %rax,%rax
   65332:	je     66409 <_IO_vfwscanf+0x2429>
   65338:	mov    (%rax),%rdx
   6533b:	cmp    0x8(%rax),%rdx
   6533f:	jae    66409 <_IO_vfwscanf+0x2429>
   65345:	lea    0x4(%rdx),%rcx
   65349:	mov    (%rdx),%r15d
   6534c:	mov    %rcx,(%rax)
   6534f:	cmp    $0xffffffff,%r15d
   65353:	je     66109 <_IO_vfwscanf+0x2129>
   65359:	lea    -0x2b(%r15),%eax
   6535d:	addq   $0x1,-0x4f8(%rbp)
   65365:	and    $0xfffffffd,%eax
   65368:	jne    653d6 <_IO_vfwscanf+0x13f6>
   6536a:	mov    -0x450(%rbp),%rax
   65371:	mov    -0x448(%rbp),%rdx
   65378:	cmp    %rax,%rdx
   6537b:	je     66f49 <_IO_vfwscanf+0x2f69>
   65381:	lea    0x4(%rax),%rdx
   65385:	mov    %rdx,-0x450(%rbp)
   6538c:	mov    %r15d,(%rax)
   6538f:	xor    %eax,%eax
   65391:	test   %r12d,%r12d
   65394:	setg   %al
   65397:	sub    %eax,%r12d
   6539a:	mov    0xa0(%r14),%rax
   653a1:	test   %rax,%rax
   653a4:	je     66d90 <_IO_vfwscanf+0x2db0>
   653aa:	mov    (%rax),%rdx
   653ad:	cmp    0x8(%rax),%rdx
   653b1:	jae    66d90 <_IO_vfwscanf+0x2db0>
   653b7:	lea    0x4(%rdx),%rcx
   653bb:	mov    (%rdx),%r15d
   653be:	mov    %rcx,(%rax)
   653c1:	cmp    $0xffffffff,%r15d
   653c5:	je     65fb0 <_IO_vfwscanf+0x1fd0>
   653cb:	lea    0x2(%rsi),%rax
   653cf:	mov    %rax,-0x4f8(%rbp)
   653d6:	test   %r12d,%r12d
   653d9:	je     65fc0 <_IO_vfwscanf+0x1fe0>
   653df:	cmp    $0x30,%r15d
   653e3:	jne    65fc0 <_IO_vfwscanf+0x1fe0>
   653e9:	xor    %eax,%eax
   653eb:	test   %r12d,%r12d
   653ee:	mov    -0x448(%rbp),%rdx
   653f5:	setg   %al
   653f8:	sub    %eax,%r12d
   653fb:	mov    -0x450(%rbp),%rax
   65402:	cmp    %rax,%rdx
   65405:	je     66e6e <_IO_vfwscanf+0x2e8e>
   6540b:	lea    0x4(%rax),%rdx
   6540f:	mov    %rdx,-0x450(%rbp)
   65416:	movl   $0x30,(%rax)
   6541c:	mov    0xa0(%r14),%rax
   65423:	test   %rax,%rax
   65426:	je     66d08 <_IO_vfwscanf+0x2d28>
   6542c:	mov    (%rax),%rdx
   6542f:	cmp    0x8(%rax),%rdx
   65433:	jae    66d08 <_IO_vfwscanf+0x2d28>
   65439:	lea    0x4(%rdx),%rcx
   6543d:	mov    (%rdx),%r15d
   65440:	mov    %rcx,(%rax)
   65443:	cmp    $0xffffffff,%r15d
   65447:	je     66932 <_IO_vfwscanf+0x2952>
   6544d:	addq   $0x1,-0x4f8(%rbp)
   65455:	test   %r12d,%r12d
   65458:	je     65479 <_IO_vfwscanf+0x1499>
   6545a:	mov    %r15d,%edi
   6545d:	mov    %r8d,-0x500(%rbp)
   65464:	callq  10b6c0 <towlower>
   65469:	cmp    $0x78,%eax
   6546c:	mov    -0x500(%rbp),%r8d
   65473:	je     67199 <_IO_vfwscanf+0x31b9>
   65479:	test   %r8d,%r8d
   6547c:	je     66192 <_IO_vfwscanf+0x21b2>
   65482:	cmp    $0xa,%r8d
   65486:	jne    654a3 <_IO_vfwscanf+0x14c3>
   65488:	nopl   0x0(%rax,%rax,1)
   65490:	test   $0x400,%r13d
   65497:	jne    6792e <_IO_vfwscanf+0x394e>
   6549d:	mov    $0xa,%r8d
   654a3:	mov    %r13d,%eax
   654a6:	mov    %rbx,-0x538(%rbp)
   654ad:	mov    %r14,%rbx
   654b0:	shr    $0x7,%eax
   654b3:	mov    %r8d,%r14d
   654b6:	xor    $0x1,%eax
   654b9:	and    $0x1,%eax
   654bc:	mov    %al,-0x500(%rbp)
   654c2:	mov    -0x528(%rbp),%rax
   654c9:	add    $0x10,%rax
   654cd:	mov    %rax,-0x560(%rbp)
   654d4:	nopl   0x0(%rax)
   654d8:	cmp    $0xffffffff,%r15d
   654dc:	je     65503 <_IO_vfwscanf+0x1523>
   654de:	test   %r12d,%r12d
   654e1:	je     65503 <_IO_vfwscanf+0x1523>
   654e3:	cmp    $0x10,%r14d
   654e7:	je     65ec0 <_IO_vfwscanf+0x1ee0>
   654ed:	lea    -0x30(%r15),%eax
   654f1:	cmp    $0x9,%eax
   654f4:	ja     65e30 <_IO_vfwscanf+0x1e50>
   654fa:	cmp    %r14d,%eax
   654fd:	jl     65e54 <_IO_vfwscanf+0x1e74>
   65503:	mov    %r14d,%r8d
   65506:	mov    %rbx,%r14
   65509:	mov    -0x538(%rbp),%rbx
   65510:	mov    -0x450(%rbp),%rax
   65517:	test   %rax,%rax
   6551a:	je     66900 <_IO_vfwscanf+0x2920>
   65520:	mov    -0x440(%rbp),%rcx
   65527:	mov    %rax,%rsi
   6552a:	sub    %rcx,%rsi
   6552d:	mov    %rsi,%rdx
   65530:	sar    $0x2,%rdx
   65534:	test   %rdx,%rdx
   65537:	je     65fd0 <_IO_vfwscanf+0x1ff0>
   6553d:	cmp    $0x1,%rdx
   65541:	je     66697 <_IO_vfwscanf+0x26b7>
   65547:	cmp    $0xffffffff,%r15d
   6554b:	je     66118 <_IO_vfwscanf+0x2138>
   65551:	mov    %r15d,%esi
   65554:	mov    %r14,%rdi
   65557:	mov    %r8d,-0x500(%rbp)
   6555e:	subq   $0x1,-0x4f8(%rbp)
   65566:	callq  74430 <_IO_sputbackwc>
   6556b:	mov    -0x450(%rbp),%rax
   65572:	mov    -0x448(%rbp),%rdx
   65579:	mov    -0x500(%rbp),%r8d
   65580:	cmp    %rdx,%rax
   65583:	je     66f31 <_IO_vfwscanf+0x2f51>
   65589:	lea    0x4(%rax),%rdx
   6558d:	mov    %rdx,-0x450(%rbp)
   65594:	movl   $0x0,(%rax)
   6559a:	test   %rdx,%rdx
   6559d:	je     66c5f <_IO_vfwscanf+0x2c7f>
   655a3:	mov    %r13d,%r12d
   655a6:	mov    %r13d,%ecx
   655a9:	lea    -0x4e0(%rbp),%rsi
   655b0:	and    $0x80,%ecx
   655b6:	and    $0x40,%r12d
   655ba:	mov    %r8d,%edx
   655bd:	mov    -0x440(%rbp),%rdi
   655c4:	je     66070 <_IO_vfwscanf+0x2090>
   655ca:	callq  ad120 <__wcstol_internal>
   655cf:	mov    -0x440(%rbp),%rdi
   655d6:	cmp    %rdi,-0x4e0(%rbp)
   655dd:	je     66c40 <_IO_vfwscanf+0x2c60>
   655e3:	mov    %r13d,%esi
   655e6:	and    $0x8,%esi
   655e9:	mov    %esi,-0x500(%rbp)
   655ef:	jne    641dd <_IO_vfwscanf+0x1fd>
   655f5:	test   %r12d,%r12d
   655f8:	je     662ca <_IO_vfwscanf+0x22ea>
   655fe:	test   $0x1,%r13b
   65602:	je     66adf <_IO_vfwscanf+0x2aff>
   65608:	mov    -0x530(%rbp),%edx
   6560e:	test   %edx,%edx
   65610:	jne    671fc <_IO_vfwscanf+0x321c>
   65616:	mov    -0x4d8(%rbp),%ecx
   6561c:	cmp    $0x2f,%ecx
   6561f:	ja     6b10d <_IO_vfwscanf+0x712d>
   65625:	mov    %ecx,%edx
   65627:	add    -0x4c8(%rbp),%rdx
   6562e:	add    $0x8,%ecx
   65631:	mov    %ecx,-0x4d8(%rbp)
   65637:	mov    (%rdx),%rdx
   6563a:	mov    %rax,(%rdx)
   6563d:	addl   $0x1,-0x504(%rbp)
   65644:	jmpq   641fa <_IO_vfwscanf+0x21a>
   65649:	or     $0x40,%r13d
   6564d:	mov    -0x4f8(%rbp),%rsi
   65654:	mov    $0xa,%r8d
   6565a:	jmpq   6531e <_IO_vfwscanf+0x133e>
   6565f:	or     $0x40,%r13d
   65663:	mov    -0x4f8(%rbp),%rsi
   6566a:	xor    %r8d,%r8d
   6566d:	jmpq   6531e <_IO_vfwscanf+0x133e>
   65672:	cmp    $0xffffffff,%r15d
   65676:	je     673d4 <_IO_vfwscanf+0x33f4>
   6567c:	mov    0xa0(%r14),%rax
   65683:	test   %rax,%rax
   65686:	je     6791e <_IO_vfwscanf+0x393e>
   6568c:	mov    (%rax),%rdx
   6568f:	cmp    0x8(%rax),%rdx
   65693:	jae    6791e <_IO_vfwscanf+0x393e>
   65699:	lea    0x4(%rdx),%rcx
   6569d:	mov    (%rdx),%r15d
   656a0:	mov    %rcx,(%rax)
   656a3:	cmp    $0xffffffff,%r15d
   656a7:	je     673c5 <_IO_vfwscanf+0x33e5>
   656ad:	mov    -0x4f8(%rbp),%rax
   656b4:	add    $0x1,%rax
   656b8:	mov    %rax,-0x500(%rbp)
   656bf:	xor    %eax,%eax
   656c1:	test   %r12d,%r12d
   656c4:	setg   %al
   656c7:	sub    %eax,%r12d
   656ca:	lea    -0x2b(%r15),%eax
   656ce:	and    $0xfffffffd,%eax
   656d1:	jne    66a8d <_IO_vfwscanf+0x2aad>
   656d7:	cmp    $0x2d,%r15d
   656db:	sete   -0x568(%rbp)
   656e2:	test   %r12d,%r12d
   656e5:	je     696d2 <_IO_vfwscanf+0x56f2>
   656eb:	mov    0xa0(%r14),%rax
   656f2:	test   %rax,%rax
   656f5:	je     687dc <_IO_vfwscanf+0x47fc>
   656fb:	mov    (%rax),%rdx
   656fe:	cmp    0x8(%rax),%rdx
   65702:	jae    687dc <_IO_vfwscanf+0x47fc>
   65708:	lea    0x4(%rdx),%rcx
   6570c:	mov    (%rdx),%r15d
   6570f:	mov    %rcx,(%rax)
   65712:	cmp    $0xffffffff,%r15d
   65716:	je     686ee <_IO_vfwscanf+0x470e>
   6571c:	mov    -0x4f8(%rbp),%rax
   65723:	add    $0x2,%rax
   65727:	mov    %rax,-0x500(%rbp)
   6572e:	xor    %eax,%eax
   65730:	test   %r12d,%r12d
   65733:	setg   %al
   65736:	sub    %eax,%r12d
   65739:	mov    %r15d,%edi
   6573c:	callq  10b6c0 <towlower>
   65741:	cmp    $0x6e,%eax
   65744:	je     67403 <_IO_vfwscanf+0x3423>
   6574a:	cmp    $0x69,%eax
   6574d:	je     675b5 <_IO_vfwscanf+0x35d5>
   65753:	test   %r12d,%r12d
   65756:	je     673f1 <_IO_vfwscanf+0x3411>
   6575c:	cmp    $0x30,%r15d
   65760:	jne    673f1 <_IO_vfwscanf+0x3411>
   65766:	mov    -0x450(%rbp),%rax
   6576d:	cmp    -0x448(%rbp),%rax
   65774:	je     69193 <_IO_vfwscanf+0x51b3>
   6577a:	lea    0x4(%rax),%rdx
   6577e:	mov    %rdx,-0x450(%rbp)
   65785:	movl   $0x30,(%rax)
   6578b:	mov    0xa0(%r14),%rax
   65792:	test   %rax,%rax
   65795:	je     69183 <_IO_vfwscanf+0x51a3>
   6579b:	mov    (%rax),%rdx
   6579e:	cmp    0x8(%rax),%rdx
   657a2:	jae    69183 <_IO_vfwscanf+0x51a3>
   657a8:	lea    0x4(%rdx),%rcx
   657ac:	mov    (%rdx),%r15d
   657af:	mov    %rcx,(%rax)
   657b2:	cmp    $0xffffffff,%r15d
   657b6:	je     69044 <_IO_vfwscanf+0x5064>
   657bc:	addq   $0x1,-0x500(%rbp)
   657c4:	xor    %eax,%eax
   657c6:	test   %r12d,%r12d
   657c9:	setg   %al
   657cc:	sub    %eax,%r12d
   657cf:	je     68280 <_IO_vfwscanf+0x42a0>
   657d5:	mov    %r15d,%edi
   657d8:	callq  10b6c0 <towlower>
   657dd:	cmp    $0x78,%eax
   657e0:	movl   $0x65,-0x4f8(%rbp)
   657ea:	mov    $0x1,%r8d
   657f0:	je     68c00 <_IO_vfwscanf+0x4c20>
   657f6:	mov    %r13d,%eax
   657f9:	mov    %rbx,-0x560(%rbp)
   65800:	mov    %r13d,-0x598(%rbp)
   65807:	and    $0x800,%eax
   6580c:	movb   $0x0,-0x558(%rbp)
   65813:	movb   $0x0,-0x538(%rbp)
   6581a:	mov    %eax,-0x5a0(%rbp)
   65820:	mov    %r13d,%eax
   65823:	mov    -0x500(%rbp),%rbx
   6582a:	and    $0x80,%eax
   6582f:	mov    %r8d,%r13d
   65832:	mov    %eax,-0x5a8(%rbp)
   65838:	mov    -0x528(%rbp),%rax
   6583f:	add    $0x10,%rax
   65843:	mov    %rax,-0x5b0(%rbp)
   6584a:	jmp    658c0 <_IO_vfwscanf+0x18e0>
   6584c:	cmp    -0x448(%rbp),%rdx
   65853:	je     68325 <_IO_vfwscanf+0x4345>
   65859:	lea    0x4(%rdx),%rax
   6585d:	mov    $0x1,%r13d
   65863:	mov    %rax,-0x450(%rbp)
   6586a:	mov    %r15d,(%rdx)
   6586d:	test   %r12d,%r12d
   65870:	je     695c0 <_IO_vfwscanf+0x55e0>
   65876:	cmp    $0xffffffff,%r15d
   6587a:	je     69120 <_IO_vfwscanf+0x5140>
   65880:	mov    0xa0(%r14),%rax
   65887:	test   %rax,%rax
   6588a:	je     66c20 <_IO_vfwscanf+0x2c40>
   65890:	mov    (%rax),%rdx
   65893:	cmp    0x8(%rax),%rdx
   65897:	jae    66c20 <_IO_vfwscanf+0x2c40>
   6589d:	lea    0x4(%rdx),%rcx
   658a1:	mov    (%rdx),%r15d
   658a4:	mov    %rcx,(%rax)
   658a7:	cmp    $0xffffffff,%r15d
   658ab:	je     6671c <_IO_vfwscanf+0x273c>
   658b1:	xor    %eax,%eax
   658b3:	add    $0x1,%rbx
   658b7:	test   %r12d,%r12d
   658ba:	setg   %al
   658bd:	sub    %eax,%r12d
   658c0:	mov    -0x450(%rbp),%rdx
   658c7:	test   %rdx,%rdx
   658ca:	je     670be <_IO_vfwscanf+0x30de>
   658d0:	lea    -0x30(%r15),%eax
   658d4:	cmp    $0x9,%eax
   658d7:	jbe    6584c <_IO_vfwscanf+0x186c>
   658dd:	cmpb   $0x0,-0x558(%rbp)
   658e4:	je     668a4 <_IO_vfwscanf+0x28c4>
   658ea:	mov    -0x4f8(%rbp),%eax
   658f0:	cmp    -0x4(%rdx),%eax
   658f3:	je     67f85 <_IO_vfwscanf+0x3fa5>
   658f9:	movzbl -0x538(%rbp),%eax
   65900:	xor    $0x1,%eax
   65903:	and    $0x1,%eax
   65906:	cmp    -0x548(%rbp),%r15d
   6590d:	jne    66bd6 <_IO_vfwscanf+0x2bf6>
   65913:	test   %al,%al
   65915:	je     66bd6 <_IO_vfwscanf+0x2bf6>
   6591b:	cmp    -0x448(%rbp),%rdx
   65922:	je     69200 <_IO_vfwscanf+0x5220>
   65928:	lea    0x4(%rdx),%rax
   6592c:	movb   $0x1,-0x538(%rbp)
   65933:	mov    %rax,-0x450(%rbp)
   6593a:	mov    %r15d,(%rdx)
   6593d:	jmpq   6586d <_IO_vfwscanf+0x188d>
   65942:	mov    %r14,%r15
   65945:	mov    -0x504(%rbp),%ebx
   6594b:	mov    -0x510(%rbp),%r14
   65952:	movl   $0x2,-0x508(%rbp)
   6595c:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   65961:	mov    $0xffffffff,%r15d
   65967:	mov    %r13d,%eax
   6596a:	and    $0x1,%eax
   6596d:	mov    %eax,-0x500(%rbp)
   65973:	jne    64a87 <_IO_vfwscanf+0xaa7>
   65979:	mov    %r13d,%eax
   6597c:	and    $0x8,%eax
   6597f:	mov    %eax,-0x558(%rbp)
   65985:	jne    65a45 <_IO_vfwscanf+0x1a65>
   6598b:	test   $0x2100,%r13d
   65992:	je     68460 <_IO_vfwscanf+0x4480>
   65998:	mov    -0x530(%rbp),%eax
   6599e:	test   %eax,%eax
   659a0:	jne    6852f <_IO_vfwscanf+0x454f>
   659a6:	mov    -0x4d8(%rbp),%edx
   659ac:	cmp    $0x2f,%edx
   659af:	ja     6a185 <_IO_vfwscanf+0x61a5>
   659b5:	mov    %edx,%eax
   659b7:	add    -0x4c8(%rbp),%rax
   659be:	add    $0x8,%edx
   659c1:	mov    %edx,-0x4d8(%rbp)
   659c7:	mov    (%rax),%rax
   659ca:	mov    %rax,-0x520(%rbp)
   659d1:	cmpq   $0x0,-0x520(%rbp)
   659d9:	je     6a166 <_IO_vfwscanf+0x6186>
   659df:	mov    $0x64,%edi
   659e4:	callq  1f998 <*ABS*+0x911b0@plt+0x18>
   659e9:	mov    -0x520(%rbp),%rsi
   659f0:	test   %rax,%rax
   659f3:	mov    %rax,(%rsi)
   659f6:	je     6965d <_IO_vfwscanf+0x567d>
   659fc:	mov    -0x510(%rbp),%rcx
   65a03:	test   %rcx,%rcx
   65a06:	je     69628 <_IO_vfwscanf+0x5648>
   65a0c:	mov    (%rcx),%rdx
   65a0f:	cmp    $0x20,%rdx
   65a13:	lea    0x1(%rdx),%rcx
   65a17:	je     69628 <_IO_vfwscanf+0x5648>
   65a1d:	mov    -0x510(%rbp),%rdi
   65a24:	mov    %rax,-0x570(%rbp)
   65a2b:	movq   $0x64,-0x550(%rbp)
   65a36:	mov    %rcx,(%rdi)
   65a39:	mov    -0x520(%rbp),%rcx
   65a40:	mov    %rcx,0x10(%rdi,%rdx,8)
   65a45:	cmp    $0xffffffff,%r15d
   65a49:	je     67f05 <_IO_vfwscanf+0x3f25>
   65a4f:	mov    0xa0(%r14),%rax
   65a56:	test   %rax,%rax
   65a59:	je     68b1b <_IO_vfwscanf+0x4b3b>
   65a5f:	mov    (%rax),%rdx
   65a62:	cmp    0x8(%rax),%rdx
   65a66:	jae    68b1b <_IO_vfwscanf+0x4b3b>
   65a6c:	lea    0x4(%rdx),%rcx
   65a70:	mov    (%rdx),%r15d
   65a73:	mov    %rcx,(%rax)
   65a76:	cmp    $0xffffffff,%r15d
   65a7a:	je     68400 <_IO_vfwscanf+0x4420>
   65a80:	mov    -0x590(%rbp),%rax
   65a87:	mov    %r15d,%edi
   65a8a:	addq   $0x1,-0x4f8(%rbp)
   65a92:	mov    %r13d,-0x560(%rbp)
   65a99:	mov    %rbx,-0x568(%rbp)
   65aa0:	movq   $0x0,(%rax)
   65aa7:	mov    %r13d,%eax
   65aaa:	and    $0x2100,%eax
   65aaf:	mov    -0x570(%rbp),%r13
   65ab6:	mov    %eax,-0x530(%rbp)
   65abc:	callq  10b4f0 <iswspace>
   65ac1:	test   %eax,%eax
   65ac3:	jne    65bae <_IO_vfwscanf+0x1bce>
   65ac9:	mov    -0x558(%rbp),%eax
   65acf:	test   %eax,%eax
   65ad1:	jne    660fe <_IO_vfwscanf+0x211e>
   65ad7:	mov    -0x530(%rbp),%eax
   65add:	test   %eax,%eax
   65adf:	je     65b16 <_IO_vfwscanf+0x1b36>
   65ae1:	mov    -0x520(%rbp),%rax
   65ae8:	mov    -0x550(%rbp),%rcx
   65aef:	mov    (%rax),%rdi
   65af2:	mov    0x35a2b7(%rip),%rax        # 3bfdb0 <_DYNAMIC+0x250>
   65af9:	mov    %fs:(%rax),%rax
   65afd:	lea    (%rdi,%rcx,1),%rdx
   65b01:	mov    (%rax),%rax
   65b04:	mov    0xa8(%rax),%eax
   65b0a:	add    %r13,%rax
   65b0d:	cmp    %rdx,%rax
   65b10:	jae    6781e <_IO_vfwscanf+0x383e>
   65b16:	mov    %r13,%rbx
   65b19:	mov    -0x590(%rbp),%rdx
   65b20:	mov    %r15d,%esi
   65b23:	mov    %r13,%rdi
   65b26:	callq  ac610 <c32rtomb>
   65b2b:	cmp    $0xffffffffffffffff,%rax
   65b2f:	je     67091 <_IO_vfwscanf+0x30b1>
   65b35:	mov    0x35a274(%rip),%rsi        # 3bfdb0 <_DYNAMIC+0x250>
   65b3c:	mov    %fs:(%rsi),%rdx
   65b40:	mov    (%rdx),%rdx
   65b43:	mov    0xa8(%rdx),%edx
   65b49:	cmp    %rdx,%rax
   65b4c:	ja     6af42 <_IO_vfwscanf+0x6f62>
   65b52:	test   %r12d,%r12d
   65b55:	lea    (%rbx,%rax,1),%r13
   65b59:	jle    65b65 <_IO_vfwscanf+0x1b85>
   65b5b:	sub    $0x1,%r12d
   65b5f:	je     69169 <_IO_vfwscanf+0x5189>
   65b65:	mov    0xa0(%r14),%rax
   65b6c:	test   %rax,%rax
   65b6f:	je     66c30 <_IO_vfwscanf+0x2c50>
   65b75:	mov    (%rax),%rdx
   65b78:	cmp    0x8(%rax),%rdx
   65b7c:	jae    66c30 <_IO_vfwscanf+0x2c50>
   65b82:	lea    0x4(%rdx),%rsi
   65b86:	mov    (%rdx),%r15d
   65b89:	mov    %rsi,(%rax)
   65b8c:	cmp    $0xffffffff,%r15d
   65b90:	je     6687a <_IO_vfwscanf+0x289a>
   65b96:	mov    %r15d,%edi
   65b99:	addq   $0x1,-0x4f8(%rbp)
   65ba1:	callq  10b4f0 <iswspace>
   65ba6:	test   %eax,%eax
   65ba8:	je     65ac9 <_IO_vfwscanf+0x1ae9>
   65bae:	mov    %r15d,%esi
   65bb1:	mov    %r14,%rdi
   65bb4:	mov    %r13,-0x570(%rbp)
   65bbb:	mov    -0x568(%rbp),%rbx
   65bc2:	mov    -0x560(%rbp),%r13d
   65bc9:	subq   $0x1,-0x4f8(%rbp)
   65bd1:	callq  74430 <_IO_sputbackwc>
   65bd6:	mov    -0x558(%rbp),%r12d
   65bdd:	test   %r12d,%r12d
   65be0:	jne    641fa <_IO_vfwscanf+0x21a>
   65be6:	mov    -0x590(%rbp),%rdx
   65bed:	mov    -0x588(%rbp),%rdi
   65bf4:	xor    %esi,%esi
   65bf6:	callq  ac610 <c32rtomb>
   65bfb:	test   %rax,%rax
   65bfe:	mov    %rax,%rcx
   65c01:	je     6b4b9 <_IO_vfwscanf+0x74d9>
   65c07:	mov    -0x530(%rbp),%r11d
   65c0e:	test   %r11d,%r11d
   65c11:	je     693de <_IO_vfwscanf+0x53fe>
   65c17:	mov    -0x520(%rbp),%rax
   65c1e:	mov    (%rax),%rdi
   65c21:	mov    -0x570(%rbp),%rax
   65c28:	lea    (%rax,%rcx,1),%rdx
   65c2c:	mov    -0x550(%rbp),%rax
   65c33:	add    %rdi,%rax
   65c36:	cmp    %rax,%rdx
   65c39:	jae    6b627 <_IO_vfwscanf+0x7647>
   65c3f:	mov    -0x588(%rbp),%rsi
   65c46:	mov    -0x570(%rbp),%rdi
   65c4d:	mov    %rcx,%rdx
   65c50:	callq  90920 <__GI___mempcpy>
   65c55:	lea    0x1(%rax),%rsi
   65c59:	movb   $0x0,(%rax)
   65c5c:	mov    %rsi,-0x570(%rbp)
   65c63:	mov    -0x520(%rbp),%r13
   65c6a:	mov    -0x570(%rbp),%rsi
   65c71:	mov    0x0(%r13),%rdi
   65c75:	sub    %rdi,%rsi
   65c78:	cmp    %rsi,-0x550(%rbp)
   65c7f:	je     65c8f <_IO_vfwscanf+0x1caf>
   65c81:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   65c86:	test   %rax,%rax
   65c89:	je     65c8f <_IO_vfwscanf+0x1caf>
   65c8b:	mov    %rax,0x0(%r13)
   65c8f:	addl   $0x1,-0x504(%rbp)
   65c96:	movl   $0x0,-0x500(%rbp)
   65ca0:	movq   $0x0,-0x520(%rbp)
   65cab:	jmpq   641fa <_IO_vfwscanf+0x21a>
   65cb0:	mov    0xa0(%r14),%rax
   65cb7:	test   %rax,%rax
   65cba:	je     67f65 <_IO_vfwscanf+0x3f85>
   65cc0:	mov    (%rax),%rdx
   65cc3:	cmp    0x8(%rax),%rdx
   65cc7:	jae    67f65 <_IO_vfwscanf+0x3f85>
   65ccd:	lea    0x4(%rdx),%rcx
   65cd1:	mov    (%rdx),%r15d
   65cd4:	mov    %rcx,(%rax)
   65cd7:	cmp    $0xffffffff,%r15d
   65cdb:	je     67298 <_IO_vfwscanf+0x32b8>
   65ce1:	mov    -0x568(%rbp),%rax
   65ce8:	cmp    $0x25,%r15d
   65cec:	mov    %rax,-0x4f8(%rbp)
   65cf3:	je     641fa <_IO_vfwscanf+0x21a>
   65cf9:	mov    %r15d,%r8d
   65cfc:	mov    %r14,%r15
   65cff:	mov    -0x510(%rbp),%r14
   65d06:	mov    %r8d,%esi
   65d09:	mov    %r15,%rdi
   65d0c:	callq  74430 <_IO_sputbackwc>
   65d11:	mov    -0x504(%rbp),%ebx
   65d17:	movl   $0x2,-0x508(%rbp)
   65d21:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   65d26:	mov    -0x538(%rbp),%rax
   65d2d:	mov    -0x514(%rbp),%ecx
   65d33:	mov    %r14,%r15
   65d36:	mov    -0x510(%rbp),%r14
   65d3d:	mov    %ecx,%fs:(%rax)
   65d40:	mov    -0x504(%rbp),%eax
   65d46:	test   %eax,%eax
   65d48:	je     670f0 <_IO_vfwscanf+0x3110>
   65d4e:	mov    -0x504(%rbp),%ebx
   65d54:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   65d59:	mov    -0x4f8(%rbp),%rsi
   65d60:	mov    %r13d,%eax
   65d63:	mov    $0x10,%r8d
   65d69:	and    $0xfffffff9,%eax
   65d6c:	or     $0x1001,%eax
   65d71:	mov    %eax,%r13d
   65d74:	jmpq   6531e <_IO_vfwscanf+0x133e>
   65d79:	mov    -0x4f8(%rbp),%rsi
   65d80:	mov    $0x10,%r8d
   65d86:	jmpq   65328 <_IO_vfwscanf+0x1348>
   65d8b:	mov    $0xa,%r8d
   65d91:	mov    -0x4f8(%rbp),%rsi
   65d98:	jmpq   65328 <_IO_vfwscanf+0x1348>
   65d9d:	mov    %r14,%r15
   65da0:	mov    -0x538(%rbp),%rax
   65da7:	mov    -0x510(%rbp),%r14
   65dae:	mov    -0x514(%rbp),%edi
   65db4:	mov    %edi,%fs:(%rax)
   65db7:	mov    -0x504(%rbp),%esi
   65dbd:	test   %esi,%esi
   65dbf:	je     67100 <_IO_vfwscanf+0x3120>
   65dc5:	mov    -0x504(%rbp),%ebx
   65dcb:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   65dd0:	mov    $0x8,%r8d
   65dd6:	jmp    65d91 <_IO_vfwscanf+0x1db1>
   65dd8:	mov    -0x4f8(%rbp),%rsi
   65ddf:	mov    $0xffffffff,%r15d
   65de5:	jmpq   65d60 <_IO_vfwscanf+0x1d80>
   65dea:	mov    %r14,%r15
   65ded:	mov    -0x504(%rbp),%ebx
   65df3:	mov    -0x510(%rbp),%r14
   65dfa:	movl   $0x2,-0x508(%rbp)
   65e04:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   65e09:	mov    %r14,%r15
   65e0c:	mov    -0x504(%rbp),%ebx
   65e12:	mov    -0x510(%rbp),%r14
   65e19:	movl   $0x2,-0x508(%rbp)
   65e23:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   65e28:	nopl   0x0(%rax,%rax,1)
   65e30:	cmp    $0xa,%r14d
   65e34:	jne    65503 <_IO_vfwscanf+0x1523>
   65e3a:	cmpb   $0x0,-0x500(%rbp)
   65e41:	jne    65503 <_IO_vfwscanf+0x1523>
   65e47:	cmp    -0x518(%rbp),%r15d
   65e4e:	jne    65503 <_IO_vfwscanf+0x1523>
   65e54:	mov    -0x450(%rbp),%rax
   65e5b:	mov    -0x448(%rbp),%rdx
   65e62:	cmp    %rax,%rdx
   65e65:	je     65f00 <_IO_vfwscanf+0x1f20>
   65e6b:	lea    0x4(%rax),%rdx
   65e6f:	mov    %rdx,-0x450(%rbp)
   65e76:	mov    %r15d,(%rax)
   65e79:	xor    %eax,%eax
   65e7b:	test   %r12d,%r12d
   65e7e:	setg   %al
   65e81:	sub    %eax,%r12d
   65e84:	mov    0xa0(%rbx),%rax
   65e8b:	test   %rax,%rax
   65e8e:	je     65ef0 <_IO_vfwscanf+0x1f10>
   65e90:	mov    (%rax),%rdx
   65e93:	cmp    0x8(%rax),%rdx
   65e97:	jae    65ef0 <_IO_vfwscanf+0x1f10>
   65e99:	lea    0x4(%rdx),%rsi
   65e9d:	mov    (%rdx),%r15d
   65ea0:	mov    %rsi,(%rax)
   65ea3:	cmp    $0xffffffff,%r15d
   65ea7:	je     65ed8 <_IO_vfwscanf+0x1ef8>
   65ea9:	addq   $0x1,-0x4f8(%rbp)
   65eb1:	jmpq   654d8 <_IO_vfwscanf+0x14f8>
   65eb6:	nopw   %cs:0x0(%rax,%rax,1)
   65ec0:	mov    %r15d,%edi
   65ec3:	callq  10b620 <iswxdigit>
   65ec8:	test   %eax,%eax
   65eca:	jne    65e54 <_IO_vfwscanf+0x1e74>
   65ecc:	jmpq   65503 <_IO_vfwscanf+0x1523>
   65ed1:	nopl   0x0(%rax)
   65ed8:	mov    0x359f89(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   65edf:	mov    %fs:(%rax),%eax
   65ee2:	mov    %eax,-0x514(%rbp)
   65ee8:	jmpq   654d8 <_IO_vfwscanf+0x14f8>
   65eed:	nopl   (%rax)
   65ef0:	mov    %rbx,%rdi
   65ef3:	callq  73620 <__wuflow>
   65ef8:	mov    %eax,%r15d
   65efb:	jmp    65ea3 <_IO_vfwscanf+0x1ec3>
   65efd:	nopl   (%rax)
   65f00:	test   %rdx,%rdx
   65f03:	je     65e79 <_IO_vfwscanf+0x1e99>
   65f09:	sub    -0x440(%rbp),%rdx
   65f10:	mov    -0x560(%rbp),%rdi
   65f17:	mov    %rdx,-0x558(%rbp)
   65f1e:	callq  8afb0 <__libc_scratch_buffer_grow_preserve>
   65f23:	test   %al,%al
   65f25:	je     66435 <_IO_vfwscanf+0x2455>
   65f2b:	mov    -0x438(%rbp),%rax
   65f32:	mov    -0x440(%rbp),%rdx
   65f39:	and    $0xfffffffffffffffc,%rax
   65f3d:	add    %rdx,%rax
   65f40:	add    -0x558(%rbp),%rdx
   65f47:	mov    %rax,-0x448(%rbp)
   65f4e:	lea    0x4(%rdx),%rax
   65f52:	mov    %rax,-0x450(%rbp)
   65f59:	mov    %r15d,(%rdx)
   65f5c:	jmpq   65e79 <_IO_vfwscanf+0x1e99>
   65f61:	nopl   0x0(%rax)
   65f68:	mov    0x359ef9(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   65f6f:	mov    %rbx,-0x4f8(%rbp)
   65f76:	mov    %r13,-0x578(%rbp)
   65f7d:	mov    -0x538(%rbp),%rbx
   65f84:	mov    %fs:(%rax),%eax
   65f87:	mov    %eax,-0x514(%rbp)
   65f8d:	jmpq   64cb0 <_IO_vfwscanf+0xcd0>
   65f92:	nopw   0x0(%rax,%rax,1)
   65f98:	mov    %rax,%r13
   65f9b:	jmpq   64c2b <_IO_vfwscanf+0xc4b>
   65fa0:	mov    %r14,%rdi
   65fa3:	callq  73620 <__wuflow>
   65fa8:	mov    %eax,%r15d
   65fab:	jmpq   64c61 <_IO_vfwscanf+0xc81>
   65fb0:	mov    0x359eb1(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   65fb7:	mov    %fs:(%rax),%eax
   65fba:	mov    %eax,-0x514(%rbp)
   65fc0:	test   %r8d,%r8d
   65fc3:	je     65490 <_IO_vfwscanf+0x14b0>
   65fc9:	jmpq   65482 <_IO_vfwscanf+0x14a2>
   65fce:	xchg   %ax,%ax
   65fd0:	test   $0x1000,%r13d
   65fd7:	je     666a5 <_IO_vfwscanf+0x26c5>
   65fdd:	cmp    $0x4,%r12d
   65fe1:	jbe    666a5 <_IO_vfwscanf+0x26c5>
   65fe7:	cmp    $0x28,%r15d
   65feb:	jne    666a5 <_IO_vfwscanf+0x26c5>
   65ff1:	mov    0xa0(%r14),%rax
   65ff8:	test   %rax,%rax
   65ffb:	je     6773e <_IO_vfwscanf+0x375e>
   66001:	mov    (%rax),%rdx
   66004:	cmp    0x8(%rax),%rdx
   66008:	jae    6773e <_IO_vfwscanf+0x375e>
   6600e:	lea    0x4(%rdx),%rcx
   66012:	mov    (%rdx),%r15d
   66015:	mov    %rcx,(%rax)
   66018:	cmp    $0xffffffff,%r15d
   6601c:	mov    %r8d,-0x500(%rbp)
   66023:	je     666d8 <_IO_vfwscanf+0x26f8>
   66029:	mov    %r15d,%edi
   6602c:	callq  10b6c0 <towlower>
   66031:	cmp    $0x6e,%eax
   66034:	mov    -0x500(%rbp),%r8d
   6603b:	je     6619d <_IO_vfwscanf+0x21bd>
   66041:	mov    %r15d,%r8d
   66044:	mov    %r14,%r15
   66047:	mov    -0x510(%rbp),%r14
   6604e:	mov    %r8d,%esi
   66051:	mov    %r15,%rdi
   66054:	callq  74430 <_IO_sputbackwc>
   66059:	mov    -0x504(%rbp),%ebx
   6605f:	movl   $0x2,-0x508(%rbp)
   66069:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6606e:	xchg   %ax,%ax
   66070:	callq  ad150 <__wcstoul_internal>
   66075:	jmpq   655cf <_IO_vfwscanf+0x15ef>
   6607a:	nopw   0x0(%rax,%rax,1)
   66080:	mov    -0x500(%rbp),%eax
   66086:	mov    %r15d,%r8d
   66089:	mov    %r14,%r15
   6608c:	mov    -0x510(%rbp),%r14
   66093:	test   %eax,%eax
   66095:	jne    66338 <_IO_vfwscanf+0x2358>
   6609b:	mov    -0x504(%rbp),%ebx
   660a1:	movl   $0x0,-0x508(%rbp)
   660ab:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   660b0:	testb  $0x10,0x74(%r14)
   660b5:	jne    647da <_IO_vfwscanf+0x7fa>
   660bb:	or     $0x100,%r13d
   660c2:	mov    %eax,%edx
   660c4:	jmpq   64457 <_IO_vfwscanf+0x477>
   660c9:	mov    $0xffffffff,%ebx
   660ce:	mov    %ebx,-0x504(%rbp)
   660d4:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   660d9:	mov    0x359d88(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   660e0:	mov    $0xffffffff,%ebx
   660e5:	movl   $0x9,%fs:(%rax)
   660ec:	jmpq   64631 <_IO_vfwscanf+0x651>
   660f1:	mov    %r14,%rdi
   660f4:	callq  73620 <__wuflow>
   660f9:	jmpq   64ec3 <_IO_vfwscanf+0xee3>
   660fe:	mov    %r13,%rbx
   66101:	xor    %r13d,%r13d
   66104:	jmpq   65b19 <_IO_vfwscanf+0x1b39>
   66109:	mov    %r14,%r15
   6610c:	mov    -0x510(%rbp),%r14
   66113:	jmpq   64a66 <_IO_vfwscanf+0xa86>
   66118:	cmp    %rax,-0x448(%rbp)
   6611f:	jne    65589 <_IO_vfwscanf+0x15a9>
   66125:	mov    -0x528(%rbp),%rax
   6612c:	mov    %rsi,-0x538(%rbp)
   66133:	mov    %r8d,-0x500(%rbp)
   6613a:	lea    0x10(%rax),%rdi
   6613e:	callq  8afb0 <__libc_scratch_buffer_grow_preserve>
   66143:	test   %al,%al
   66145:	mov    -0x500(%rbp),%r8d
   6614c:	mov    -0x538(%rbp),%rsi
   66153:	je     68670 <_IO_vfwscanf+0x4690>
   66159:	mov    -0x440(%rbp),%rax
   66160:	mov    -0x438(%rbp),%rdx
   66167:	lea    (%rax,%rsi,1),%r12
   6616b:	and    $0xfffffffffffffffc,%rdx
   6616f:	add    %rax,%rdx
   66172:	mov    %rdx,-0x448(%rbp)
   66179:	lea    0x4(%r12),%rdx
   6617e:	mov    %rdx,-0x450(%rbp)
   66185:	movl   $0x0,(%r12)
   6618d:	jmpq   6559a <_IO_vfwscanf+0x15ba>
   66192:	mov    $0x8,%r8d
   66198:	jmpq   654a3 <_IO_vfwscanf+0x14c3>
   6619d:	mov    0xa0(%r14),%rax
   661a4:	test   %rax,%rax
   661a7:	je     67800 <_IO_vfwscanf+0x3820>
   661ad:	mov    (%rax),%rdx
   661b0:	cmp    0x8(%rax),%rdx
   661b4:	jae    67800 <_IO_vfwscanf+0x3820>
   661ba:	lea    0x4(%rdx),%rcx
   661be:	mov    (%rdx),%r15d
   661c1:	mov    %rcx,(%rax)
   661c4:	cmp    $0xffffffff,%r15d
   661c8:	mov    %r8d,-0x500(%rbp)
   661cf:	je     66fed <_IO_vfwscanf+0x300d>
   661d5:	mov    %r15d,%edi
   661d8:	callq  10b6c0 <towlower>
   661dd:	cmp    $0x69,%eax
   661e0:	mov    -0x500(%rbp),%r8d
   661e7:	jne    66041 <_IO_vfwscanf+0x2061>
   661ed:	mov    0xa0(%r14),%rax
   661f4:	test   %rax,%rax
   661f7:	je     67900 <_IO_vfwscanf+0x3920>
   661fd:	mov    (%rax),%rdx
   66200:	cmp    0x8(%rax),%rdx
   66204:	jae    67900 <_IO_vfwscanf+0x3920>
   6620a:	lea    0x4(%rdx),%rcx
   6620e:	mov    (%rdx),%r15d
   66211:	mov    %rcx,(%rax)
   66214:	cmp    $0xffffffff,%r15d
   66218:	mov    %r8d,-0x500(%rbp)
   6621f:	je     66fcd <_IO_vfwscanf+0x2fed>
   66225:	mov    %r15d,%edi
   66228:	callq  10b6c0 <towlower>
   6622d:	cmp    $0x6c,%eax
   66230:	mov    -0x500(%rbp),%r8d
   66237:	jne    66041 <_IO_vfwscanf+0x2061>
   6623d:	mov    0xa0(%r14),%rax
   66244:	test   %rax,%rax
   66247:	je     66cda <_IO_vfwscanf+0x2cfa>
   6624d:	mov    (%rax),%rdx
   66250:	cmp    0x8(%rax),%rdx
   66254:	jae    66cda <_IO_vfwscanf+0x2cfa>
   6625a:	lea    0x4(%rdx),%rcx
   6625e:	mov    (%rdx),%r15d
   66261:	mov    %rcx,(%rax)
   66264:	cmp    $0xffffffff,%r15d
   66268:	je     66947 <_IO_vfwscanf+0x2967>
   6626e:	addq   $0x4,-0x4f8(%rbp)
   66276:	cmp    $0x29,%r15d
   6627a:	jne    66041 <_IO_vfwscanf+0x2061>
   66280:	mov    -0x450(%rbp),%rcx
   66287:	mov    -0x448(%rbp),%rdx
   6628e:	cmp    %rcx,%rdx
   66291:	je     67020 <_IO_vfwscanf+0x3040>
   66297:	lea    0x4(%rcx),%rax
   6629b:	mov    %rax,-0x450(%rbp)
   662a2:	movl   $0x30,(%rcx)
   662a8:	jmpq   65580 <_IO_vfwscanf+0x15a0>
   662ad:	mov    0x359bb4(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   662b4:	mov    %r14,%r15
   662b7:	mov    -0x510(%rbp),%r14
   662be:	mov    %rax,-0x538(%rbp)
   662c5:	jmpq   64a5d <_IO_vfwscanf+0xa7d>
   662ca:	test   $0x1,%r13b
   662ce:	je     66a99 <_IO_vfwscanf+0x2ab9>
   662d4:	mov    -0x530(%rbp),%r10d
   662db:	test   %r10d,%r10d
   662de:	je     65616 <_IO_vfwscanf+0x1636>
   662e4:	mov    -0x580(%rbp),%rdi
   662eb:	mov    -0x588(%rbp),%r11
   662f2:	xor    %r8d,%r8d
   662f5:	mov    -0x530(%rbp),%r9d
   662fc:	mov    (%rdi),%rdx
   662ff:	mov    %rdx,(%r11)
   66302:	mov    0x8(%rdi),%rcx
   66306:	mov    %rcx,0x8(%r11)
   6630a:	mov    0x10(%rdi),%rsi
   6630e:	xor    %edi,%edi
   66310:	mov    %rsi,0x10(%r11)
   66314:	mov    %edx,%esi
   66316:	sub    $0x1,%r9d
   6631a:	je     6aa83 <_IO_vfwscanf+0x6aa3>
   66320:	cmp    $0x2f,%esi
   66323:	ja     69813 <_IO_vfwscanf+0x5833>
   66329:	add    $0x8,%esi
   6632c:	mov    $0x1,%r8d
   66332:	jmp    66316 <_IO_vfwscanf+0x2336>
   66334:	nopl   0x0(%rax)
   66338:	cmp    $0xffffffff,%r8d
   6633c:	je     6700d <_IO_vfwscanf+0x302d>
   66342:	nopw   0x0(%rax,%rax,1)
   66348:	mov    0xa0(%r15),%rax
   6634f:	test   %rax,%rax
   66352:	je     663fa <_IO_vfwscanf+0x241a>
   66358:	mov    (%rax),%rdx
   6635b:	cmp    0x8(%rax),%rdx
   6635f:	jae    663fa <_IO_vfwscanf+0x241a>
   66365:	lea    0x4(%rdx),%rcx
   66369:	mov    (%rdx),%ebx
   6636b:	mov    %rcx,(%rax)
   6636e:	cmp    $0xffffffff,%ebx
   66371:	je     663a0 <_IO_vfwscanf+0x23c0>
   66373:	mov    %ebx,%edi
   66375:	callq  10b4f0 <iswspace>
   6637a:	test   %eax,%eax
   6637c:	jne    66348 <_IO_vfwscanf+0x2368>
   6637e:	mov    %ebx,%esi
   66380:	mov    %r15,%rdi
   66383:	mov    %eax,-0x508(%rbp)
   66389:	callq  74430 <_IO_sputbackwc>
   6638e:	mov    -0x504(%rbp),%ebx
   66394:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   66399:	nopl   0x0(%rax)
   663a0:	mov    0x359ac1(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   663a7:	mov    %ebx,%edi
   663a9:	mov    %rax,-0x538(%rbp)
   663b0:	mov    %fs:(%rax),%eax
   663b3:	mov    %eax,-0x514(%rbp)
   663b9:	callq  10b4f0 <iswspace>
   663be:	test   %eax,%eax
   663c0:	je     663e5 <_IO_vfwscanf+0x2405>
   663c2:	mov    -0x514(%rbp),%r12d
   663c9:	mov    -0x538(%rbp),%r13
   663d0:	mov    $0xffffffff,%ebx
   663d5:	mov    %ebx,%edi
   663d7:	mov    %r12d,%fs:0x0(%r13)
   663dc:	callq  10b4f0 <iswspace>
   663e1:	test   %eax,%eax
   663e3:	jne    663d5 <_IO_vfwscanf+0x23f5>
   663e5:	mov    -0x504(%rbp),%ebx
   663eb:	movl   $0x0,-0x508(%rbp)
   663f5:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   663fa:	mov    %r15,%rdi
   663fd:	callq  73620 <__wuflow>
   66402:	mov    %eax,%ebx
   66404:	jmpq   6636e <_IO_vfwscanf+0x238e>
   66409:	mov    %r14,%rdi
   6640c:	mov    %rsi,-0x538(%rbp)
   66413:	mov    %r8d,-0x500(%rbp)
   6641a:	callq  73620 <__wuflow>
   6641f:	mov    -0x500(%rbp),%r8d
   66426:	mov    %eax,%r15d
   66429:	mov    -0x538(%rbp),%rsi
   66430:	jmpq   6534f <_IO_vfwscanf+0x136f>
   66435:	pxor   %xmm0,%xmm0
   66439:	movaps %xmm0,-0x450(%rbp)
   66440:	jmpq   65e79 <_IO_vfwscanf+0x1e99>
   66445:	lea    0x8(%rbx),%rax
   66449:	or     $0x200,%r13d
   66450:	mov    0x8(%rbx),%edx
   66453:	mov    %rax,-0x558(%rbp)
   6645a:	jmpq   64457 <_IO_vfwscanf+0x477>
   6645f:	lea    0x8(%rbx),%rax
   66463:	or     $0x3,%r13d
   66467:	mov    0x8(%rbx),%edx
   6646a:	mov    %rax,-0x558(%rbp)
   66471:	jmpq   64457 <_IO_vfwscanf+0x477>
   66476:	lea    0x8(%rbx),%rax
   6647a:	or     $0x2001,%r13d
   66481:	mov    0x8(%rbx),%edx
   66484:	mov    %rax,-0x558(%rbp)
   6648b:	jmpq   64457 <_IO_vfwscanf+0x477>
   66490:	mov    0x3599d1(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   66497:	mov    -0x538(%rbp),%rbx
   6649e:	mov    -0x558(%rbp),%r13d
   664a5:	mov    %r12,-0x570(%rbp)
   664ac:	mov    %fs:(%rax),%eax
   664af:	mov    %eax,-0x514(%rbp)
   664b5:	mov    -0x560(%rbp),%edi
   664bb:	test   %edi,%edi
   664bd:	jne    641fa <_IO_vfwscanf+0x21a>
   664c3:	and    $0x2100,%r13d
   664ca:	je     65c8f <_IO_vfwscanf+0x1caf>
   664d0:	jmpq   65c63 <_IO_vfwscanf+0x1c83>
   664d5:	nopl   (%rax)
   664d8:	mov    %r13d,%edx
   664db:	lea    -0x1(%r12),%r13d
   664e0:	movslq %r12d,%r12
   664e3:	add    %rax,%r12
   664e6:	and    $0x2100,%edx
   664ec:	mov    %r14,%rsi
   664ef:	mov    %r12,-0x558(%rbp)
   664f6:	mov    %edx,%r12d
   664f9:	mov    %rbx,-0x530(%rbp)
   66500:	test   %r12d,%r12d
   66503:	mov    %rax,%rbx
   66506:	mov    %r13d,%r14d
   66509:	mov    -0x578(%rbp),%rax
   66510:	mov    %rsi,%r13
   66513:	je     6653e <_IO_vfwscanf+0x255e>
   66515:	nopl   (%rax)
   66518:	mov    -0x520(%rbp),%rdi
   6651f:	mov    -0x550(%rbp),%rsi
   66526:	mov    (%rdi),%rdi
   66529:	lea    0x0(,%rsi,4),%r8
   66531:	lea    (%rdi,%r8,1),%rsi
   66535:	cmp    %rsi,%rax
   66538:	je     6662e <_IO_vfwscanf+0x264e>
   6653e:	test   %r14d,%r14d
   66541:	lea    0x4(%rax),%r8
   66545:	mov    %r15d,(%rax)
   66548:	jle    66b85 <_IO_vfwscanf+0x2ba5>
   6654e:	mov    0xa0(%r13),%rax
   66555:	test   %rax,%rax
   66558:	je     66610 <_IO_vfwscanf+0x2630>
   6655e:	mov    (%rax),%rsi
   66561:	cmp    0x8(%rax),%rsi
   66565:	jae    66610 <_IO_vfwscanf+0x2630>
   6656b:	lea    0x4(%rsi),%rdi
   6656f:	mov    (%rsi),%r15d
   66572:	mov    %rdi,(%rax)
   66575:	sub    $0x1,%r14d
   66579:	cmp    $0xffffffff,%r15d
   6657d:	je     66590 <_IO_vfwscanf+0x25b0>
   6657f:	add    $0x1,%rbx
   66583:	test   %r12d,%r12d
   66586:	mov    %r8,%rax
   66589:	je     6653e <_IO_vfwscanf+0x255e>
   6658b:	jmp    66518 <_IO_vfwscanf+0x2538>
   6658d:	nopl   (%rax)
   66590:	mov    0x3598d1(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   66597:	mov    %rbx,-0x4f8(%rbp)
   6659e:	mov    %r12d,%edx
   665a1:	mov    -0x530(%rbp),%rbx
   665a8:	mov    %r8,%r12
   665ab:	mov    %r13,%r14
   665ae:	mov    %fs:(%rax),%eax
   665b1:	mov    %eax,-0x514(%rbp)
   665b7:	test   %edx,%edx
   665b9:	je     665ea <_IO_vfwscanf+0x260a>
   665bb:	mov    -0x520(%rbp),%r13
   665c2:	mov    %r12,%rsi
   665c5:	mov    0x0(%r13),%rdi
   665c9:	sub    %rdi,%rsi
   665cc:	mov    %rsi,%rax
   665cf:	sar    $0x2,%rax
   665d3:	cmp    -0x550(%rbp),%rax
   665da:	je     665ea <_IO_vfwscanf+0x260a>
   665dc:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   665e1:	test   %rax,%rax
   665e4:	je     665ea <_IO_vfwscanf+0x260a>
   665e6:	mov    %rax,0x0(%r13)
   665ea:	addl   $0x1,-0x504(%rbp)
   665f1:	mov    %r12,-0x578(%rbp)
   665f8:	movq   $0x0,-0x520(%rbp)
   66603:	jmpq   641fa <_IO_vfwscanf+0x21a>
   66608:	nopl   0x0(%rax,%rax,1)
   66610:	mov    %r13,%rdi
   66613:	mov    %r8,-0x4f8(%rbp)
   6661a:	callq  73620 <__wuflow>
   6661f:	mov    -0x4f8(%rbp),%r8
   66626:	mov    %eax,%r15d
   66629:	jmpq   66575 <_IO_vfwscanf+0x2595>
   6662e:	mov    -0x558(%rbp),%rax
   66635:	mov    -0x550(%rbp),%rsi
   6663c:	movslq %r14d,%r10
   6663f:	mov    %r8,-0x538(%rbp)
   66646:	sub    %rbx,%rax
   66649:	cmp    %rax,%rsi
   6664c:	cmovle %rsi,%r10
   66650:	add    %rsi,%r10
   66653:	lea    0x0(,%r10,4),%rsi
   6665b:	mov    %r10,-0x4f8(%rbp)
   66662:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   66667:	test   %rax,%rax
   6666a:	mov    -0x4f8(%rbp),%r10
   66671:	mov    -0x538(%rbp),%r8
   66678:	je     69059 <_IO_vfwscanf+0x5079>
   6667e:	mov    -0x520(%rbp),%rdi
   66685:	mov    %r10,-0x550(%rbp)
   6668c:	mov    %rax,(%rdi)
   6668f:	add    %r8,%rax
   66692:	jmpq   6653e <_IO_vfwscanf+0x255e>
   66697:	mov    (%rcx),%edx
   66699:	sub    $0x2b,%edx
   6669c:	and    $0xfffffffd,%edx
   6669f:	jne    65547 <_IO_vfwscanf+0x1567>
   666a5:	mov    %r15d,%r8d
   666a8:	mov    %r14,%r15
   666ab:	mov    -0x510(%rbp),%r14
   666b2:	cmp    $0xffffffff,%r8d
   666b6:	jne    6604e <_IO_vfwscanf+0x206e>
   666bc:	mov    -0x504(%rbp),%ebx
   666c2:	movl   $0x2,-0x508(%rbp)
   666cc:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   666d1:	nopl   0x0(%rax)
   666d8:	mov    0x359789(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   666df:	mov    %r15d,%r8d
   666e2:	mov    %r14,%r15
   666e5:	mov    %r8d,%edi
   666e8:	mov    -0x510(%rbp),%r14
   666ef:	mov    %rax,-0x538(%rbp)
   666f6:	mov    %fs:(%rax),%ebx
   666f9:	callq  10b6c0 <towlower>
   666fe:	cmp    $0x6e,%eax
   66701:	je     66c91 <_IO_vfwscanf+0x2cb1>
   66707:	mov    -0x504(%rbp),%ebx
   6670d:	movl   $0x2,-0x508(%rbp)
   66717:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6671c:	mov    0x359745(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   66723:	mov    %rbx,-0x500(%rbp)
   6672a:	mov    -0x598(%rbp),%r13d
   66731:	mov    -0x560(%rbp),%rbx
   66738:	mov    %fs:(%rax),%eax
   6673b:	mov    %eax,-0x514(%rbp)
   66741:	mov    -0x450(%rbp),%rdx
   66748:	test   %rdx,%rdx
   6674b:	je     69c80 <_IO_vfwscanf+0x5ca0>
   66751:	test   $0x400,%r13d
   66758:	jne    6999c <_IO_vfwscanf+0x59bc>
   6675e:	mov    %rdx,%rax
   66761:	sub    -0x440(%rbp),%rax
   66768:	sar    $0x2,%rax
   6676c:	test   %rax,%rax
   6676f:	je     6a950 <_IO_vfwscanf+0x6970>
   66775:	cmp    $0x2,%rax
   66779:	jne    66789 <_IO_vfwscanf+0x27a9>
   6677b:	mov    -0x5a0(%rbp),%eax
   66781:	test   %eax,%eax
   66783:	jne    6a715 <_IO_vfwscanf+0x6735>
   66789:	mov    -0x500(%rbp),%rsi
   66790:	mov    -0x448(%rbp),%rax
   66797:	mov    %rsi,-0x4f8(%rbp)
   6679e:	cmp    %rax,%rdx
   667a1:	je     69559 <_IO_vfwscanf+0x5579>
   667a7:	lea    0x4(%rdx),%rax
   667ab:	mov    %rax,-0x450(%rbp)
   667b2:	movl   $0x0,(%rdx)
   667b8:	test   %rax,%rax
   667bb:	je     69573 <_IO_vfwscanf+0x5593>
   667c1:	mov    %r13d,%edx
   667c4:	lea    -0x4e0(%rbp),%rsi
   667cb:	mov    -0x440(%rbp),%rdi
   667d2:	and    $0x80,%edx
   667d8:	test   $0x2,%r13b
   667dc:	jne    68025 <_IO_vfwscanf+0x4045>
   667e2:	test   $0x3,%r13b
   667e6:	je     67e92 <_IO_vfwscanf+0x3eb2>
   667ec:	callq  ad180 <__wcstod_internal>
   667f1:	and    $0x8,%r13d
   667f5:	jne    67392 <_IO_vfwscanf+0x33b2>
   667fb:	mov    -0x440(%rbp),%rdx
   66802:	mov    -0x4e0(%rbp),%rcx
   66809:	cmp    %rdx,%rcx
   6680c:	je     698ff <_IO_vfwscanf+0x591f>
   66812:	mov    -0x530(%rbp),%r13d
   66819:	test   %r13d,%r13d
   6681c:	jne    691a9 <_IO_vfwscanf+0x51c9>
   66822:	mov    -0x4d8(%rbp),%esi
   66828:	cmp    $0x2f,%esi
   6682b:	ja     69977 <_IO_vfwscanf+0x5997>
   66831:	mov    %esi,%eax
   66833:	add    -0x4c8(%rbp),%rax
   6683a:	add    $0x8,%esi
   6683d:	mov    %esi,-0x4d8(%rbp)
   66843:	mov    (%rax),%rax
   66846:	cmpb   $0x0,-0x568(%rbp)
   6684d:	je     66857 <_IO_vfwscanf+0x2877>
   6684f:	xorpd  0x12aad9(%rip),%xmm0        # 191330 <signmask>
   66857:	movsd  %xmm0,(%rax)
   6685b:	cmp    %rdx,%rcx
   6685e:	je     6914a <_IO_vfwscanf+0x516a>
   66864:	addl   $0x1,-0x504(%rbp)
   6686b:	movl   $0x0,-0x500(%rbp)
   66875:	jmpq   641fa <_IO_vfwscanf+0x21a>
   6687a:	mov    -0x538(%rbp),%rax
   66881:	mov    %r13,-0x570(%rbp)
   66888:	mov    -0x568(%rbp),%rbx
   6688f:	mov    -0x560(%rbp),%r13d
   66896:	mov    %fs:(%rax),%eax
   66899:	mov    %eax,-0x514(%rbp)
   6689f:	jmpq   65bd6 <_IO_vfwscanf+0x1bf6>
   668a4:	mov    -0x5a0(%rbp),%esi
   668aa:	test   %esi,%esi
   668ac:	je     66956 <_IO_vfwscanf+0x2976>
   668b2:	mov    %r15d,%edi
   668b5:	mov    %rdx,-0x500(%rbp)
   668bc:	callq  10b620 <iswxdigit>
   668c1:	test   %eax,%eax
   668c3:	mov    -0x500(%rbp),%rdx
   668ca:	je     66956 <_IO_vfwscanf+0x2976>
   668d0:	cmp    -0x448(%rbp),%rdx
   668d7:	jne    65859 <_IO_vfwscanf+0x1879>
   668dd:	mov    -0x528(%rbp),%rdi
   668e4:	mov    %r15d,%esi
   668e7:	mov    $0x1,%r13d
   668ed:	callq  63f80 <char_buffer_add_slow>
   668f2:	jmpq   6586d <_IO_vfwscanf+0x188d>
   668f7:	nopw   0x0(%rax,%rax,1)
   66900:	mov    0x359561(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   66907:	mov    $0xffffffff,%ebx
   6690c:	mov    %r14,%r15
   6690f:	movl   $0x0,-0x508(%rbp)
   66919:	mov    -0x510(%rbp),%r14
   66920:	mov    %ebx,-0x504(%rbp)
   66926:	movl   $0xc,%fs:(%rax)
   6692d:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   66932:	mov    0x35952f(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   66939:	mov    %fs:(%rax),%eax
   6693c:	mov    %eax,-0x514(%rbp)
   66942:	jmpq   65455 <_IO_vfwscanf+0x1475>
   66947:	mov    %r14,%r15
   6694a:	mov    -0x510(%rbp),%r14
   66951:	jmpq   666bc <_IO_vfwscanf+0x26dc>
   66956:	test   %r13b,%r13b
   66959:	je     658f9 <_IO_vfwscanf+0x1919>
   6695f:	mov    %r15d,%edi
   66962:	mov    %rdx,-0x500(%rbp)
   66969:	callq  10b6c0 <towlower>
   6696e:	cmp    %eax,-0x4f8(%rbp)
   66974:	mov    -0x500(%rbp),%rdx
   6697b:	jne    658f9 <_IO_vfwscanf+0x1919>
   66981:	cmp    -0x448(%rbp),%rdx
   66988:	je     6b285 <_IO_vfwscanf+0x72a5>
   6698e:	lea    0x4(%rdx),%rax
   66992:	mov    %r13b,-0x558(%rbp)
   66999:	mov    %r13b,-0x538(%rbp)
   669a0:	mov    %rax,-0x450(%rbp)
   669a7:	mov    -0x4f8(%rbp),%eax
   669ad:	mov    %eax,(%rdx)
   669af:	jmpq   6586d <_IO_vfwscanf+0x188d>
   669b4:	and    $0x8,%eax
   669b7:	mov    %eax,-0x500(%rbp)
   669bd:	jne    65233 <_IO_vfwscanf+0x1253>
   669c3:	test   $0x2100,%r13d
   669ca:	je     6754d <_IO_vfwscanf+0x356d>
   669d0:	mov    -0x530(%rbp),%r9d
   669d7:	test   %r9d,%r9d
   669da:	jne    68228 <_IO_vfwscanf+0x4248>
   669e0:	mov    -0x4d8(%rbp),%edx
   669e6:	cmp    $0x2f,%edx
   669e9:	ja     6ab10 <_IO_vfwscanf+0x6b30>
   669ef:	mov    %edx,%eax
   669f1:	add    -0x4c8(%rbp),%rax
   669f8:	add    $0x8,%edx
   669fb:	mov    %edx,-0x4d8(%rbp)
   66a01:	mov    (%rax),%rax
   66a04:	mov    %rax,-0x520(%rbp)
   66a0b:	cmpq   $0x0,-0x520(%rbp)
   66a13:	je     6aaf1 <_IO_vfwscanf+0x6b11>
   66a19:	mov    $0x64,%edi
   66a1e:	callq  1f998 <*ABS*+0x911b0@plt+0x18>
   66a23:	mov    -0x520(%rbp),%rdi
   66a2a:	test   %rax,%rax
   66a2d:	mov    %rax,(%rdi)
   66a30:	je     6948d <_IO_vfwscanf+0x54ad>
   66a36:	mov    -0x510(%rbp),%rcx
   66a3d:	test   %rcx,%rcx
   66a40:	je     687ec <_IO_vfwscanf+0x480c>
   66a46:	mov    (%rcx),%rdx
   66a49:	cmp    $0x20,%rdx
   66a4d:	je     687ec <_IO_vfwscanf+0x480c>
   66a53:	lea    0x1(%rdx),%rcx
   66a57:	mov    -0x510(%rbp),%rsi
   66a5e:	mov    %rax,-0x570(%rbp)
   66a65:	movq   $0x64,-0x550(%rbp)
   66a70:	mov    %rcx,(%rsi)
   66a73:	mov    %rdi,0x10(%rsi,%rdx,8)
   66a78:	jmpq   65233 <_IO_vfwscanf+0x1253>
   66a7d:	mov    %r14,%rdi
   66a80:	callq  73620 <__wuflow>
   66a85:	mov    %eax,%r15d
   66a88:	jmpq   650ca <_IO_vfwscanf+0x10ea>
   66a8d:	movb   $0x0,-0x568(%rbp)
   66a94:	jmpq   65739 <_IO_vfwscanf+0x1759>
   66a99:	test   $0x4,%r13b
   66a9d:	je     67250 <_IO_vfwscanf+0x3270>
   66aa3:	mov    -0x530(%rbp),%r9d
   66aaa:	test   %r9d,%r9d
   66aad:	jne    681d5 <_IO_vfwscanf+0x41f5>
   66ab3:	mov    -0x4d8(%rbp),%ecx
   66ab9:	cmp    $0x2f,%ecx
   66abc:	ja     6a734 <_IO_vfwscanf+0x6754>
   66ac2:	mov    %ecx,%edx
   66ac4:	add    -0x4c8(%rbp),%rdx
   66acb:	add    $0x8,%ecx
   66ace:	mov    %ecx,-0x4d8(%rbp)
   66ad4:	mov    (%rdx),%rdx
   66ad7:	mov    %ax,(%rdx)
   66ada:	jmpq   6563d <_IO_vfwscanf+0x165d>
   66adf:	test   $0x4,%r13b
   66ae3:	je     6731f <_IO_vfwscanf+0x333f>
   66ae9:	mov    -0x530(%rbp),%r13d
   66af0:	test   %r13d,%r13d
   66af3:	je     66ab3 <_IO_vfwscanf+0x2ad3>
   66af5:	mov    -0x580(%rbp),%rcx
   66afc:	mov    -0x588(%rbp),%r11
   66b03:	xor    %r8d,%r8d
   66b06:	mov    -0x530(%rbp),%r9d
   66b0d:	mov    (%rcx),%rdx
   66b10:	mov    %rcx,%rdi
   66b13:	mov    %rdx,(%r11)
   66b16:	mov    0x8(%rcx),%rcx
   66b1a:	mov    %rcx,0x8(%r11)
   66b1e:	mov    0x10(%rdi),%rsi
   66b22:	xor    %edi,%edi
   66b24:	mov    %rsi,0x10(%r11)
   66b28:	mov    %edx,%esi
   66b2a:	sub    $0x1,%r9d
   66b2e:	je     69885 <_IO_vfwscanf+0x58a5>
   66b34:	cmp    $0x2f,%esi
   66b37:	ja     6aa03 <_IO_vfwscanf+0x6a23>
   66b3d:	add    $0x8,%esi
   66b40:	mov    $0x1,%r8d
   66b46:	jmp    66b2a <_IO_vfwscanf+0x2b4a>
   66b48:	nopl   0x0(%rax,%rax,1)
   66b50:	mov    0x359311(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   66b57:	mov    -0x514(%rbp),%esi
   66b5d:	mov    %r14,%r15
   66b60:	mov    -0x510(%rbp),%r14
   66b67:	mov    %esi,%fs:(%rax)
   66b6a:	mov    -0x504(%rbp),%r11d
   66b71:	test   %r11d,%r11d
   66b74:	je     66cf8 <_IO_vfwscanf+0x2d18>
   66b7a:	mov    -0x504(%rbp),%ebx
   66b80:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   66b85:	mov    %rbx,-0x4f8(%rbp)
   66b8c:	mov    %r12d,%edx
   66b8f:	mov    -0x530(%rbp),%rbx
   66b96:	mov    %r8,%r12
   66b99:	mov    %r13,%r14
   66b9c:	jmpq   665b7 <_IO_vfwscanf+0x25d7>
   66ba1:	mov    0x3592c0(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   66ba8:	mov    -0x514(%rbp),%esi
   66bae:	mov    %r14,%r15
   66bb1:	mov    -0x510(%rbp),%r14
   66bb8:	mov    %esi,%fs:(%rax)
   66bbb:	mov    -0x504(%rbp),%r12d
   66bc2:	test   %r12d,%r12d
   66bc5:	je     66dbc <_IO_vfwscanf+0x2ddc>
   66bcb:	mov    -0x504(%rbp),%ebx
   66bd1:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   66bd6:	mov    -0x5a8(%rbp),%ecx
   66bdc:	test   %ecx,%ecx
   66bde:	je     6a05f <_IO_vfwscanf+0x607f>
   66be4:	cmp    -0x518(%rbp),%r15d
   66beb:	jne    6a05f <_IO_vfwscanf+0x607f>
   66bf1:	test   %al,%al
   66bf3:	je     6a05f <_IO_vfwscanf+0x607f>
   66bf9:	cmp    -0x448(%rbp),%rdx
   66c00:	je     695a5 <_IO_vfwscanf+0x55c5>
   66c06:	lea    0x4(%rdx),%rax
   66c0a:	movb   $0x0,-0x538(%rbp)
   66c11:	mov    %rax,-0x450(%rbp)
   66c18:	mov    %r15d,(%rdx)
   66c1b:	jmpq   6586d <_IO_vfwscanf+0x188d>
   66c20:	mov    %r14,%rdi
   66c23:	callq  73620 <__wuflow>
   66c28:	mov    %eax,%r15d
   66c2b:	jmpq   658a7 <_IO_vfwscanf+0x18c7>
   66c30:	mov    %r14,%rdi
   66c33:	callq  73620 <__wuflow>
   66c38:	mov    %eax,%r15d
   66c3b:	jmpq   65b8c <_IO_vfwscanf+0x1bac>
   66c40:	mov    %r14,%r15
   66c43:	mov    -0x504(%rbp),%ebx
   66c49:	mov    -0x510(%rbp),%r14
   66c50:	movl   $0x2,-0x508(%rbp)
   66c5a:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   66c5f:	mov    %r14,%r15
   66c62:	mov    -0x510(%rbp),%r14
   66c69:	mov    0x3591f8(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   66c70:	mov    $0xffffffff,%ebx
   66c75:	movl   $0x0,-0x508(%rbp)
   66c7f:	mov    %ebx,-0x504(%rbp)
   66c85:	movl   $0xc,%fs:(%rax)
   66c8c:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   66c91:	mov    -0x538(%rbp),%rax
   66c98:	mov    %ebx,%fs:(%rax)
   66c9b:	mov    $0xffffffff,%edi
   66ca0:	callq  10b6c0 <towlower>
   66ca5:	cmp    $0x69,%eax
   66ca8:	jne    66707 <_IO_vfwscanf+0x2727>
   66cae:	mov    -0x538(%rbp),%rax
   66cb5:	mov    %ebx,%fs:(%rax)
   66cb8:	mov    $0xffffffff,%edi
   66cbd:	callq  10b6c0 <towlower>
   66cc2:	cmp    $0x6c,%eax
   66cc5:	jne    66707 <_IO_vfwscanf+0x2727>
   66ccb:	mov    -0x538(%rbp),%rax
   66cd2:	mov    %ebx,%fs:(%rax)
   66cd5:	jmpq   66707 <_IO_vfwscanf+0x2727>
   66cda:	mov    %r14,%rdi
   66cdd:	mov    %r8d,-0x500(%rbp)
   66ce4:	callq  73620 <__wuflow>
   66ce9:	mov    -0x500(%rbp),%r8d
   66cf0:	mov    %eax,%r15d
   66cf3:	jmpq   66264 <_IO_vfwscanf+0x2284>
   66cf8:	mov    $0xffffffff,%ebx
   66cfd:	mov    %ebx,-0x504(%rbp)
   66d03:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   66d08:	mov    %r14,%rdi
   66d0b:	mov    %r8d,-0x500(%rbp)
   66d12:	callq  73620 <__wuflow>
   66d17:	mov    -0x500(%rbp),%r8d
   66d1e:	mov    %eax,%r15d
   66d21:	jmpq   65443 <_IO_vfwscanf+0x1463>
   66d26:	mov    -0x530(%rbp),%r9d
   66d2d:	test   %r9d,%r9d
   66d30:	jne    6775c <_IO_vfwscanf+0x377c>
   66d36:	mov    -0x4d8(%rbp),%edx
   66d3c:	cmp    $0x2f,%edx
   66d3f:	ja     6b2aa <_IO_vfwscanf+0x72ca>
   66d45:	mov    %edx,%eax
   66d47:	add    -0x4c8(%rbp),%rax
   66d4e:	add    $0x8,%edx
   66d51:	mov    %edx,-0x4d8(%rbp)
   66d57:	mov    (%rax),%rax
   66d5a:	mov    %rax,-0x578(%rbp)
   66d61:	cmpq   $0x0,-0x578(%rbp)
   66d69:	jne    64b55 <_IO_vfwscanf+0xb75>
   66d6f:	mov    %r14,%r15
   66d72:	mov    -0x504(%rbp),%ebx
   66d78:	mov    -0x510(%rbp),%r14
   66d7f:	movl   $0x2,-0x508(%rbp)
   66d89:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   66d8e:	xchg   %ax,%ax
   66d90:	mov    %r14,%rdi
   66d93:	mov    %rsi,-0x538(%rbp)
   66d9a:	mov    %r8d,-0x500(%rbp)
   66da1:	callq  73620 <__wuflow>
   66da6:	mov    -0x500(%rbp),%r8d
   66dad:	mov    %eax,%r15d
   66db0:	mov    -0x538(%rbp),%rsi
   66db7:	jmpq   653c1 <_IO_vfwscanf+0x13e1>
   66dbc:	mov    $0xffffffff,%ebx
   66dc1:	mov    %ebx,-0x504(%rbp)
   66dc7:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   66dcc:	mov    -0x530(%rbp),%ecx
   66dd2:	test   %ecx,%ecx
   66dd4:	jne    67856 <_IO_vfwscanf+0x3876>
   66dda:	mov    -0x4d8(%rbp),%edx
   66de0:	cmp    $0x2f,%edx
   66de3:	ja     6b4a2 <_IO_vfwscanf+0x74c2>
   66de9:	mov    %edx,%eax
   66deb:	add    -0x4c8(%rbp),%rax
   66df2:	add    $0x8,%edx
   66df5:	mov    %edx,-0x4d8(%rbp)
   66dfb:	mov    (%rax),%rax
   66dfe:	mov    %rax,-0x578(%rbp)
   66e05:	cmpq   $0x0,-0x578(%rbp)
   66e0d:	jne    64e16 <_IO_vfwscanf+0xe36>
   66e13:	mov    %r14,%r15
   66e16:	mov    -0x504(%rbp),%ebx
   66e1c:	mov    -0x510(%rbp),%r14
   66e23:	movl   $0x2,-0x508(%rbp)
   66e2d:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   66e32:	nopw   0x0(%rax,%rax,1)
   66e38:	mov    -0x504(%rbp),%ecx
   66e3e:	mov    %r14,%r15
   66e41:	mov    -0x510(%rbp),%r14
   66e48:	test   %ecx,%ecx
   66e4a:	mov    %ecx,%ebx
   66e4c:	jne    64590 <_IO_vfwscanf+0x5b0>
   66e52:	mov    %eax,%ebx
   66e54:	mov    %eax,-0x504(%rbp)
   66e5a:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   66e5f:	mov    %r14,%r15
   66e62:	mov    -0x510(%rbp),%r14
   66e69:	jmpq   66bbb <_IO_vfwscanf+0x2bdb>
   66e6e:	test   %rdx,%rdx
   66e71:	je     6541c <_IO_vfwscanf+0x143c>
   66e77:	mov    -0x528(%rbp),%rax
   66e7e:	sub    -0x440(%rbp),%rdx
   66e85:	mov    %r8d,-0x500(%rbp)
   66e8c:	lea    0x10(%rax),%rdi
   66e90:	mov    %rdx,%r15
   66e93:	callq  8afb0 <__libc_scratch_buffer_grow_preserve>
   66e98:	test   %al,%al
   66e9a:	mov    -0x500(%rbp),%r8d
   66ea1:	je     6947d <_IO_vfwscanf+0x549d>
   66ea7:	mov    -0x438(%rbp),%rdx
   66eae:	mov    -0x440(%rbp),%rax
   66eb5:	and    $0xfffffffffffffffc,%rdx
   66eb9:	add    %rax,%rdx
   66ebc:	mov    %rdx,-0x448(%rbp)
   66ec3:	lea    (%rax,%r15,1),%rdx
   66ec7:	lea    0x4(%rdx),%rax
   66ecb:	mov    %rax,-0x450(%rbp)
   66ed2:	movl   $0x30,(%rdx)
   66ed8:	jmpq   6541c <_IO_vfwscanf+0x143c>
   66edd:	mov    %r14,%r15
   66ee0:	mov    -0x510(%rbp),%r14
   66ee7:	jmpq   66b6a <_IO_vfwscanf+0x2b8a>
   66eec:	mov    -0x550(%rbp),%rax
   66ef3:	mov    %rcx,-0x558(%rbp)
   66efa:	lea    0x0(,%rax,8),%rsi
   66f02:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   66f07:	test   %rax,%rax
   66f0a:	mov    -0x558(%rbp),%rcx
   66f11:	je     693a0 <_IO_vfwscanf+0x53c0>
   66f17:	mov    -0x520(%rbp),%rsi
   66f1e:	lea    (%rax,%rcx,1),%r13
   66f22:	shlq   -0x550(%rbp)
   66f29:	mov    %rax,(%rsi)
   66f2c:	jmpq   64c2b <_IO_vfwscanf+0xc4b>
   66f31:	test   %rax,%rax
   66f34:	je     66c5f <_IO_vfwscanf+0x2c7f>
   66f3a:	sub    -0x440(%rbp),%rax
   66f41:	mov    %rax,%rsi
   66f44:	jmpq   66125 <_IO_vfwscanf+0x2145>
   66f49:	test   %rdx,%rdx
   66f4c:	je     6538f <_IO_vfwscanf+0x13af>
   66f52:	mov    -0x528(%rbp),%rax
   66f59:	sub    -0x440(%rbp),%rdx
   66f60:	mov    %rsi,-0x558(%rbp)
   66f67:	mov    %r8d,-0x538(%rbp)
   66f6e:	lea    0x10(%rax),%rdi
   66f72:	mov    %rdx,-0x500(%rbp)
   66f79:	callq  8afb0 <__libc_scratch_buffer_grow_preserve>
   66f7e:	test   %al,%al
   66f80:	mov    -0x538(%rbp),%r8d
   66f87:	mov    -0x558(%rbp),%rsi
   66f8e:	je     69390 <_IO_vfwscanf+0x53b0>
   66f94:	mov    -0x438(%rbp),%rdx
   66f9b:	mov    -0x440(%rbp),%rax
   66fa2:	and    $0xfffffffffffffffc,%rdx
   66fa6:	add    %rax,%rdx
   66fa9:	mov    %rdx,-0x448(%rbp)
   66fb0:	mov    -0x500(%rbp),%rdx
   66fb7:	add    %rax,%rdx
   66fba:	lea    0x4(%rdx),%rax
   66fbe:	mov    %rax,-0x450(%rbp)
   66fc5:	mov    %r15d,(%rdx)
   66fc8:	jmpq   6538f <_IO_vfwscanf+0x13af>
   66fcd:	mov    0x358e94(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   66fd4:	mov    %r14,%r15
   66fd7:	mov    -0x510(%rbp),%r14
   66fde:	mov    %rax,-0x538(%rbp)
   66fe5:	mov    %fs:(%rax),%ebx
   66fe8:	jmpq   66cb8 <_IO_vfwscanf+0x2cd8>
   66fed:	mov    0x358e74(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   66ff4:	mov    %r14,%r15
   66ff7:	mov    -0x510(%rbp),%r14
   66ffe:	mov    %rax,-0x538(%rbp)
   67005:	mov    %fs:(%rax),%ebx
   67008:	jmpq   66c9b <_IO_vfwscanf+0x2cbb>
   6700d:	mov    0x358e54(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   67014:	mov    %rax,-0x538(%rbp)
   6701b:	jmpq   663c2 <_IO_vfwscanf+0x23e2>
   67020:	test   %rdx,%rdx
   67023:	mov    %r8d,-0x500(%rbp)
   6702a:	je     66c5f <_IO_vfwscanf+0x2c7f>
   67030:	mov    -0x528(%rbp),%rax
   67037:	sub    -0x440(%rbp),%rdx
   6703e:	lea    0x10(%rax),%rdi
   67042:	mov    %rdx,%r12
   67045:	callq  8afb0 <__libc_scratch_buffer_grow_preserve>
   6704a:	test   %al,%al
   6704c:	mov    -0x500(%rbp),%r8d
   67053:	je     68670 <_IO_vfwscanf+0x4690>
   67059:	mov    -0x440(%rbp),%rax
   67060:	mov    -0x438(%rbp),%rdx
   67067:	add    %rax,%r12
   6706a:	and    $0xfffffffffffffffc,%rdx
   6706e:	add    %rax,%rdx
   67071:	lea    0x4(%r12),%rax
   67076:	mov    %rdx,-0x448(%rbp)
   6707d:	mov    %rax,-0x450(%rbp)
   67084:	movl   $0x30,(%r12)
   6708c:	jmpq   65580 <_IO_vfwscanf+0x15a0>
   67091:	mov    -0x538(%rbp),%rax
   67098:	mov    %r14,%r15
   6709b:	mov    -0x504(%rbp),%ebx
   670a1:	mov    -0x510(%rbp),%r14
   670a8:	movl   $0x4,-0x508(%rbp)
   670b2:	movl   $0x54,%fs:(%rax)
   670b9:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   670be:	mov    0x358da3(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   670c5:	mov    $0xffffffff,%ebx
   670ca:	mov    %r14,%r15
   670cd:	movl   $0x0,-0x508(%rbp)
   670d7:	mov    -0x510(%rbp),%r14
   670de:	mov    %ebx,-0x504(%rbp)
   670e4:	movl   $0xc,%fs:(%rax)
   670eb:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   670f0:	mov    $0xffffffff,%ebx
   670f5:	mov    %ebx,-0x504(%rbp)
   670fb:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   67100:	mov    $0xffffffff,%ebx
   67105:	mov    %ebx,-0x504(%rbp)
   6710b:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   67110:	test   $0x4,%r13b
   67114:	je     68180 <_IO_vfwscanf+0x41a0>
   6711a:	mov    -0x530(%rbp),%r12d
   67121:	test   %r12d,%r12d
   67124:	jne    68580 <_IO_vfwscanf+0x45a0>
   6712a:	mov    -0x4d8(%rbp),%edx
   67130:	cmp    $0x2f,%edx
   67133:	ja     6b418 <_IO_vfwscanf+0x7438>
   67139:	mov    %edx,%eax
   6713b:	add    -0x4c8(%rbp),%rax
   67142:	add    $0x8,%edx
   67145:	mov    %edx,-0x4d8(%rbp)
   6714b:	mov    (%rax),%rax
   6714e:	movzwl -0x4f8(%rbp),%edi
   67155:	movl   $0x0,-0x500(%rbp)
   6715f:	mov    %di,(%rax)
   67162:	jmpq   641fa <_IO_vfwscanf+0x21a>
   67167:	mov    0x358cfa(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   6716e:	mov    $0xffffffff,%ebx
   67173:	movl   $0x16,%fs:(%rax)
   6717a:	jmpq   64631 <_IO_vfwscanf+0x651>
   6717f:	mov    %rbx,-0x4f8(%rbp)
   67186:	mov    %r13,-0x578(%rbp)
   6718d:	mov    -0x538(%rbp),%rbx
   67194:	jmpq   64cb0 <_IO_vfwscanf+0xcd0>
   67199:	test   $0xa,%r8b
   6719d:	jne    65482 <_IO_vfwscanf+0x14a2>
   671a3:	xor    %eax,%eax
   671a5:	test   %r12d,%r12d
   671a8:	setg   %al
   671ab:	sub    %eax,%r12d
   671ae:	cmp    $0xffffffff,%r15d
   671b2:	je     69468 <_IO_vfwscanf+0x5488>
   671b8:	mov    0xa0(%r14),%rax
   671bf:	test   %rax,%rax
   671c2:	je     6ab9f <_IO_vfwscanf+0x6bbf>
   671c8:	mov    (%rax),%rdx
   671cb:	cmp    0x8(%rax),%rdx
   671cf:	jae    6ab9f <_IO_vfwscanf+0x6bbf>
   671d5:	lea    0x4(%rdx),%rcx
   671d9:	mov    (%rdx),%r15d
   671dc:	mov    %rcx,(%rax)
   671df:	cmp    $0xffffffff,%r15d
   671e3:	je     6930f <_IO_vfwscanf+0x532f>
   671e9:	addq   $0x1,-0x4f8(%rbp)
   671f1:	mov    $0x10,%r8d
   671f7:	jmpq   654a3 <_IO_vfwscanf+0x14c3>
   671fc:	mov    -0x580(%rbp),%rdi
   67203:	mov    -0x588(%rbp),%r11
   6720a:	xor    %r8d,%r8d
   6720d:	mov    -0x530(%rbp),%r9d
   67214:	mov    (%rdi),%rdx
   67217:	mov    %rdx,(%r11)
   6721a:	mov    0x8(%rdi),%rcx
   6721e:	mov    %rcx,0x8(%r11)
   67222:	mov    0x10(%rdi),%rsi
   67226:	xor    %edi,%edi
   67228:	mov    %rsi,0x10(%r11)
   6722c:	mov    %edx,%esi
   6722e:	sub    $0x1,%r9d
   67232:	je     6aa83 <_IO_vfwscanf+0x6aa3>
   67238:	cmp    $0x2f,%esi
   6723b:	ja     6a0f7 <_IO_vfwscanf+0x6117>
   67241:	add    $0x8,%esi
   67244:	mov    $0x1,%r8d
   6724a:	jmp    6722e <_IO_vfwscanf+0x324e>
   6724c:	nopl   0x0(%rax)
   67250:	and    $0x200,%r13d
   67257:	jne    68295 <_IO_vfwscanf+0x42b5>
   6725d:	mov    -0x530(%rbp),%r8d
   67264:	test   %r8d,%r8d
   67267:	jne    6875d <_IO_vfwscanf+0x477d>
   6726d:	mov    -0x4d8(%rbp),%ecx
   67273:	cmp    $0x2f,%ecx
   67276:	ja     6aa54 <_IO_vfwscanf+0x6a74>
   6727c:	mov    %ecx,%edx
   6727e:	add    -0x4c8(%rbp),%rdx
   67285:	add    $0x8,%ecx
   67288:	mov    %ecx,-0x4d8(%rbp)
   6728e:	mov    (%rdx),%rdx
   67291:	mov    %eax,(%rdx)
   67293:	jmpq   6563d <_IO_vfwscanf+0x165d>
   67298:	mov    %r14,%r15
   6729b:	mov    -0x510(%rbp),%r14
   672a2:	jmpq   65d40 <_IO_vfwscanf+0x1d60>
   672a7:	mov    -0x530(%rbp),%r10d
   672ae:	test   %r10d,%r10d
   672b1:	jne    68128 <_IO_vfwscanf+0x4148>
   672b7:	mov    -0x4d8(%rbp),%edx
   672bd:	cmp    $0x2f,%edx
   672c0:	ja     6ade2 <_IO_vfwscanf+0x6e02>
   672c6:	mov    %edx,%eax
   672c8:	add    -0x4c8(%rbp),%rax
   672cf:	add    $0x8,%edx
   672d2:	mov    %edx,-0x4d8(%rbp)
   672d8:	mov    (%rax),%rax
   672db:	mov    %rax,-0x578(%rbp)
   672e2:	cmpq   $0x0,-0x578(%rbp)
   672ea:	jne    6b716 <_IO_vfwscanf+0x7736>
   672f0:	mov    %r14,%r15
   672f3:	mov    -0x504(%rbp),%ebx
   672f9:	mov    -0x510(%rbp),%r14
   67300:	movl   $0x2,-0x508(%rbp)
   6730a:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6730f:	mov    %r14,%rdi
   67312:	callq  73620 <__wuflow>
   67317:	mov    %eax,%r15d
   6731a:	jmpq   64b86 <_IO_vfwscanf+0xba6>
   6731f:	and    $0x200,%r13d
   67326:	jne    67fea <_IO_vfwscanf+0x400a>
   6732c:	mov    -0x530(%rbp),%r12d
   67333:	test   %r12d,%r12d
   67336:	je     6726d <_IO_vfwscanf+0x328d>
   6733c:	mov    -0x580(%rbp),%rcx
   67343:	mov    -0x588(%rbp),%r11
   6734a:	xor    %r8d,%r8d
   6734d:	mov    (%rcx),%rdx
   67350:	mov    %rcx,%rdi
   67353:	mov    %rdx,(%r11)
   67356:	mov    0x8(%rcx),%rcx
   6735a:	mov    %rcx,0x8(%r11)
   6735e:	mov    0x10(%rdi),%rsi
   67362:	xor    %edi,%edi
   67364:	mov    %rsi,0x10(%r11)
   67368:	mov    %edx,%esi
   6736a:	subl   $0x1,-0x530(%rbp)
   67371:	je     6a4b9 <_IO_vfwscanf+0x64d9>
   67377:	cmp    $0x2f,%esi
   6737a:	ja     6998e <_IO_vfwscanf+0x59ae>
   67380:	add    $0x8,%esi
   67383:	mov    $0x1,%r8d
   67389:	jmp    6736a <_IO_vfwscanf+0x338a>
   6738b:	nopl   0x0(%rax,%rax,1)
   67390:	fstp   %st(0)
   67392:	mov    -0x440(%rbp),%rax
   67399:	cmp    %rax,-0x4e0(%rbp)
   673a0:	jne    641dd <_IO_vfwscanf+0x1fd>
   673a6:	mov    %r14,%r15
   673a9:	mov    -0x504(%rbp),%ebx
   673af:	mov    -0x510(%rbp),%r14
   673b6:	movl   $0x2,-0x508(%rbp)
   673c0:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   673c5:	mov    %r14,%r15
   673c8:	mov    -0x510(%rbp),%r14
   673cf:	jmpq   65db7 <_IO_vfwscanf+0x1dd7>
   673d4:	mov    0x358a8d(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   673db:	mov    %r14,%r15
   673de:	mov    -0x510(%rbp),%r14
   673e5:	mov    %rax,-0x538(%rbp)
   673ec:	jmpq   65dae <_IO_vfwscanf+0x1dce>
   673f1:	movl   $0x65,-0x4f8(%rbp)
   673fb:	xor    %r8d,%r8d
   673fe:	jmpq   657f6 <_IO_vfwscanf+0x1816>
   67403:	mov    -0x450(%rbp),%rax
   6740a:	cmp    -0x448(%rbp),%rax
   67411:	je     69330 <_IO_vfwscanf+0x5350>
   67417:	lea    0x4(%rax),%rdx
   6741b:	mov    %rdx,-0x450(%rbp)
   67422:	mov    %r15d,(%rax)
   67425:	test   %r12d,%r12d
   67428:	je     68821 <_IO_vfwscanf+0x4841>
   6742e:	mov    0xa0(%r14),%rax
   67435:	test   %rax,%rax
   67438:	je     696c2 <_IO_vfwscanf+0x56e2>
   6743e:	mov    (%rax),%rdx
   67441:	cmp    0x8(%rax),%rdx
   67445:	jae    696c2 <_IO_vfwscanf+0x56e2>
   6744b:	lea    0x4(%rdx),%rcx
   6744f:	mov    (%rdx),%r15d
   67452:	mov    %rcx,(%rax)
   67455:	cmp    $0xffffffff,%r15d
   67459:	je     696a3 <_IO_vfwscanf+0x56c3>
   6745f:	mov    %r15d,%edi
   67462:	callq  10b6c0 <towlower>
   67467:	cmp    $0x61,%eax
   6746a:	jne    6953a <_IO_vfwscanf+0x555a>
   67470:	xor    %eax,%eax
   67472:	test   %r12d,%r12d
   67475:	setg   %al
   67478:	sub    %eax,%r12d
   6747b:	mov    -0x450(%rbp),%rax
   67482:	cmp    -0x448(%rbp),%rax
   67489:	je     69526 <_IO_vfwscanf+0x5546>
   6748f:	lea    0x4(%rax),%rdx
   67493:	mov    %rdx,-0x450(%rbp)
   6749a:	mov    %r15d,(%rax)
   6749d:	test   %r12d,%r12d
   674a0:	je     69507 <_IO_vfwscanf+0x5527>
   674a6:	mov    0xa0(%r14),%rax
   674ad:	test   %rax,%rax
   674b0:	je     694f7 <_IO_vfwscanf+0x5517>
   674b6:	mov    (%rax),%rdx
   674b9:	cmp    0x8(%rax),%rdx
   674bd:	jae    694f7 <_IO_vfwscanf+0x5517>
   674c3:	lea    0x4(%rdx),%rcx
   674c7:	mov    (%rdx),%r15d
   674ca:	mov    %rcx,(%rax)
   674cd:	cmp    $0xffffffff,%r15d
   674d1:	je     694d8 <_IO_vfwscanf+0x54f8>
   674d7:	mov    -0x500(%rbp),%rax
   674de:	mov    %r15d,%edi
   674e1:	add    $0x2,%rax
   674e5:	mov    %rax,-0x4f8(%rbp)
   674ec:	callq  10b6c0 <towlower>
   674f1:	cmp    $0x6e,%eax
   674f4:	jne    694b9 <_IO_vfwscanf+0x54d9>
   674fa:	mov    -0x450(%rbp),%rcx
   67501:	mov    -0x448(%rbp),%rax
   67508:	cmp    %rax,%rcx
   6750b:	je     6aabb <_IO_vfwscanf+0x6adb>
   67511:	lea    0x4(%rcx),%rdx
   67515:	mov    %rdx,-0x450(%rbp)
   6751c:	mov    %r15d,(%rcx)
   6751f:	jmpq   6679e <_IO_vfwscanf+0x27be>
   67524:	mov    %r14,%rdi
   67527:	callq  73620 <__wuflow>
   6752c:	mov    %eax,%r15d
   6752f:	jmpq   64e47 <_IO_vfwscanf+0xe67>
   67534:	mov    %r13,-0x4f8(%rbp)
   6753b:	mov    %eax,%r15d
   6753e:	movl   $0x0,-0x500(%rbp)
   67548:	jmpq   641fa <_IO_vfwscanf+0x21a>
   6754d:	mov    -0x530(%rbp),%r8d
   67554:	test   %r8d,%r8d
   67557:	jne    6840f <_IO_vfwscanf+0x442f>
   6755d:	mov    -0x4d8(%rbp),%edx
   67563:	cmp    $0x2f,%edx
   67566:	ja     6adcb <_IO_vfwscanf+0x6deb>
   6756c:	mov    %edx,%eax
   6756e:	add    -0x4c8(%rbp),%rax
   67575:	add    $0x8,%edx
   67578:	mov    %edx,-0x4d8(%rbp)
   6757e:	mov    (%rax),%rax
   67581:	mov    %rax,-0x570(%rbp)
   67588:	cmpq   $0x0,-0x570(%rbp)
   67590:	jne    6b716 <_IO_vfwscanf+0x7736>
   67596:	mov    %r14,%r15
   67599:	mov    -0x504(%rbp),%ebx
   6759f:	mov    -0x510(%rbp),%r14
   675a6:	movl   $0x2,-0x508(%rbp)
   675b0:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   675b5:	mov    -0x450(%rbp),%rax
   675bc:	cmp    -0x448(%rbp),%rax
   675c3:	je     6a294 <_IO_vfwscanf+0x62b4>
   675c9:	lea    0x4(%rax),%rdx
   675cd:	mov    %rdx,-0x450(%rbp)
   675d4:	mov    %r15d,(%rax)
   675d7:	test   %r12d,%r12d
   675da:	je     69288 <_IO_vfwscanf+0x52a8>
   675e0:	mov    0xa0(%r14),%rax
   675e7:	test   %rax,%rax
   675ea:	je     69278 <_IO_vfwscanf+0x5298>
   675f0:	mov    (%rax),%rdx
   675f3:	cmp    0x8(%rax),%rdx
   675f7:	jae    69278 <_IO_vfwscanf+0x5298>
   675fd:	lea    0x4(%rdx),%rcx
   67601:	mov    (%rdx),%r15d
   67604:	mov    %rcx,(%rax)
   67607:	cmp    $0xffffffff,%r15d
   6760b:	je     69259 <_IO_vfwscanf+0x5279>
   67611:	mov    %r15d,%edi
   67614:	callq  10b6c0 <towlower>
   67619:	cmp    $0x6e,%eax
   6761c:	jne    6923a <_IO_vfwscanf+0x525a>
   67622:	xor    %eax,%eax
   67624:	test   %r12d,%r12d
   67627:	setg   %al
   6762a:	sub    %eax,%r12d
   6762d:	mov    -0x450(%rbp),%rax
   67634:	cmp    -0x448(%rbp),%rax
   6763b:	je     6a9db <_IO_vfwscanf+0x69fb>
   67641:	lea    0x4(%rax),%rdx
   67645:	mov    %rdx,-0x450(%rbp)
   6764c:	mov    %r15d,(%rax)
   6764f:	test   %r12d,%r12d
   67652:	je     6a9bc <_IO_vfwscanf+0x69dc>
   67658:	mov    0xa0(%r14),%rax
   6765f:	test   %rax,%rax
   67662:	je     6aa11 <_IO_vfwscanf+0x6a31>
   67668:	mov    (%rax),%rdx
   6766b:	cmp    0x8(%rax),%rdx
   6766f:	jae    6aa11 <_IO_vfwscanf+0x6a31>
   67675:	lea    0x4(%rdx),%rcx
   67679:	mov    (%rdx),%r15d
   6767c:	mov    %rcx,(%rax)
   6767f:	cmp    $0xffffffff,%r15d
   67683:	je     6921b <_IO_vfwscanf+0x523b>
   67689:	mov    -0x500(%rbp),%rax
   67690:	mov    %r15d,%edi
   67693:	add    $0x2,%rax
   67697:	mov    %rax,-0x4f8(%rbp)
   6769e:	callq  10b6c0 <towlower>
   676a3:	cmp    $0x66,%eax
   676a6:	jne    6aa35 <_IO_vfwscanf+0x6a55>
   676ac:	xor    %eax,%eax
   676ae:	test   %r12d,%r12d
   676b1:	setg   %al
   676b4:	sub    %eax,%r12d
   676b7:	mov    -0x450(%rbp),%rax
   676be:	cmp    -0x448(%rbp),%rax
   676c5:	je     6aa21 <_IO_vfwscanf+0x6a41>
   676cb:	lea    0x4(%rax),%rdx
   676cf:	mov    %rdx,-0x450(%rbp)
   676d6:	mov    %r15d,(%rax)
   676d9:	test   %r12d,%r12d
   676dc:	je     6772b <_IO_vfwscanf+0x374b>
   676de:	mov    0xa0(%r14),%rax
   676e5:	test   %rax,%rax
   676e8:	je     6982f <_IO_vfwscanf+0x584f>
   676ee:	mov    (%rax),%rdx
   676f1:	cmp    0x8(%rax),%rdx
   676f5:	jae    6982f <_IO_vfwscanf+0x584f>
   676fb:	lea    0x4(%rdx),%rcx
   676ff:	mov    (%rdx),%r15d
   67702:	mov    %rcx,(%rax)
   67705:	cmp    $0xffffffff,%r15d
   67709:	je     6973c <_IO_vfwscanf+0x575c>
   6770f:	mov    %r15d,%edi
   67712:	callq  10b6c0 <towlower>
   67717:	cmp    $0x69,%eax
   6771a:	je     6a2a8 <_IO_vfwscanf+0x62c8>
   67720:	mov    %r15d,%esi
   67723:	mov    %r14,%rdi
   67726:	callq  74430 <_IO_sputbackwc>
   6772b:	mov    -0x450(%rbp),%rdx
   67732:	mov    -0x448(%rbp),%rax
   67739:	jmpq   6679e <_IO_vfwscanf+0x27be>
   6773e:	mov    %r14,%rdi
   67741:	mov    %r8d,-0x500(%rbp)
   67748:	callq  73620 <__wuflow>
   6774d:	mov    -0x500(%rbp),%r8d
   67754:	mov    %eax,%r15d
   67757:	jmpq   66018 <_IO_vfwscanf+0x2038>
   6775c:	mov    -0x580(%rbp),%rdi
   67763:	mov    -0x588(%rbp),%rsi
   6776a:	mov    -0x530(%rbp),%r8d
   67771:	mov    (%rdi),%rax
   67774:	mov    %rax,(%rsi)
   67777:	mov    0x8(%rdi),%rdx
   6777b:	mov    %rdx,0x8(%rsi)
   6777f:	mov    0x10(%rdi),%rcx
   67783:	xor    %edi,%edi
   67785:	mov    %rcx,0x10(%rsi)
   67789:	mov    %eax,%ecx
   6778b:	xor    %esi,%esi
   6778d:	sub    $0x1,%r8d
   67791:	je     6b305 <_IO_vfwscanf+0x7325>
   67797:	cmp    $0x2f,%ecx
   6779a:	ja     6b2f7 <_IO_vfwscanf+0x7317>
   677a0:	add    $0x8,%ecx
   677a3:	mov    $0x1,%edi
   677a8:	jmp    6778d <_IO_vfwscanf+0x37ad>
   677aa:	nopw   0x0(%rax,%rax,1)
   677b0:	mov    -0x580(%rbp),%rdi
   677b7:	mov    -0x588(%rbp),%rsi
   677be:	mov    -0x530(%rbp),%r8d
   677c5:	mov    (%rdi),%rax
   677c8:	mov    %rax,(%rsi)
   677cb:	mov    0x8(%rdi),%rdx
   677cf:	mov    %rdx,0x8(%rsi)
   677d3:	mov    0x10(%rdi),%rcx
   677d7:	xor    %edi,%edi
   677d9:	mov    %rcx,0x10(%rsi)
   677dd:	mov    %eax,%ecx
   677df:	xor    %esi,%esi
   677e1:	sub    $0x1,%r8d
   677e5:	je     6a0b8 <_IO_vfwscanf+0x60d8>
   677eb:	cmp    $0x2f,%ecx
   677ee:	ja     6a0aa <_IO_vfwscanf+0x60ca>
   677f4:	add    $0x8,%ecx
   677f7:	mov    $0x1,%edi
   677fc:	jmp    677e1 <_IO_vfwscanf+0x3801>
   677fe:	xchg   %ax,%ax
   67800:	mov    %r14,%rdi
   67803:	mov    %r8d,-0x500(%rbp)
   6780a:	callq  73620 <__wuflow>
   6780f:	mov    -0x500(%rbp),%r8d
   67816:	mov    %eax,%r15d
   67819:	jmpq   661c4 <_IO_vfwscanf+0x21e4>
   6781e:	shlq   -0x550(%rbp)
   67825:	mov    %r13,%rbx
   67828:	mov    -0x550(%rbp),%rax
   6782f:	sub    %rdi,%rbx
   67832:	mov    %rax,%rsi
   67835:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   6783a:	test   %rax,%rax
   6783d:	je     6b547 <_IO_vfwscanf+0x7567>
   67843:	mov    -0x520(%rbp),%rsi
   6784a:	lea    (%rax,%rbx,1),%r13
   6784e:	mov    %rax,(%rsi)
   67851:	jmpq   65b16 <_IO_vfwscanf+0x1b36>
   67856:	mov    -0x580(%rbp),%rdi
   6785d:	mov    -0x588(%rbp),%rsi
   67864:	mov    -0x530(%rbp),%r8d
   6786b:	mov    (%rdi),%rax
   6786e:	mov    %rax,(%rsi)
   67871:	mov    0x8(%rdi),%rdx
   67875:	mov    %rdx,0x8(%rsi)
   67879:	mov    0x10(%rdi),%rcx
   6787d:	xor    %edi,%edi
   6787f:	mov    %rcx,0x10(%rsi)
   67883:	mov    %eax,%ecx
   67885:	xor    %esi,%esi
   67887:	sub    $0x1,%r8d
   6788b:	je     6b1a7 <_IO_vfwscanf+0x71c7>
   67891:	cmp    $0x2f,%ecx
   67894:	ja     6b199 <_IO_vfwscanf+0x71b9>
   6789a:	add    $0x8,%ecx
   6789d:	mov    $0x1,%edi
   678a2:	jmp    67887 <_IO_vfwscanf+0x38a7>
   678a4:	nopl   0x0(%rax)
   678a8:	mov    -0x580(%rbp),%rdi
   678af:	mov    -0x588(%rbp),%rsi
   678b6:	mov    -0x530(%rbp),%r8d
   678bd:	mov    (%rdi),%rax
   678c0:	mov    %rax,(%rsi)
   678c3:	mov    0x8(%rdi),%rdx
   678c7:	mov    %rdx,0x8(%rsi)
   678cb:	mov    0x10(%rdi),%rcx
   678cf:	xor    %edi,%edi
   678d1:	mov    %rcx,0x10(%rsi)
   678d5:	mov    %eax,%ecx
   678d7:	xor    %esi,%esi
   678d9:	sub    $0x1,%r8d
   678dd:	je     6b352 <_IO_vfwscanf+0x7372>
   678e3:	cmp    $0x2f,%ecx
   678e6:	ja     6b344 <_IO_vfwscanf+0x7364>
   678ec:	add    $0x8,%ecx
   678ef:	mov    $0x1,%edi
   678f4:	jmp    678d9 <_IO_vfwscanf+0x38f9>
   678f6:	nopw   %cs:0x0(%rax,%rax,1)
   67900:	mov    %r14,%rdi
   67903:	mov    %r8d,-0x500(%rbp)
   6790a:	callq  73620 <__wuflow>
   6790f:	mov    -0x500(%rbp),%r8d
   67916:	mov    %eax,%r15d
   67919:	jmpq   66214 <_IO_vfwscanf+0x2234>
   6791e:	mov    %r14,%rdi
   67921:	callq  73620 <__wuflow>
   67926:	mov    %eax,%r15d
   67929:	jmpq   656a3 <_IO_vfwscanf+0x16c3>
   6792e:	lea    0x122118(%rip),%rdi        # 189a4d <null+0xf>
   67935:	callq  10b870 <wctrans>
   6793a:	mov    %rax,%rdi
   6793d:	mov    %rax,-0x560(%rbp)
   67944:	mov    0x358465(%rip),%rax        # 3bfdb0 <_DYNAMIC+0x250>
   6794b:	test   %rdi,%rdi
   6794e:	mov    %fs:(%rax),%rax
   67952:	mov    (%rax),%rax
   67955:	mov    0x130(%rax),%ecx
   6795b:	lea    -0x1(%rcx),%eax
   6795e:	mov    %eax,-0x500(%rbp)
   67964:	jne    6abd2 <_IO_vfwscanf+0x6bf2>
   6796a:	mov    %r13d,%eax
   6796d:	xor    %edi,%edi
   6796f:	mov    %r14,-0x558(%rbp)
   67976:	shr    $0x7,%eax
   67979:	mov    %rbx,-0x568(%rbp)
   67980:	mov    %r13d,-0x598(%rbp)
   67987:	xor    $0x1,%eax
   6798a:	mov    %edi,%r14d
   6798d:	and    $0x1,%eax
   67990:	mov    %al,-0x5a0(%rbp)
   67996:	mov    -0x528(%rbp),%rax
   6799d:	add    $0x10,%rax
   679a1:	mov    %rax,-0x5b0(%rbp)
   679a8:	nopl   0x0(%rax,%rax,1)
   679b0:	cmp    $0xffffffff,%r15d
   679b4:	je     67e72 <_IO_vfwscanf+0x3e92>
   679ba:	test   %r12d,%r12d
   679bd:	je     67e72 <_IO_vfwscanf+0x3e92>
   679c3:	movslq %r14d,%rdx
   679c6:	shl    $0x2,%rdx
   679ca:	cmpq   $0x0,-0x560(%rbp)
   679d2:	jne    67d94 <_IO_vfwscanf+0x3db4>
   679d8:	mov    0x3583d1(%rip),%rax        # 3bfdb0 <_DYNAMIC+0x250>
   679df:	mov    %fs:(%rax),%rax
   679e3:	mov    (%rax),%rbx
   679e6:	mov    %rdx,%rax
   679e9:	add    0x138(%rbx),%rax
   679f0:	cmp    (%rax),%r15d
   679f3:	je     68114 <_IO_vfwscanf+0x4134>
   679f9:	mov    %rdx,%rcx
   679fc:	add    0x140(%rbx),%rcx
   67a03:	cmp    (%rcx),%r15d
   67a06:	je     68100 <_IO_vfwscanf+0x4120>
   67a0c:	mov    %rdx,%rsi
   67a0f:	add    0x148(%rbx),%rsi
   67a16:	cmp    (%rsi),%r15d
   67a19:	je     67fd6 <_IO_vfwscanf+0x3ff6>
   67a1f:	mov    %rdx,%rdi
   67a22:	add    0x150(%rbx),%rdi
   67a29:	add    $0x4,%rsi
   67a2d:	cmp    (%rdi),%r15d
   67a30:	je     6870d <_IO_vfwscanf+0x472d>
   67a36:	mov    %rdx,%r8
   67a39:	add    0x158(%rbx),%r8
   67a40:	add    $0x4,%rdi
   67a44:	cmp    (%r8),%r15d
   67a47:	je     686da <_IO_vfwscanf+0x46fa>
   67a4d:	mov    %rdx,%r9
   67a50:	add    0x160(%rbx),%r9
   67a57:	add    $0x4,%r8
   67a5b:	cmp    (%r9),%r15d
   67a5e:	je     67fc2 <_IO_vfwscanf+0x3fe2>
   67a64:	mov    %rdx,%r11
   67a67:	add    0x168(%rbx),%r11
   67a6e:	add    $0x4,%r9
   67a72:	cmp    (%r11),%r15d
   67a75:	je     686c6 <_IO_vfwscanf+0x46e6>
   67a7b:	mov    %rdx,%r10
   67a7e:	add    0x170(%rbx),%r10
   67a85:	add    $0x4,%r11
   67a89:	cmp    (%r10),%r15d
   67a8c:	je     686b2 <_IO_vfwscanf+0x46d2>
   67a92:	mov    %rdx,%r13
   67a95:	add    0x178(%rbx),%r13
   67a9c:	add    $0x4,%r10
   67aa0:	cmp    0x0(%r13),%r15d
   67aa4:	je     6869e <_IO_vfwscanf+0x46be>
   67aaa:	mov    0x180(%rbx),%rbx
   67ab1:	add    $0x4,%r13
   67ab5:	add    $0x4,%rcx
   67ab9:	mov    %r13,-0x538(%rbp)
   67ac0:	add    %rdx,%rbx
   67ac3:	cmp    (%rbx),%r15d
   67ac6:	je     6868a <_IO_vfwscanf+0x46aa>
   67acc:	lea    0x1(%r14),%edx
   67ad0:	cmp    %edx,-0x500(%rbp)
   67ad6:	jl     67c2a <_IO_vfwscanf+0x3c4a>
   67adc:	cmp    0x4(%rax),%r15d
   67ae0:	je     67c79 <_IO_vfwscanf+0x3c99>
   67ae6:	add    $0x8,%rax
   67aea:	cmp    (%rcx),%r15d
   67aed:	mov    %rax,%r13
   67af0:	je     67c8d <_IO_vfwscanf+0x3cad>
   67af6:	cmp    (%rsi),%r15d
   67af9:	je     67b93 <_IO_vfwscanf+0x3bb3>
   67aff:	mov    %r14d,-0x5a8(%rbp)
   67b06:	xor    %eax,%eax
   67b08:	mov    %r12d,%r14d
   67b0b:	cmp    (%rdi,%rax,1),%r15d
   67b0f:	je     67c9e <_IO_vfwscanf+0x3cbe>
   67b15:	cmp    (%r8,%rax,1),%r15d
   67b19:	je     67cc6 <_IO_vfwscanf+0x3ce6>
   67b1f:	cmp    (%r9,%rax,1),%r15d
   67b23:	je     67cda <_IO_vfwscanf+0x3cfa>
   67b29:	cmp    (%r11,%rax,1),%r15d
   67b2d:	je     67d58 <_IO_vfwscanf+0x3d78>
   67b33:	cmp    (%r10,%rax,1),%r15d
   67b37:	je     67d80 <_IO_vfwscanf+0x3da0>
   67b3d:	mov    -0x538(%rbp),%r12
   67b44:	cmp    (%r12,%rax,1),%r15d
   67b48:	je     67d6c <_IO_vfwscanf+0x3d8c>
   67b4e:	cmp    0x4(%rbx,%rax,1),%r15d
   67b53:	je     67d44 <_IO_vfwscanf+0x3d64>
   67b59:	add    $0x1,%edx
   67b5c:	cmp    %edx,-0x500(%rbp)
   67b62:	jl     67c20 <_IO_vfwscanf+0x3c40>
   67b68:	cmp    0x0(%r13,%rax,1),%r15d
   67b6d:	je     67c76 <_IO_vfwscanf+0x3c96>
   67b73:	cmp    0x4(%rcx,%rax,1),%r15d
   67b78:	je     67c8a <_IO_vfwscanf+0x3caa>
   67b7e:	mov    0x4(%rsi,%rax,1),%r12d
   67b83:	add    $0x4,%rax
   67b87:	cmp    %r12d,%r15d
   67b8a:	jne    67b0b <_IO_vfwscanf+0x3b2b>
   67b90:	mov    %r14d,%r12d
   67b93:	mov    $0x32,%r13d
   67b99:	mov    $0x32,%r15d
   67b9f:	nop
   67ba0:	mov    %edx,-0x500(%rbp)
   67ba6:	mov    %edx,%r14d
   67ba9:	mov    -0x450(%rbp),%rax
   67bb0:	mov    -0x448(%rbp),%rbx
   67bb7:	cmp    %rax,%rbx
   67bba:	je     67cee <_IO_vfwscanf+0x3d0e>
   67bc0:	lea    0x4(%rax),%rdx
   67bc4:	mov    %rdx,-0x450(%rbp)
   67bcb:	mov    %r13d,(%rax)
   67bce:	xor    %eax,%eax
   67bd0:	test   %r12d,%r12d
   67bd3:	setg   %al
   67bd6:	sub    %eax,%r12d
   67bd9:	cmp    $0xffffffff,%r15d
   67bdd:	je     67c4c <_IO_vfwscanf+0x3c6c>
   67bdf:	mov    -0x558(%rbp),%rax
   67be6:	mov    0xa0(%rax),%rax
   67bed:	test   %rax,%rax
   67bf0:	je     67cb2 <_IO_vfwscanf+0x3cd2>
   67bf6:	mov    (%rax),%rdx
   67bf9:	cmp    0x8(%rax),%rdx
   67bfd:	jae    67cb2 <_IO_vfwscanf+0x3cd2>
   67c03:	lea    0x4(%rdx),%rcx
   67c07:	mov    (%rdx),%r15d
   67c0a:	mov    %rcx,(%rax)
   67c0d:	cmp    $0xffffffff,%r15d
   67c11:	je     67c61 <_IO_vfwscanf+0x3c81>
   67c13:	addq   $0x1,-0x4f8(%rbp)
   67c1b:	jmpq   679b0 <_IO_vfwscanf+0x39d0>
   67c20:	mov    %r14d,%r12d
   67c23:	mov    -0x5a8(%rbp),%r14d
   67c2a:	cmpb   $0x0,-0x5a0(%rbp)
   67c31:	jne    67e72 <_IO_vfwscanf+0x3e92>
   67c37:	cmp    -0x518(%rbp),%r15d
   67c3e:	jne    67e72 <_IO_vfwscanf+0x3e92>
   67c44:	mov    %r15d,%r13d
   67c47:	jmpq   67ba9 <_IO_vfwscanf+0x3bc9>
   67c4c:	mov    0x358215(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   67c53:	mov    -0x514(%rbp),%ecx
   67c59:	mov    %ecx,%fs:(%rax)
   67c5c:	jmpq   679b0 <_IO_vfwscanf+0x39d0>
   67c61:	mov    0x358200(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   67c68:	mov    %fs:(%rax),%eax
   67c6b:	mov    %eax,-0x514(%rbp)
   67c71:	jmpq   679b0 <_IO_vfwscanf+0x39d0>
   67c76:	mov    %r14d,%r12d
   67c79:	mov    $0x30,%r13d
   67c7f:	mov    $0x30,%r15d
   67c85:	jmpq   67ba0 <_IO_vfwscanf+0x3bc0>
   67c8a:	mov    %r14d,%r12d
   67c8d:	mov    $0x31,%r13d
   67c93:	mov    $0x31,%r15d
   67c99:	jmpq   67ba0 <_IO_vfwscanf+0x3bc0>
   67c9e:	mov    %r14d,%r12d
   67ca1:	mov    $0x33,%r13d
   67ca7:	mov    $0x33,%r15d
   67cad:	jmpq   67ba0 <_IO_vfwscanf+0x3bc0>
   67cb2:	mov    -0x558(%rbp),%rdi
   67cb9:	callq  73620 <__wuflow>
   67cbe:	mov    %eax,%r15d
   67cc1:	jmpq   67c0d <_IO_vfwscanf+0x3c2d>
   67cc6:	mov    %r14d,%r12d
   67cc9:	mov    $0x34,%r13d
   67ccf:	mov    $0x34,%r15d
   67cd5:	jmpq   67ba0 <_IO_vfwscanf+0x3bc0>
   67cda:	mov    %r14d,%r12d
   67cdd:	mov    $0x35,%r13d
   67ce3:	mov    $0x35,%r15d
   67ce9:	jmpq   67ba0 <_IO_vfwscanf+0x3bc0>
   67cee:	test   %rbx,%rbx
   67cf1:	je     67bce <_IO_vfwscanf+0x3bee>
   67cf7:	mov    -0x5b0(%rbp),%rdi
   67cfe:	sub    -0x440(%rbp),%rbx
   67d05:	callq  8afb0 <__libc_scratch_buffer_grow_preserve>
   67d0a:	test   %al,%al
   67d0c:	je     69034 <_IO_vfwscanf+0x5054>
   67d12:	mov    -0x440(%rbp),%rax
   67d19:	mov    -0x438(%rbp),%rdx
   67d20:	add    %rax,%rbx
   67d23:	and    $0xfffffffffffffffc,%rdx
   67d27:	add    %rax,%rdx
   67d2a:	lea    0x4(%rbx),%rax
   67d2e:	mov    %rdx,-0x448(%rbp)
   67d35:	mov    %rax,-0x450(%rbp)
   67d3c:	mov    %r13d,(%rbx)
   67d3f:	jmpq   67bce <_IO_vfwscanf+0x3bee>
   67d44:	mov    %r14d,%r12d
   67d47:	mov    $0x39,%r13d
   67d4d:	mov    $0x39,%r15d
   67d53:	jmpq   67ba0 <_IO_vfwscanf+0x3bc0>
   67d58:	mov    %r14d,%r12d
   67d5b:	mov    $0x36,%r13d
   67d61:	mov    $0x36,%r15d
   67d67:	jmpq   67ba0 <_IO_vfwscanf+0x3bc0>
   67d6c:	mov    %r14d,%r12d
   67d6f:	mov    $0x38,%r13d
   67d75:	mov    $0x38,%r15d
   67d7b:	jmpq   67ba0 <_IO_vfwscanf+0x3bc0>
   67d80:	mov    %r14d,%r12d
   67d83:	mov    $0x37,%r13d
   67d89:	mov    $0x37,%r15d
   67d8f:	jmpq   67ba0 <_IO_vfwscanf+0x3bc0>
   67d94:	mov    %rdx,%rax
   67d97:	add    -0x4a0(%rbp),%rax
   67d9e:	cmp    (%rax),%r15d
   67da1:	je     68114 <_IO_vfwscanf+0x4134>
   67da7:	mov    %rdx,%rcx
   67daa:	add    -0x498(%rbp),%rcx
   67db1:	cmp    (%rcx),%r15d
   67db4:	je     68100 <_IO_vfwscanf+0x4120>
   67dba:	mov    %rdx,%rsi
   67dbd:	add    -0x490(%rbp),%rsi
   67dc4:	add    $0x4,%rcx
   67dc8:	cmp    %r15d,(%rsi)
   67dcb:	je     67fd6 <_IO_vfwscanf+0x3ff6>
   67dd1:	mov    %rdx,%rdi
   67dd4:	add    -0x488(%rbp),%rdi
   67ddb:	add    $0x4,%rsi
   67ddf:	cmp    (%rdi),%r15d
   67de2:	je     6870d <_IO_vfwscanf+0x472d>
   67de8:	mov    %rdx,%r8
   67deb:	add    -0x480(%rbp),%r8
   67df2:	add    $0x4,%rdi
   67df6:	cmp    (%r8),%r15d
   67df9:	je     686da <_IO_vfwscanf+0x46fa>
   67dff:	mov    %rdx,%r9
   67e02:	add    -0x478(%rbp),%r9
   67e09:	add    $0x4,%r8
   67e0d:	cmp    (%r9),%r15d
   67e10:	je     67fc2 <_IO_vfwscanf+0x3fe2>
   67e16:	mov    %rdx,%r11
   67e19:	add    -0x470(%rbp),%r11
   67e20:	add    $0x4,%r9
   67e24:	cmp    (%r11),%r15d
   67e27:	je     686c6 <_IO_vfwscanf+0x46e6>
   67e2d:	mov    %rdx,%r10
   67e30:	add    -0x468(%rbp),%r10
   67e37:	add    $0x4,%r11
   67e3b:	cmp    (%r10),%r15d
   67e3e:	je     686b2 <_IO_vfwscanf+0x46d2>
   67e44:	mov    %rdx,%rbx
   67e47:	add    -0x460(%rbp),%rbx
   67e4e:	add    $0x4,%r10
   67e52:	cmp    (%rbx),%r15d
   67e55:	je     6869e <_IO_vfwscanf+0x46be>
   67e5b:	add    $0x4,%rbx
   67e5f:	mov    %rbx,-0x538(%rbp)
   67e66:	mov    -0x458(%rbp),%rbx
   67e6d:	jmpq   67ac0 <_IO_vfwscanf+0x3ae0>
   67e72:	mov    -0x568(%rbp),%rbx
   67e79:	mov    -0x598(%rbp),%r13d
   67e80:	mov    $0xa,%r8d
   67e86:	mov    -0x558(%rbp),%r14
   67e8d:	jmpq   65510 <_IO_vfwscanf+0x1530>
   67e92:	callq  ad1e0 <__wcstof_internal>
   67e97:	and    $0x8,%r13d
   67e9b:	jne    67392 <_IO_vfwscanf+0x33b2>
   67ea1:	mov    -0x440(%rbp),%rdx
   67ea8:	mov    -0x4e0(%rbp),%rcx
   67eaf:	cmp    %rdx,%rcx
   67eb2:	je     698ff <_IO_vfwscanf+0x591f>
   67eb8:	mov    -0x530(%rbp),%r12d
   67ebf:	test   %r12d,%r12d
   67ec2:	jne    69407 <_IO_vfwscanf+0x5427>
   67ec8:	mov    -0x4d8(%rbp),%esi
   67ece:	cmp    $0x2f,%esi
   67ed1:	ja     6b0a8 <_IO_vfwscanf+0x70c8>
   67ed7:	mov    %esi,%eax
   67ed9:	add    -0x4c8(%rbp),%rax
   67ee0:	add    $0x8,%esi
   67ee3:	mov    %esi,-0x4d8(%rbp)
   67ee9:	mov    (%rax),%rax
   67eec:	cmpb   $0x0,-0x568(%rbp)
   67ef3:	je     67efc <_IO_vfwscanf+0x3f1c>
   67ef5:	xorps  0x129484(%rip),%xmm0        # 191380 <othermask+0x40>
   67efc:	movss  %xmm0,(%rax)
   67f00:	jmpq   6685b <_IO_vfwscanf+0x287b>
   67f05:	mov    -0x538(%rbp),%rax
   67f0c:	mov    -0x514(%rbp),%esi
   67f12:	mov    %r14,%r15
   67f15:	mov    -0x510(%rbp),%r14
   67f1c:	mov    %esi,%fs:(%rax)
   67f1f:	mov    -0x504(%rbp),%ebx
   67f25:	test   %ebx,%ebx
   67f27:	je     67f75 <_IO_vfwscanf+0x3f95>
   67f29:	mov    -0x504(%rbp),%ebx
   67f2f:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   67f34:	mov    0x357f2d(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   67f3b:	mov    -0x514(%rbp),%edi
   67f41:	mov    %r14,%r15
   67f44:	mov    -0x510(%rbp),%r14
   67f4b:	mov    %edi,%fs:(%rax)
   67f4e:	mov    -0x504(%rbp),%r13d
   67f55:	test   %r13d,%r13d
   67f58:	je     67fb2 <_IO_vfwscanf+0x3fd2>
   67f5a:	mov    -0x504(%rbp),%ebx
   67f60:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   67f65:	mov    %r14,%rdi
   67f68:	callq  73620 <__wuflow>
   67f6d:	mov    %eax,%r15d
   67f70:	jmpq   65cd7 <_IO_vfwscanf+0x1cf7>
   67f75:	mov    $0xffffffff,%ebx
   67f7a:	mov    %ebx,-0x504(%rbp)
   67f80:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   67f85:	lea    -0x2b(%r15),%eax
   67f89:	and    $0xfffffffd,%eax
   67f8c:	jne    658f9 <_IO_vfwscanf+0x1919>
   67f92:	cmp    -0x448(%rbp),%rdx
   67f99:	je     698e9 <_IO_vfwscanf+0x5909>
   67f9f:	lea    0x4(%rdx),%rax
   67fa3:	mov    %rax,-0x450(%rbp)
   67faa:	mov    %r15d,(%rdx)
   67fad:	jmpq   6586d <_IO_vfwscanf+0x188d>
   67fb2:	mov    $0xffffffff,%ebx
   67fb7:	mov    %ebx,-0x504(%rbp)
   67fbd:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   67fc2:	mov    %r14d,%edx
   67fc5:	mov    $0x35,%r13d
   67fcb:	mov    $0x35,%r15d
   67fd1:	jmpq   67ba0 <_IO_vfwscanf+0x3bc0>
   67fd6:	mov    %r14d,%edx
   67fd9:	mov    $0x32,%r13d
   67fdf:	mov    $0x32,%r15d
   67fe5:	jmpq   67ba0 <_IO_vfwscanf+0x3bc0>
   67fea:	mov    -0x530(%rbp),%r11d
   67ff1:	test   %r11d,%r11d
   67ff4:	jne    68620 <_IO_vfwscanf+0x4640>
   67ffa:	mov    -0x4d8(%rbp),%ecx
   68000:	cmp    $0x2f,%ecx
   68003:	ja     6ae5a <_IO_vfwscanf+0x6e7a>
   68009:	mov    %ecx,%edx
   6800b:	add    -0x4c8(%rbp),%rdx
   68012:	add    $0x8,%ecx
   68015:	mov    %ecx,-0x4d8(%rbp)
   6801b:	mov    (%rdx),%rdx
   6801e:	mov    %al,(%rdx)
   68020:	jmpq   6563d <_IO_vfwscanf+0x165d>
   68025:	callq  ad1b0 <__wcstold_internal>
   6802a:	and    $0x8,%r13d
   6802e:	jne    67390 <_IO_vfwscanf+0x33b0>
   68034:	mov    -0x440(%rbp),%rdx
   6803b:	mov    -0x4e0(%rbp),%rcx
   68042:	cmp    %rdx,%rcx
   68045:	je     698fd <_IO_vfwscanf+0x591d>
   6804b:	mov    -0x530(%rbp),%eax
   68051:	test   %eax,%eax
   68053:	jne    690c9 <_IO_vfwscanf+0x50e9>
   68059:	mov    -0x4d8(%rbp),%esi
   6805f:	cmp    $0x2f,%esi
   68062:	ja     6ad6e <_IO_vfwscanf+0x6d8e>
   68068:	mov    %esi,%eax
   6806a:	add    -0x4c8(%rbp),%rax
   68071:	add    $0x8,%esi
   68074:	mov    %esi,-0x4d8(%rbp)
   6807a:	mov    (%rax),%rax
   6807d:	cmpb   $0x0,-0x568(%rbp)
   68084:	je     68088 <_IO_vfwscanf+0x40a8>
   68086:	fchs   
   68088:	fstpt  (%rax)
   6808a:	jmpq   6685b <_IO_vfwscanf+0x287b>
   6808f:	mov    -0x530(%rbp),%r8d
   68096:	test   %r8d,%r8d
   68099:	jne    68b3b <_IO_vfwscanf+0x4b5b>
   6809f:	mov    -0x4d8(%rbp),%edx
   680a5:	cmp    $0x2f,%edx
   680a8:	ja     6a124 <_IO_vfwscanf+0x6144>
   680ae:	mov    %edx,%eax
   680b0:	add    -0x4c8(%rbp),%rax
   680b7:	add    $0x8,%edx
   680ba:	mov    %edx,-0x4d8(%rbp)
   680c0:	mov    (%rax),%rax
   680c3:	mov    %rax,-0x570(%rbp)
   680ca:	cmpq   $0x0,-0x570(%rbp)
   680d2:	jne    64fe0 <_IO_vfwscanf+0x1000>
   680d8:	mov    %r14,%r15
   680db:	mov    -0x504(%rbp),%ebx
   680e1:	mov    -0x510(%rbp),%r14
   680e8:	movl   $0x2,-0x508(%rbp)
   680f2:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   680f7:	nopw   0x0(%rax,%rax,1)
   68100:	mov    %r14d,%edx
   68103:	mov    $0x31,%r13d
   68109:	mov    $0x31,%r15d
   6810f:	jmpq   67ba0 <_IO_vfwscanf+0x3bc0>
   68114:	mov    %r14d,%edx
   68117:	mov    $0x30,%r13d
   6811d:	mov    $0x30,%r15d
   68123:	jmpq   67ba0 <_IO_vfwscanf+0x3bc0>
   68128:	mov    -0x580(%rbp),%rcx
   6812f:	mov    -0x588(%rbp),%rdi
   68136:	xor    %esi,%esi
   68138:	mov    -0x530(%rbp),%r8d
   6813f:	mov    (%rcx),%rax
   68142:	mov    %rax,(%rdi)
   68145:	mov    0x8(%rcx),%rdx
   68149:	mov    %rdx,0x8(%rdi)
   6814d:	mov    0x10(%rcx),%rcx
   68151:	mov    %rcx,0x10(%rdi)
   68155:	mov    %eax,%ecx
   68157:	xor    %edi,%edi
   68159:	sub    $0x1,%r8d
   6815d:	je     6b45f <_IO_vfwscanf+0x747f>
   68163:	cmp    $0x2f,%ecx
   68166:	ja     6b451 <_IO_vfwscanf+0x7471>
   6816c:	add    $0x8,%ecx
   6816f:	mov    $0x1,%edi
   68174:	jmp    68159 <_IO_vfwscanf+0x4179>
   68176:	nopw   %cs:0x0(%rax,%rax,1)
   68180:	and    $0x200,%r13d
   68187:	mov    %r13d,-0x500(%rbp)
   6818e:	jne    68840 <_IO_vfwscanf+0x4860>
   68194:	mov    -0x530(%rbp),%r11d
   6819b:	test   %r11d,%r11d
   6819e:	jne    69344 <_IO_vfwscanf+0x5364>
   681a4:	mov    -0x4d8(%rbp),%edx
   681aa:	cmp    $0x2f,%edx
   681ad:	ja     6a13b <_IO_vfwscanf+0x615b>
   681b3:	mov    %edx,%eax
   681b5:	add    -0x4c8(%rbp),%rax
   681bc:	add    $0x8,%edx
   681bf:	mov    %edx,-0x4d8(%rbp)
   681c5:	mov    (%rax),%rax
   681c8:	mov    -0x4f8(%rbp),%ecx
   681ce:	mov    %ecx,(%rax)
   681d0:	jmpq   641fa <_IO_vfwscanf+0x21a>
   681d5:	mov    -0x580(%rbp),%rdi
   681dc:	mov    -0x588(%rbp),%r11
   681e3:	xor    %r8d,%r8d
   681e6:	mov    -0x530(%rbp),%r9d
   681ed:	mov    (%rdi),%rdx
   681f0:	mov    %rdx,(%r11)
   681f3:	mov    0x8(%rdi),%rcx
   681f7:	mov    %rcx,0x8(%r11)
   681fb:	mov    0x10(%rdi),%rsi
   681ff:	xor    %edi,%edi
   68201:	mov    %rsi,0x10(%r11)
   68205:	mov    %edx,%esi
   68207:	sub    $0x1,%r9d
   6820b:	je     69885 <_IO_vfwscanf+0x58a5>
   68211:	cmp    $0x2f,%esi
   68214:	ja     69821 <_IO_vfwscanf+0x5841>
   6821a:	add    $0x8,%esi
   6821d:	mov    $0x1,%r8d
   68223:	jmp    68207 <_IO_vfwscanf+0x4227>
   68225:	nopl   (%rax)
   68228:	mov    -0x580(%rbp),%rcx
   6822f:	mov    -0x588(%rbp),%rsi
   68236:	xor    %edi,%edi
   68238:	mov    -0x530(%rbp),%r8d
   6823f:	mov    (%rcx),%rax
   68242:	mov    %rax,(%rsi)
   68245:	mov    0x8(%rcx),%rdx
   68249:	mov    %rdx,0x8(%rsi)
   6824d:	mov    0x10(%rcx),%rcx
   68251:	mov    %rcx,0x10(%rsi)
   68255:	mov    %eax,%ecx
   68257:	xor    %esi,%esi
   68259:	sub    $0x1,%r8d
   6825d:	je     6a97d <_IO_vfwscanf+0x699d>
   68263:	cmp    $0x2f,%ecx
   68266:	ja     6a96f <_IO_vfwscanf+0x698f>
   6826c:	add    $0x8,%ecx
   6826f:	mov    $0x1,%esi
   68274:	jmp    68259 <_IO_vfwscanf+0x4279>
   68276:	nopw   %cs:0x0(%rax,%rax,1)
   68280:	movl   $0x65,-0x4f8(%rbp)
   6828a:	mov    $0x1,%r8d
   68290:	jmpq   657f6 <_IO_vfwscanf+0x1816>
   68295:	mov    -0x530(%rbp),%edi
   6829b:	test   %edi,%edi
   6829d:	je     67ffa <_IO_vfwscanf+0x401a>
   682a3:	mov    -0x580(%rbp),%rdi
   682aa:	mov    -0x588(%rbp),%r11
   682b1:	xor    %r8d,%r8d
   682b4:	mov    (%rdi),%rdx
   682b7:	mov    %rdx,(%r11)
   682ba:	mov    0x8(%rdi),%rcx
   682be:	mov    %rcx,0x8(%r11)
   682c2:	mov    0x10(%rdi),%rsi
   682c6:	xor    %edi,%edi
   682c8:	mov    %rsi,0x10(%r11)
   682cc:	mov    %edx,%esi
   682ce:	subl   $0x1,-0x530(%rbp)
   682d5:	je     69cfd <_IO_vfwscanf+0x5d1d>
   682db:	cmp    $0x2f,%esi
   682de:	ja     69969 <_IO_vfwscanf+0x5989>
   682e4:	add    $0x8,%esi
   682e7:	mov    $0x1,%r8d
   682ed:	jmp    682ce <_IO_vfwscanf+0x42ee>
   682ef:	nop
   682f0:	sub    $0x120,%rsp
   682f7:	mov    -0x510(%rbp),%rdi
   682fe:	mov    $0x1,%ecx
   68303:	lea    0xf(%rsp),%rdx
   68308:	and    $0xfffffffffffffff0,%rdx
   6830c:	movq   $0x0,(%rdx)
   68313:	mov    %rdi,0x8(%rdx)
   68317:	mov    %rdx,-0x510(%rbp)
   6831e:	xor    %edx,%edx
   68320:	jmpq   64df9 <_IO_vfwscanf+0xe19>
   68325:	sub    -0x440(%rbp),%rdx
   6832c:	mov    -0x5b0(%rbp),%rdi
   68333:	mov    %rdx,%r13
   68336:	callq  8afb0 <__libc_scratch_buffer_grow_preserve>
   6833b:	test   %al,%al
   6833d:	je     6af23 <_IO_vfwscanf+0x6f43>
   68343:	mov    -0x438(%rbp),%rdx
   6834a:	mov    -0x440(%rbp),%rax
   68351:	and    $0xfffffffffffffffc,%rdx
   68355:	add    %rax,%rdx
   68358:	add    %r13,%rax
   6835b:	mov    $0x1,%r13d
   68361:	mov    %rdx,-0x448(%rbp)
   68368:	lea    0x4(%rax),%rdx
   6836c:	mov    %rdx,-0x450(%rbp)
   68373:	mov    %r15d,(%rax)
   68376:	jmpq   6586d <_IO_vfwscanf+0x188d>
   6837b:	sub    $0x120,%rsp
   68382:	mov    -0x510(%rbp),%rdi
   68389:	mov    $0x1,%ecx
   6838e:	lea    0xf(%rsp),%rdx
   68393:	and    $0xfffffffffffffff0,%rdx
   68397:	movq   $0x0,(%rdx)
   6839e:	mov    %rdi,0x8(%rdx)
   683a2:	mov    %rdx,-0x510(%rbp)
   683a9:	xor    %edx,%edx
   683ab:	jmpq   64b2d <_IO_vfwscanf+0xb4d>
   683b0:	mov    -0x580(%rbp),%rcx
   683b7:	mov    -0x588(%rbp),%rsi
   683be:	xor    %edi,%edi
   683c0:	mov    -0x530(%rbp),%r8d
   683c7:	mov    (%rcx),%rax
   683ca:	mov    %rax,(%rsi)
   683cd:	mov    0x8(%rcx),%rdx
   683d1:	mov    %rdx,0x8(%rsi)
   683d5:	mov    0x10(%rcx),%rcx
   683d9:	mov    %rcx,0x10(%rsi)
   683dd:	mov    %eax,%ecx
   683df:	xor    %esi,%esi
   683e1:	sub    $0x1,%r8d
   683e5:	je     69cbe <_IO_vfwscanf+0x5cde>
   683eb:	cmp    $0x2f,%ecx
   683ee:	ja     69cb0 <_IO_vfwscanf+0x5cd0>
   683f4:	add    $0x8,%ecx
   683f7:	mov    $0x1,%esi
   683fc:	jmp    683e1 <_IO_vfwscanf+0x4401>
   683fe:	xchg   %ax,%ax
   68400:	mov    %r14,%r15
   68403:	mov    -0x510(%rbp),%r14
   6840a:	jmpq   67f1f <_IO_vfwscanf+0x3f3f>
   6840f:	mov    -0x580(%rbp),%rcx
   68416:	mov    -0x588(%rbp),%rdi
   6841d:	xor    %esi,%esi
   6841f:	mov    -0x530(%rbp),%r8d
   68426:	mov    (%rcx),%rax
   68429:	mov    %rax,(%rdi)
   6842c:	mov    0x8(%rcx),%rdx
   68430:	mov    %rdx,0x8(%rdi)
   68434:	mov    0x10(%rcx),%rcx
   68438:	mov    %rcx,0x10(%rdi)
   6843c:	mov    %eax,%ecx
   6843e:	xor    %edi,%edi
   68440:	sub    $0x1,%r8d
   68444:	je     6a1aa <_IO_vfwscanf+0x61ca>
   6844a:	cmp    $0x2f,%ecx
   6844d:	ja     6a19c <_IO_vfwscanf+0x61bc>
   68453:	add    $0x8,%ecx
   68456:	mov    $0x1,%esi
   6845b:	jmp    68440 <_IO_vfwscanf+0x4460>
   6845d:	nopl   (%rax)
   68460:	mov    -0x530(%rbp),%eax
   68466:	test   %eax,%eax
   68468:	jne    68bb4 <_IO_vfwscanf+0x4bd4>
   6846e:	mov    -0x4d8(%rbp),%edx
   68474:	cmp    $0x2f,%edx
   68477:	ja     6a1fb <_IO_vfwscanf+0x621b>
   6847d:	mov    %edx,%eax
   6847f:	add    -0x4c8(%rbp),%rax
   68486:	add    $0x8,%edx
   68489:	mov    %edx,-0x4d8(%rbp)
   6848f:	mov    (%rax),%rax
   68492:	mov    %rax,-0x570(%rbp)
   68499:	cmpq   $0x0,-0x570(%rbp)
   684a1:	jne    65a45 <_IO_vfwscanf+0x1a65>
   684a7:	mov    %r14,%r15
   684aa:	mov    -0x504(%rbp),%ebx
   684b0:	mov    -0x510(%rbp),%r14
   684b7:	movl   $0x2,-0x508(%rbp)
   684c1:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   684c6:	nopw   %cs:0x0(%rax,%rax,1)
   684d0:	mov    -0x580(%rbp),%rdi
   684d7:	mov    -0x588(%rbp),%rsi
   684de:	mov    -0x530(%rbp),%r8d
   684e5:	mov    (%rdi),%rax
   684e8:	mov    %rax,(%rsi)
   684eb:	mov    0x8(%rdi),%rdx
   684ef:	mov    %rdx,0x8(%rsi)
   684f3:	mov    0x10(%rdi),%rcx
   684f7:	xor    %edi,%edi
   684f9:	mov    %rcx,0x10(%rsi)
   684fd:	mov    %eax,%ecx
   684ff:	xor    %esi,%esi
   68501:	sub    $0x1,%r8d
   68505:	je     6ad93 <_IO_vfwscanf+0x6db3>
   6850b:	cmp    $0x2f,%ecx
   6850e:	ja     6ad85 <_IO_vfwscanf+0x6da5>
   68514:	add    $0x8,%ecx
   68517:	mov    $0x1,%edi
   6851c:	jmp    68501 <_IO_vfwscanf+0x4521>
   6851e:	xchg   %ax,%ax
   68520:	mov    %r14,%r15
   68523:	mov    -0x510(%rbp),%r14
   6852a:	jmpq   67f4e <_IO_vfwscanf+0x3f6e>
   6852f:	mov    -0x580(%rbp),%rdi
   68536:	mov    -0x588(%rbp),%rsi
   6853d:	mov    (%rdi),%rax
   68540:	mov    %rax,(%rsi)
   68543:	mov    0x8(%rdi),%rdx
   68547:	mov    %rdx,0x8(%rsi)
   6854b:	mov    0x10(%rdi),%rcx
   6854f:	xor    %edi,%edi
   68551:	mov    %rcx,0x10(%rsi)
   68555:	mov    %eax,%ecx
   68557:	xor    %esi,%esi
   68559:	subl   $0x1,-0x530(%rbp)
   68560:	je     6b77d <_IO_vfwscanf+0x779d>
   68566:	cmp    $0x2f,%ecx
   68569:	ja     6b683 <_IO_vfwscanf+0x76a3>
   6856f:	add    $0x8,%ecx
   68572:	mov    $0x1,%esi
   68577:	jmp    68559 <_IO_vfwscanf+0x4579>
   68579:	nopl   0x0(%rax)
   68580:	mov    -0x580(%rbp),%rdi
   68587:	mov    -0x588(%rbp),%rsi
   6858e:	mov    (%rdi),%rax
   68591:	mov    %rax,(%rsi)
   68594:	mov    0x8(%rdi),%rdx
   68598:	mov    %rdx,0x8(%rsi)
   6859c:	mov    0x10(%rdi),%rcx
   685a0:	xor    %edi,%edi
   685a2:	mov    %rcx,0x10(%rsi)
   685a6:	mov    %eax,%ecx
   685a8:	xor    %esi,%esi
   685aa:	subl   $0x1,-0x530(%rbp)
   685b1:	je     6ad32 <_IO_vfwscanf+0x6d52>
   685b7:	cmp    $0x2f,%ecx
   685ba:	ja     6ad24 <_IO_vfwscanf+0x6d44>
   685c0:	add    $0x8,%ecx
   685c3:	mov    $0x1,%edi
   685c8:	jmp    685aa <_IO_vfwscanf+0x45ca>
   685ca:	nopw   0x0(%rax,%rax,1)
   685d0:	mov    -0x580(%rbp),%rdi
   685d7:	mov    -0x588(%rbp),%rsi
   685de:	mov    (%rdi),%rax
   685e1:	mov    %rax,(%rsi)
   685e4:	mov    0x8(%rdi),%rdx
   685e8:	mov    %rdx,0x8(%rsi)
   685ec:	mov    0x10(%rdi),%rcx
   685f0:	xor    %edi,%edi
   685f2:	mov    %rcx,0x10(%rsi)
   685f6:	mov    %eax,%ecx
   685f8:	xor    %esi,%esi
   685fa:	subl   $0x1,-0x530(%rbp)
   68601:	je     6ae1b <_IO_vfwscanf+0x6e3b>
   68607:	cmp    $0x2f,%ecx
   6860a:	ja     6ae0d <_IO_vfwscanf+0x6e2d>
   68610:	add    $0x8,%ecx
   68613:	mov    $0x1,%esi
   68618:	jmp    685fa <_IO_vfwscanf+0x461a>
   6861a:	nopw   0x0(%rax,%rax,1)
   68620:	mov    -0x580(%rbp),%rdi
   68627:	mov    -0x588(%rbp),%r11
   6862e:	xor    %r8d,%r8d
   68631:	mov    (%rdi),%rdx
   68634:	mov    %rdx,(%r11)
   68637:	mov    0x8(%rdi),%rcx
   6863b:	mov    %rcx,0x8(%r11)
   6863f:	mov    0x10(%rdi),%rsi
   68643:	xor    %edi,%edi
   68645:	mov    %rsi,0x10(%r11)
   68649:	mov    %edx,%esi
   6864b:	subl   $0x1,-0x530(%rbp)
   68652:	je     69cfd <_IO_vfwscanf+0x5d1d>
   68658:	cmp    $0x2f,%esi
   6865b:	ja     6ace0 <_IO_vfwscanf+0x6d00>
   68661:	add    $0x8,%esi
   68664:	mov    $0x1,%r8d
   6866a:	jmp    6864b <_IO_vfwscanf+0x466b>
   6866c:	nopl   0x0(%rax)
   68670:	pxor   %xmm0,%xmm0
   68674:	mov    %r14,%r15
   68677:	mov    -0x510(%rbp),%r14
   6867e:	movaps %xmm0,-0x450(%rbp)
   68685:	jmpq   66c69 <_IO_vfwscanf+0x2c89>
   6868a:	mov    %r14d,%edx
   6868d:	mov    $0x39,%r13d
   68693:	mov    $0x39,%r15d
   68699:	jmpq   67ba0 <_IO_vfwscanf+0x3bc0>
   6869e:	mov    %r14d,%edx
   686a1:	mov    $0x38,%r13d
   686a7:	mov    $0x38,%r15d
   686ad:	jmpq   67ba0 <_IO_vfwscanf+0x3bc0>
   686b2:	mov    %r14d,%edx
   686b5:	mov    $0x37,%r13d
   686bb:	mov    $0x37,%r15d
   686c1:	jmpq   67ba0 <_IO_vfwscanf+0x3bc0>
   686c6:	mov    %r14d,%edx
   686c9:	mov    $0x36,%r13d
   686cf:	mov    $0x36,%r15d
   686d5:	jmpq   67ba0 <_IO_vfwscanf+0x3bc0>
   686da:	mov    %r14d,%edx
   686dd:	mov    $0x34,%r13d
   686e3:	mov    $0x34,%r15d
   686e9:	jmpq   67ba0 <_IO_vfwscanf+0x3bc0>
   686ee:	mov    %r14,%r15
   686f1:	mov    -0x504(%rbp),%ebx
   686f7:	mov    -0x510(%rbp),%r14
   686fe:	movl   $0x2,-0x508(%rbp)
   68708:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6870d:	mov    %r14d,%edx
   68710:	mov    $0x33,%r13d
   68716:	mov    $0x33,%r15d
   6871c:	jmpq   67ba0 <_IO_vfwscanf+0x3bc0>
   68721:	sub    $0x120,%rsp
   68728:	mov    -0x510(%rbp),%rcx
   6872f:	lea    0xf(%rsp),%rdx
   68734:	and    $0xfffffffffffffff0,%rdx
   68738:	mov    %rcx,0x8(%rdx)
   6873c:	mov    %rdx,-0x510(%rbp)
   68743:	mov    $0x1,%ecx
   68748:	movq   $0x0,(%rdx)
   6874f:	mov    -0x510(%rbp),%rdi
   68756:	xor    %edx,%edx
   68758:	jmpq   65212 <_IO_vfwscanf+0x1232>
   6875d:	mov    -0x580(%rbp),%rdi
   68764:	mov    -0x588(%rbp),%r11
   6876b:	xor    %r8d,%r8d
   6876e:	mov    (%rdi),%rdx
   68771:	mov    %rdx,(%r11)
   68774:	mov    0x8(%rdi),%rcx
   68778:	mov    %rcx,0x8(%r11)
   6877c:	mov    0x10(%rdi),%rsi
   68780:	xor    %edi,%edi
   68782:	mov    %rsi,0x10(%r11)
   68786:	mov    %edx,%esi
   68788:	subl   $0x1,-0x530(%rbp)
   6878f:	je     6a4b9 <_IO_vfwscanf+0x64d9>
   68795:	cmp    $0x2f,%esi
   68798:	ja     6a09c <_IO_vfwscanf+0x60bc>
   6879e:	add    $0x8,%esi
   687a1:	mov    $0x1,%r8d
   687a7:	jmp    68788 <_IO_vfwscanf+0x47a8>
   687a9:	nopl   0x0(%rax)
   687b0:	and    $0x2000,%r13d
   687b7:	mov    %r14,%r15
   687ba:	mov    -0x510(%rbp),%r14
   687c1:	jne    6986d <_IO_vfwscanf+0x588d>
   687c7:	mov    -0x504(%rbp),%ebx
   687cd:	movl   $0x2,-0x508(%rbp)
   687d7:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   687dc:	mov    %r14,%rdi
   687df:	callq  73620 <__wuflow>
   687e4:	mov    %eax,%r15d
   687e7:	jmpq   65712 <_IO_vfwscanf+0x1732>
   687ec:	sub    $0x120,%rsp
   687f3:	mov    -0x520(%rbp),%rdi
   687fa:	lea    0xf(%rsp),%rdx
   687ff:	and    $0xfffffffffffffff0,%rdx
   68803:	mov    %rcx,0x8(%rdx)
   68807:	movq   $0x0,(%rdx)
   6880e:	mov    $0x1,%ecx
   68813:	mov    %rdx,-0x510(%rbp)
   6881a:	xor    %edx,%edx
   6881c:	jmpq   66a57 <_IO_vfwscanf+0x2a77>
   68821:	mov    %r14,%r15
   68824:	mov    -0x504(%rbp),%ebx
   6882a:	mov    -0x510(%rbp),%r14
   68831:	movl   $0x2,-0x508(%rbp)
   6883b:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   68840:	mov    -0x530(%rbp),%r10d
   68847:	test   %r10d,%r10d
   6884a:	jne    695da <_IO_vfwscanf+0x55fa>
   68850:	mov    -0x4d8(%rbp),%edx
   68856:	cmp    $0x2f,%edx
   68859:	ja     69856 <_IO_vfwscanf+0x5876>
   6885f:	mov    %edx,%eax
   68861:	add    -0x4c8(%rbp),%rax
   68868:	add    $0x8,%edx
   6886b:	mov    %edx,-0x4d8(%rbp)
   68871:	mov    (%rax),%rax
   68874:	movzbl -0x4f8(%rbp),%edi
   6887b:	movl   $0x0,-0x500(%rbp)
   68885:	mov    %dil,(%rax)
   68888:	jmpq   641fa <_IO_vfwscanf+0x21a>
   6888d:	mov    -0x538(%rbp),%r9d
   68894:	test   %r9d,%r9d
   68897:	je     68c8f <_IO_vfwscanf+0x4caf>
   6889d:	cmp    $0xffffffff,%r15d
   688a1:	je     6aff2 <_IO_vfwscanf+0x7012>
   688a7:	mov    0xa0(%r14),%rax
   688ae:	test   %rax,%rax
   688b1:	je     6b020 <_IO_vfwscanf+0x7040>
   688b7:	mov    (%rax),%rdx
   688ba:	cmp    0x8(%rax),%rdx
   688be:	jae    6b020 <_IO_vfwscanf+0x7040>
   688c4:	lea    0x4(%rdx),%rcx
   688c8:	mov    (%rdx),%r15d
   688cb:	mov    %rcx,(%rax)
   688ce:	cmp    $0xffffffff,%r15d
   688d2:	je     6afb2 <_IO_vfwscanf+0x6fd2>
   688d8:	mov    -0x4f8(%rbp),%rax
   688df:	mov    -0x578(%rbp),%rsi
   688e6:	mov    %r13d,-0x568(%rbp)
   688ed:	add    $0x1,%rax
   688f1:	mov    %rax,-0x538(%rbp)
   688f8:	mov    %r13d,%eax
   688fb:	mov    %r12d,%r13d
   688fe:	and    $0x2100,%eax
   68903:	mov    %r8,%r12
   68906:	mov    %eax,-0x558(%rbp)
   6890c:	movzbl -0x530(%rbp),%eax
   68913:	xor    $0x1,%eax
   68916:	mov    %al,-0x560(%rbp)
   6891c:	mov    -0x4e0(%rbp),%r10
   68923:	cmp    %r10,%r12
   68926:	mov    %r10,%rax
   68929:	ja     68942 <_IO_vfwscanf+0x4962>
   6892b:	jmpq   68a59 <_IO_vfwscanf+0x4a79>
   68930:	cmp    %edx,%r15d
   68933:	je     68988 <_IO_vfwscanf+0x49a8>
   68935:	add    $0x4,%rax
   68939:	cmp    %rax,%r12
   6893c:	jbe    68a59 <_IO_vfwscanf+0x4a79>
   68942:	mov    (%rax),%edx
   68944:	cmp    $0x2d,%edx
   68947:	jne    68930 <_IO_vfwscanf+0x4950>
   68949:	mov    0x4(%rax),%edi
   6894c:	test   %edi,%edi
   6894e:	je     68930 <_IO_vfwscanf+0x4950>
   68950:	lea    0x4(%rax),%rcx
   68954:	cmp    %rcx,%r12
   68957:	je     68930 <_IO_vfwscanf+0x4950>
   68959:	cmp    %rax,%r10
   6895c:	je     68930 <_IO_vfwscanf+0x4950>
   6895e:	mov    -0x4(%rax),%ecx
   68961:	cmp    %edi,%ecx
   68963:	ja     68930 <_IO_vfwscanf+0x4950>
   68965:	lea    0x1(%rcx),%edx
   68968:	cmp    %edx,%edi
   6896a:	jge    68983 <_IO_vfwscanf+0x49a3>
   6896c:	jmpq   68a50 <_IO_vfwscanf+0x4a70>
   68971:	nopl   0x0(%rax)
   68978:	add    $0x1,%edx
   6897b:	cmp    %edx,%edi
   6897d:	jl     68a50 <_IO_vfwscanf+0x4a70>
   68983:	cmp    %edx,%r15d
   68986:	jne    68978 <_IO_vfwscanf+0x4998>
   68988:	mov    -0x530(%rbp),%r8d
   6898f:	test   %r8d,%r8d
   68992:	je     68a59 <_IO_vfwscanf+0x4a79>
   68998:	mov    %rsi,-0x578(%rbp)
   6899f:	mov    %r14,%rdi
   689a2:	mov    %r15d,%esi
   689a5:	subq   $0x1,-0x538(%rbp)
   689ad:	callq  74430 <_IO_sputbackwc>
   689b2:	mov    -0x4f8(%rbp),%rdi
   689b9:	cmp    %rdi,-0x538(%rbp)
   689c0:	je     6a105 <_IO_vfwscanf+0x6125>
   689c6:	mov    -0x500(%rbp),%ecx
   689cc:	test   %ecx,%ecx
   689ce:	jne    68afe <_IO_vfwscanf+0x4b1e>
   689d4:	cmpl   $0x0,-0x558(%rbp)
   689db:	mov    -0x578(%rbp),%rax
   689e2:	lea    0x4(%rax),%r12
   689e6:	movl   $0x0,(%rax)
   689ec:	je     68a1d <_IO_vfwscanf+0x4a3d>
   689ee:	mov    -0x520(%rbp),%r13
   689f5:	mov    %r12,%rsi
   689f8:	mov    0x0(%r13),%rdi
   689fc:	sub    %rdi,%rsi
   689ff:	mov    %rsi,%rax
   68a02:	sar    $0x2,%rax
   68a06:	cmp    %rax,-0x550(%rbp)
   68a0d:	je     68a1d <_IO_vfwscanf+0x4a3d>
   68a0f:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   68a14:	test   %rax,%rax
   68a17:	je     68a1d <_IO_vfwscanf+0x4a3d>
   68a19:	mov    %rax,0x0(%r13)
   68a1d:	mov    -0x538(%rbp),%rax
   68a24:	addl   $0x1,-0x504(%rbp)
   68a2b:	mov    %r12,-0x578(%rbp)
   68a32:	movq   $0x0,-0x520(%rbp)
   68a3d:	mov    %rax,-0x4f8(%rbp)
   68a44:	jmpq   641fa <_IO_vfwscanf+0x21a>
   68a49:	nopl   0x0(%rax)
   68a50:	add    $0x8,%rax
   68a54:	jmpq   68939 <_IO_vfwscanf+0x4959>
   68a59:	cmp    %rax,%r12
   68a5c:	jne    68a6b <_IO_vfwscanf+0x4a8b>
   68a5e:	cmpb   $0x0,-0x560(%rbp)
   68a65:	jne    68998 <_IO_vfwscanf+0x49b8>
   68a6b:	mov    -0x500(%rbp),%edi
   68a71:	test   %edi,%edi
   68a73:	jne    68ab3 <_IO_vfwscanf+0x4ad3>
   68a75:	lea    0x4(%rsi),%rax
   68a79:	mov    %r15d,(%rsi)
   68a7c:	mov    -0x558(%rbp),%esi
   68a82:	test   %esi,%esi
   68a84:	je     69460 <_IO_vfwscanf+0x5480>
   68a8a:	mov    -0x520(%rbp),%rsi
   68a91:	mov    -0x550(%rbp),%rcx
   68a98:	mov    (%rsi),%rdi
   68a9b:	lea    0x0(,%rcx,4),%rdx
   68aa3:	mov    %rax,%rsi
   68aa6:	lea    (%rdi,%rdx,1),%rcx
   68aaa:	cmp    %rcx,%rax
   68aad:	je     6b0bf <_IO_vfwscanf+0x70df>
   68ab3:	sub    $0x1,%r13d
   68ab7:	test   %r13d,%r13d
   68aba:	jle    6abc6 <_IO_vfwscanf+0x6be6>
   68ac0:	mov    0xa0(%r14),%rax
   68ac7:	test   %rax,%rax
   68aca:	je     69000 <_IO_vfwscanf+0x5020>
   68ad0:	mov    (%rax),%rdx
   68ad3:	cmp    0x8(%rax),%rdx
   68ad7:	jae    69000 <_IO_vfwscanf+0x5020>
   68add:	lea    0x4(%rdx),%rcx
   68ae1:	mov    (%rdx),%r15d
   68ae4:	mov    %rcx,(%rax)
   68ae7:	cmp    $0xffffffff,%r15d
   68aeb:	je     68fe4 <_IO_vfwscanf+0x5004>
   68af1:	addq   $0x1,-0x538(%rbp)
   68af9:	jmpq   6891c <_IO_vfwscanf+0x493c>
   68afe:	mov    -0x538(%rbp),%rax
   68b05:	movl   $0x0,-0x500(%rbp)
   68b0f:	mov    %rax,-0x4f8(%rbp)
   68b16:	jmpq   641fa <_IO_vfwscanf+0x21a>
   68b1b:	mov    %r14,%rdi
   68b1e:	callq  73620 <__wuflow>
   68b23:	mov    %eax,%r15d
   68b26:	jmpq   65a76 <_IO_vfwscanf+0x1a96>
   68b2b:	mov    %r14,%rdi
   68b2e:	callq  73620 <__wuflow>
   68b33:	mov    %eax,%r15d
   68b36:	jmpq   65011 <_IO_vfwscanf+0x1031>
   68b3b:	mov    -0x580(%rbp),%rdi
   68b42:	mov    -0x588(%rbp),%rsi
   68b49:	mov    (%rdi),%rax
   68b4c:	mov    %rax,(%rsi)
   68b4f:	mov    0x8(%rdi),%rdx
   68b53:	mov    %rdx,0x8(%rsi)
   68b57:	mov    0x10(%rdi),%rcx
   68b5b:	xor    %edi,%edi
   68b5d:	mov    %rcx,0x10(%rsi)
   68b61:	mov    %eax,%ecx
   68b63:	xor    %esi,%esi
   68b65:	subl   $0x1,-0x530(%rbp)
   68b6c:	je     6a22a <_IO_vfwscanf+0x624a>
   68b72:	cmp    $0x2f,%ecx
   68b75:	ja     6a1ed <_IO_vfwscanf+0x620d>
   68b7b:	add    $0x8,%ecx
   68b7e:	mov    $0x1,%esi
   68b83:	jmp    68b65 <_IO_vfwscanf+0x4b85>
   68b85:	nopl   (%rax)
   68b88:	and    $0x2000,%r13d
   68b8f:	mov    %r14,%r15
   68b92:	mov    -0x510(%rbp),%r14
   68b99:	jne    6a212 <_IO_vfwscanf+0x6232>
   68b9f:	mov    -0x504(%rbp),%ebx
   68ba5:	movl   $0x2,-0x508(%rbp)
   68baf:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   68bb4:	mov    -0x580(%rbp),%rdi
   68bbb:	mov    -0x588(%rbp),%rsi
   68bc2:	mov    (%rdi),%rax
   68bc5:	mov    %rax,(%rsi)
   68bc8:	mov    0x8(%rdi),%rdx
   68bcc:	mov    %rdx,0x8(%rsi)
   68bd0:	mov    0x10(%rdi),%rcx
   68bd4:	xor    %edi,%edi
   68bd6:	mov    %rcx,0x10(%rsi)
   68bda:	mov    %eax,%ecx
   68bdc:	xor    %esi,%esi
   68bde:	subl   $0x1,-0x530(%rbp)
   68be5:	je     6af6f <_IO_vfwscanf+0x6f8f>
   68beb:	cmp    $0x2f,%ecx
   68bee:	ja     6af61 <_IO_vfwscanf+0x6f81>
   68bf4:	add    $0x8,%ecx
   68bf7:	mov    $0x1,%esi
   68bfc:	jmp    68bde <_IO_vfwscanf+0x4bfe>
   68bfe:	xchg   %ax,%ax
   68c00:	mov    -0x450(%rbp),%rax
   68c07:	cmp    -0x448(%rbp),%rax
   68c0e:	je     6b06a <_IO_vfwscanf+0x708a>
   68c14:	lea    0x4(%rax),%rdx
   68c18:	mov    %rdx,-0x450(%rbp)
   68c1f:	mov    %r15d,(%rax)
   68c22:	mov    %r13d,%eax
   68c25:	and    $0x7f,%al
   68c27:	or     $0x8,%ah
   68c2a:	cmp    $0xffffffff,%r15d
   68c2e:	mov    %eax,%r13d
   68c31:	je     6b055 <_IO_vfwscanf+0x7075>
   68c37:	mov    0xa0(%r14),%rax
   68c3e:	test   %rax,%rax
   68c41:	je     6b07e <_IO_vfwscanf+0x709e>
   68c47:	mov    (%rax),%rdx
   68c4a:	cmp    0x8(%rax),%rdx
   68c4e:	jae    6b07e <_IO_vfwscanf+0x709e>
   68c54:	lea    0x4(%rdx),%rcx
   68c58:	mov    (%rdx),%r15d
   68c5b:	mov    %rcx,(%rax)
   68c5e:	cmp    $0xffffffff,%r15d
   68c62:	je     6afdd <_IO_vfwscanf+0x6ffd>
   68c68:	addq   $0x1,-0x500(%rbp)
   68c70:	test   %r12d,%r12d
   68c73:	jle    6b00e <_IO_vfwscanf+0x702e>
   68c79:	sub    $0x1,%r12d
   68c7d:	movl   $0x70,-0x4f8(%rbp)
   68c87:	xor    %r8d,%r8d
   68c8a:	jmpq   657f6 <_IO_vfwscanf+0x1816>
   68c8f:	cmp    $0xffffffff,%r15d
   68c93:	je     6a7d9 <_IO_vfwscanf+0x67f9>
   68c99:	mov    0xa0(%r14),%rax
   68ca0:	test   %rax,%rax
   68ca3:	je     6a872 <_IO_vfwscanf+0x6892>
   68ca9:	mov    (%rax),%rdx
   68cac:	cmp    0x8(%rax),%rdx
   68cb0:	jae    6a872 <_IO_vfwscanf+0x6892>
   68cb6:	lea    0x4(%rdx),%rcx
   68cba:	mov    (%rdx),%r15d
   68cbd:	mov    %rcx,(%rax)
   68cc0:	cmp    $0xffffffff,%r15d
   68cc4:	je     6a866 <_IO_vfwscanf+0x6886>
   68cca:	mov    -0x4f8(%rbp),%rax
   68cd1:	mov    -0x570(%rbp),%rcx
   68cd8:	mov    %rbx,-0x560(%rbp)
   68cdf:	mov    %r13d,-0x558(%rbp)
   68ce6:	mov    %r12d,%ebx
   68ce9:	mov    %r8,%r12
   68cec:	add    $0x1,%rax
   68cf0:	mov    %rax,-0x538(%rbp)
   68cf7:	mov    -0x590(%rbp),%rax
   68cfe:	movq   $0x0,(%rax)
   68d05:	mov    %r13d,%eax
   68d08:	mov    %r15d,%r13d
   68d0b:	and    $0x2100,%eax
   68d10:	mov    %eax,-0x568(%rbp)
   68d16:	movzbl -0x530(%rbp),%eax
   68d1d:	xor    $0x1,%eax
   68d20:	mov    %al,-0x598(%rbp)
   68d26:	mov    -0x4e0(%rbp),%r10
   68d2d:	cmp    %r10,%r12
   68d30:	mov    %r10,%rax
   68d33:	ja     68d52 <_IO_vfwscanf+0x4d72>
   68d35:	jmpq   68ec9 <_IO_vfwscanf+0x4ee9>
   68d3a:	nopw   0x0(%rax,%rax,1)
   68d40:	cmp    %edx,%r13d
   68d43:	je     68d98 <_IO_vfwscanf+0x4db8>
   68d45:	add    $0x4,%rax
   68d49:	cmp    %rax,%r12
   68d4c:	jbe    68ec9 <_IO_vfwscanf+0x4ee9>
   68d52:	mov    (%rax),%edx
   68d54:	cmp    $0x2d,%edx
   68d57:	jne    68d40 <_IO_vfwscanf+0x4d60>
   68d59:	mov    0x4(%rax),%edi
   68d5c:	test   %edi,%edi
   68d5e:	je     68d40 <_IO_vfwscanf+0x4d60>
   68d60:	lea    0x4(%rax),%rsi
   68d64:	cmp    %rsi,%r12
   68d67:	je     68d40 <_IO_vfwscanf+0x4d60>
   68d69:	cmp    %rax,%r10
   68d6c:	je     68d40 <_IO_vfwscanf+0x4d60>
   68d6e:	mov    -0x4(%rax),%esi
   68d71:	cmp    %edi,%esi
   68d73:	ja     68d40 <_IO_vfwscanf+0x4d60>
   68d75:	lea    0x1(%rsi),%edx
   68d78:	cmp    %edx,%edi
   68d7a:	jge    68d93 <_IO_vfwscanf+0x4db3>
   68d7c:	jmpq   68ec0 <_IO_vfwscanf+0x4ee0>
   68d81:	nopl   0x0(%rax)
   68d88:	add    $0x1,%edx
   68d8b:	cmp    %edx,%edi
   68d8d:	jl     68ec0 <_IO_vfwscanf+0x4ee0>
   68d93:	cmp    %edx,%r13d
   68d96:	jne    68d88 <_IO_vfwscanf+0x4da8>
   68d98:	mov    -0x530(%rbp),%edi
   68d9e:	test   %edi,%edi
   68da0:	je     68ec9 <_IO_vfwscanf+0x4ee9>
   68da6:	mov    %r13d,%r15d
   68da9:	mov    %r14,%rdi
   68dac:	mov    -0x560(%rbp),%rbx
   68db3:	mov    %r15d,%esi
   68db6:	mov    %rcx,-0x570(%rbp)
   68dbd:	mov    -0x558(%rbp),%r13d
   68dc4:	subq   $0x1,-0x538(%rbp)
   68dcc:	callq  74430 <_IO_sputbackwc>
   68dd1:	mov    -0x4f8(%rbp),%rcx
   68dd8:	cmp    %rcx,-0x538(%rbp)
   68ddf:	je     6a8fa <_IO_vfwscanf+0x691a>
   68de5:	mov    -0x500(%rbp),%eax
   68deb:	test   %eax,%eax
   68ded:	jne    68afe <_IO_vfwscanf+0x4b1e>
   68df3:	mov    -0x590(%rbp),%rdx
   68dfa:	mov    -0x588(%rbp),%rdi
   68e01:	xor    %esi,%esi
   68e03:	callq  ac610 <c32rtomb>
   68e08:	test   %rax,%rax
   68e0b:	mov    %rax,%rcx
   68e0e:	je     6a8c5 <_IO_vfwscanf+0x68e5>
   68e14:	cmpl   $0x0,-0x568(%rbp)
   68e1b:	je     6a89c <_IO_vfwscanf+0x68bc>
   68e21:	mov    -0x520(%rbp),%rax
   68e28:	mov    (%rax),%rdi
   68e2b:	mov    -0x570(%rbp),%rax
   68e32:	lea    (%rax,%rcx,1),%rdx
   68e36:	mov    -0x550(%rbp),%rax
   68e3d:	add    %rdi,%rax
   68e40:	cmp    %rax,%rdx
   68e43:	jae    6a781 <_IO_vfwscanf+0x67a1>
   68e49:	mov    -0x570(%rbp),%rdi
   68e50:	mov    -0x588(%rbp),%rsi
   68e57:	mov    %rcx,%rdx
   68e5a:	callq  90920 <__GI___mempcpy>
   68e5f:	lea    0x1(%rax),%rdi
   68e63:	movb   $0x0,(%rax)
   68e66:	mov    %rdi,-0x570(%rbp)
   68e6d:	mov    -0x520(%rbp),%r13
   68e74:	mov    -0x570(%rbp),%rsi
   68e7b:	mov    0x0(%r13),%rdi
   68e7f:	sub    %rdi,%rsi
   68e82:	cmp    -0x550(%rbp),%rsi
   68e89:	je     68e99 <_IO_vfwscanf+0x4eb9>
   68e8b:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   68e90:	test   %rax,%rax
   68e93:	je     68e99 <_IO_vfwscanf+0x4eb9>
   68e95:	mov    %rax,0x0(%r13)
   68e99:	mov    -0x538(%rbp),%rax
   68ea0:	addl   $0x1,-0x504(%rbp)
   68ea7:	movq   $0x0,-0x520(%rbp)
   68eb2:	mov    %rax,-0x4f8(%rbp)
   68eb9:	jmpq   641fa <_IO_vfwscanf+0x21a>
   68ebe:	xchg   %ax,%ax
   68ec0:	add    $0x8,%rax
   68ec4:	jmpq   68d49 <_IO_vfwscanf+0x4d69>
   68ec9:	cmp    %rax,%r12
   68ecc:	jne    68edb <_IO_vfwscanf+0x4efb>
   68ece:	cmpb   $0x0,-0x598(%rbp)
   68ed5:	jne    68da6 <_IO_vfwscanf+0x4dc6>
   68edb:	mov    -0x500(%rbp),%edx
   68ee1:	test   %edx,%edx
   68ee3:	jne    68fad <_IO_vfwscanf+0x4fcd>
   68ee9:	mov    -0x568(%rbp),%eax
   68eef:	test   %eax,%eax
   68ef1:	je     68f28 <_IO_vfwscanf+0x4f48>
   68ef3:	mov    -0x520(%rbp),%rax
   68efa:	mov    -0x550(%rbp),%rsi
   68f01:	mov    (%rax),%rdi
   68f04:	mov    0x356ea5(%rip),%rax        # 3bfdb0 <_DYNAMIC+0x250>
   68f0b:	mov    %fs:(%rax),%rax
   68f0f:	lea    (%rdi,%rsi,1),%rdx
   68f13:	mov    (%rax),%rax
   68f16:	mov    0xa8(%rax),%eax
   68f1c:	add    %rcx,%rax
   68f1f:	cmp    %rdx,%rax
   68f22:	jae    6a919 <_IO_vfwscanf+0x6939>
   68f28:	mov    %rcx,%r15
   68f2b:	mov    -0x590(%rbp),%rdx
   68f32:	mov    %r13d,%esi
   68f35:	mov    %rcx,%rdi
   68f38:	callq  ac610 <c32rtomb>
   68f3d:	cmp    $0xffffffffffffffff,%rax
   68f41:	je     6aef6 <_IO_vfwscanf+0x6f16>
   68f47:	mov    0x356e62(%rip),%rdi        # 3bfdb0 <_DYNAMIC+0x250>
   68f4e:	mov    %fs:(%rdi),%rdx
   68f52:	mov    (%rdx),%rdx
   68f55:	mov    0xa8(%rdx),%edx
   68f5b:	cmp    %rdx,%rax
   68f5e:	ja     6aed7 <_IO_vfwscanf+0x6ef7>
   68f64:	sub    $0x1,%ebx
   68f67:	lea    (%r15,%rax,1),%rcx
   68f6b:	test   %ebx,%ebx
   68f6d:	jle    6aeba <_IO_vfwscanf+0x6eda>
   68f73:	mov    0xa0(%r14),%rax
   68f7a:	test   %rax,%rax
   68f7d:	je     6ae9c <_IO_vfwscanf+0x6ebc>
   68f83:	mov    (%rax),%rdx
   68f86:	cmp    0x8(%rax),%rdx
   68f8a:	jae    6ae9c <_IO_vfwscanf+0x6ebc>
   68f90:	lea    0x4(%rdx),%rsi
   68f94:	mov    (%rdx),%r13d
   68f97:	mov    %rsi,(%rax)
   68f9a:	cmp    $0xffffffff,%r13d
   68f9e:	je     68fb7 <_IO_vfwscanf+0x4fd7>
   68fa0:	addq   $0x1,-0x538(%rbp)
   68fa8:	jmpq   68d26 <_IO_vfwscanf+0x4d46>
   68fad:	mov    %rcx,%r15
   68fb0:	xor    %ecx,%ecx
   68fb2:	jmpq   68f2b <_IO_vfwscanf+0x4f4b>
   68fb7:	mov    0x356eaa(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   68fbe:	mov    %r13d,%r15d
   68fc1:	mov    -0x560(%rbp),%rbx
   68fc8:	mov    %rcx,-0x570(%rbp)
   68fcf:	mov    -0x558(%rbp),%r13d
   68fd6:	mov    %fs:(%rax),%eax
   68fd9:	mov    %eax,-0x514(%rbp)
   68fdf:	jmpq   68dd1 <_IO_vfwscanf+0x4df1>
   68fe4:	mov    0x356e7d(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   68feb:	mov    %rsi,-0x578(%rbp)
   68ff2:	mov    %fs:(%rax),%eax
   68ff5:	mov    %eax,-0x514(%rbp)
   68ffb:	jmpq   689b2 <_IO_vfwscanf+0x49d2>
   69000:	mov    %r14,%rdi
   69003:	mov    %rsi,-0x578(%rbp)
   6900a:	callq  73620 <__wuflow>
   6900f:	mov    -0x578(%rbp),%rsi
   69016:	mov    %eax,%r15d
   69019:	jmpq   68ae7 <_IO_vfwscanf+0x4b07>
   6901e:	movl   $0x0,-0x500(%rbp)
   69028:	mov    %rax,-0x4f8(%rbp)
   6902f:	jmpq   641fa <_IO_vfwscanf+0x21a>
   69034:	pxor   %xmm0,%xmm0
   69038:	movaps %xmm0,-0x450(%rbp)
   6903f:	jmpq   67bce <_IO_vfwscanf+0x3bee>
   69044:	mov    0x356e1d(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   6904b:	mov    %fs:(%rax),%eax
   6904e:	mov    %eax,-0x514(%rbp)
   69054:	jmpq   657c4 <_IO_vfwscanf+0x17e4>
   69059:	mov    -0x520(%rbp),%rax
   69060:	lea    0x4(%r8),%rsi
   69064:	addq   $0x1,-0x550(%rbp)
   6906c:	mov    %r8,-0x4f8(%rbp)
   69073:	mov    (%rax),%rdi
   69076:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   6907b:	test   %rax,%rax
   6907e:	je     6a4f7 <_IO_vfwscanf+0x6517>
   69084:	mov    -0x520(%rbp),%rdi
   6908b:	mov    -0x4f8(%rbp),%r8
   69092:	mov    %rax,(%rdi)
   69095:	add    %r8,%rax
   69098:	jmpq   6653e <_IO_vfwscanf+0x255e>
   6909d:	and    $0x2000,%r13d
   690a4:	mov    %r14,%r15
   690a7:	mov    -0x510(%rbp),%r14
   690ae:	jne    6ab27 <_IO_vfwscanf+0x6b47>
   690b4:	mov    -0x504(%rbp),%ebx
   690ba:	movl   $0x2,-0x508(%rbp)
   690c4:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   690c9:	mov    -0x580(%rbp),%rdi
   690d0:	mov    -0x588(%rbp),%r11
   690d7:	xor    %r9d,%r9d
   690da:	xor    %r8d,%r8d
   690dd:	mov    (%rdi),%rax
   690e0:	mov    %rax,(%r11)
   690e3:	mov    0x8(%rdi),%rsi
   690e7:	mov    %rsi,0x8(%r11)
   690eb:	mov    0x10(%rdi),%rdi
   690ef:	mov    %rdi,0x10(%r11)
   690f3:	mov    %eax,%edi
   690f5:	subl   $0x1,-0x530(%rbp)
   690fc:	je     6b6a0 <_IO_vfwscanf+0x76c0>
   69102:	cmp    $0x2f,%edi
   69105:	ja     6b691 <_IO_vfwscanf+0x76b1>
   6910b:	add    $0x8,%edi
   6910e:	mov    $0x1,%r8d
   69114:	jmp    690f5 <_IO_vfwscanf+0x5115>
   69116:	nopw   %cs:0x0(%rax,%rax,1)
   69120:	mov    0x356d41(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   69127:	mov    -0x514(%rbp),%esi
   6912d:	mov    %rbx,-0x500(%rbp)
   69134:	mov    -0x598(%rbp),%r13d
   6913b:	mov    -0x560(%rbp),%rbx
   69142:	mov    %esi,%fs:(%rax)
   69145:	jmpq   66741 <_IO_vfwscanf+0x2761>
   6914a:	mov    %r14,%r15
   6914d:	mov    -0x504(%rbp),%ebx
   69153:	mov    -0x510(%rbp),%r14
   6915a:	movl   $0x2,-0x508(%rbp)
   69164:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   69169:	mov    %r13,-0x570(%rbp)
   69170:	mov    -0x568(%rbp),%rbx
   69177:	mov    -0x560(%rbp),%r13d
   6917e:	jmpq   65bd6 <_IO_vfwscanf+0x1bf6>
   69183:	mov    %r14,%rdi
   69186:	callq  73620 <__wuflow>
   6918b:	mov    %eax,%r15d
   6918e:	jmpq   657b2 <_IO_vfwscanf+0x17d2>
   69193:	mov    -0x528(%rbp),%rdi
   6919a:	mov    $0x30,%esi
   6919f:	callq  63f80 <char_buffer_add_slow>
   691a4:	jmpq   6578b <_IO_vfwscanf+0x17ab>
   691a9:	mov    -0x580(%rbp),%rsi
   691b0:	mov    -0x588(%rbp),%r11
   691b7:	xor    %r9d,%r9d
   691ba:	xor    %r8d,%r8d
   691bd:	mov    (%rsi),%rax
   691c0:	mov    %rsi,%rdi
   691c3:	mov    %rax,(%r11)
   691c6:	mov    0x8(%rsi),%rsi
   691ca:	mov    %rsi,0x8(%r11)
   691ce:	mov    0x10(%rdi),%rdi
   691d2:	mov    %rdi,0x10(%r11)
   691d6:	mov    %eax,%edi
   691d8:	subl   $0x1,-0x530(%rbp)
   691df:	je     6992d <_IO_vfwscanf+0x594d>
   691e5:	cmp    $0x2f,%edi
   691e8:	ja     6991e <_IO_vfwscanf+0x593e>
   691ee:	add    $0x8,%edi
   691f1:	mov    $0x1,%r8d
   691f7:	jmp    691d8 <_IO_vfwscanf+0x51f8>
   691f9:	nopl   0x0(%rax)
   69200:	mov    -0x528(%rbp),%rdi
   69207:	mov    %r15d,%esi
   6920a:	callq  63f80 <char_buffer_add_slow>
   6920f:	movb   $0x1,-0x538(%rbp)
   69216:	jmpq   6586d <_IO_vfwscanf+0x188d>
   6921b:	mov    %r14,%r15
   6921e:	mov    -0x504(%rbp),%ebx
   69224:	mov    -0x510(%rbp),%r14
   6922b:	movl   $0x2,-0x508(%rbp)
   69235:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6923a:	mov    %r14,%r15
   6923d:	mov    -0x504(%rbp),%ebx
   69243:	mov    -0x510(%rbp),%r14
   6924a:	movl   $0x2,-0x508(%rbp)
   69254:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   69259:	mov    %r14,%r15
   6925c:	mov    -0x504(%rbp),%ebx
   69262:	mov    -0x510(%rbp),%r14
   69269:	movl   $0x2,-0x508(%rbp)
   69273:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   69278:	mov    %r14,%rdi
   6927b:	callq  73620 <__wuflow>
   69280:	mov    %eax,%r15d
   69283:	jmpq   67607 <_IO_vfwscanf+0x3627>
   69288:	mov    %r14,%r15
   6928b:	mov    -0x504(%rbp),%ebx
   69291:	mov    -0x510(%rbp),%r14
   69298:	movl   $0x2,-0x508(%rbp)
   692a2:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   692a7:	sub    $0x120,%rsp
   692ae:	mov    -0x510(%rbp),%rdi
   692b5:	mov    $0x1,%ecx
   692ba:	lea    0xf(%rsp),%rdx
   692bf:	and    $0xfffffffffffffff0,%rdx
   692c3:	mov    %rdi,0x8(%rdx)
   692c7:	mov    %rdx,-0x510(%rbp)
   692ce:	movq   $0x0,(%rdx)
   692d5:	mov    -0x510(%rbp),%rdi
   692dc:	xor    %edx,%edx
   692de:	jmpq   64fbf <_IO_vfwscanf+0xfdf>
   692e3:	and    $0x2000,%r13d
   692ea:	mov    %r14,%r15
   692ed:	mov    -0x510(%rbp),%r14
   692f4:	jne    6b124 <_IO_vfwscanf+0x7144>
   692fa:	mov    -0x504(%rbp),%ebx
   69300:	movl   $0x2,-0x508(%rbp)
   6930a:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6930f:	mov    0x356b52(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   69316:	mov    %fs:(%rax),%eax
   69319:	mov    %eax,-0x514(%rbp)
   6931f:	mov    $0x10,%r8d
   69325:	mov    $0xffffffff,%r15d
   6932b:	jmpq   65510 <_IO_vfwscanf+0x1530>
   69330:	mov    -0x528(%rbp),%rdi
   69337:	mov    %r15d,%esi
   6933a:	callq  63f80 <char_buffer_add_slow>
   6933f:	jmpq   67425 <_IO_vfwscanf+0x3445>
   69344:	mov    -0x580(%rbp),%rdi
   6934b:	mov    -0x588(%rbp),%rsi
   69352:	mov    (%rdi),%rax
   69355:	mov    %rax,(%rsi)
   69358:	mov    0x8(%rdi),%rdx
   6935c:	mov    %rdx,0x8(%rsi)
   69360:	mov    0x10(%rdi),%rcx
   69364:	xor    %edi,%edi
   69366:	mov    %rcx,0x10(%rsi)
   6936a:	mov    %eax,%ecx
   6936c:	xor    %esi,%esi
   6936e:	subl   $0x1,-0x530(%rbp)
   69375:	je     6976d <_IO_vfwscanf+0x578d>
   6937b:	cmp    $0x2f,%ecx
   6937e:	ja     6975f <_IO_vfwscanf+0x577f>
   69384:	add    $0x8,%ecx
   69387:	mov    $0x1,%edi
   6938c:	jmp    6936e <_IO_vfwscanf+0x538e>
   6938e:	xchg   %ax,%ax
   69390:	pxor   %xmm0,%xmm0
   69394:	movaps %xmm0,-0x450(%rbp)
   6939b:	jmpq   6538f <_IO_vfwscanf+0x13af>
   693a0:	mov    -0x520(%rbp),%rax
   693a7:	lea    0x4(%rcx),%rsi
   693ab:	addq   $0x1,-0x550(%rbp)
   693b3:	mov    (%rax),%rdi
   693b6:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   693bb:	test   %rax,%rax
   693be:	mov    -0x558(%rbp),%rcx
   693c5:	je     6b4ee <_IO_vfwscanf+0x750e>
   693cb:	mov    -0x520(%rbp),%rdi
   693d2:	lea    (%rax,%rcx,1),%r13
   693d6:	mov    %rax,(%rdi)
   693d9:	jmpq   64c2b <_IO_vfwscanf+0xc4b>
   693de:	mov    -0x588(%rbp),%rsi
   693e5:	mov    -0x570(%rbp),%rdi
   693ec:	mov    %rax,%rdx
   693ef:	callq  90920 <__GI___mempcpy>
   693f4:	lea    0x1(%rax),%rcx
   693f8:	movb   $0x0,(%rax)
   693fb:	mov    %rcx,-0x570(%rbp)
   69402:	jmpq   65c8f <_IO_vfwscanf+0x1caf>
   69407:	mov    -0x580(%rbp),%rsi
   6940e:	mov    -0x588(%rbp),%r11
   69415:	xor    %r9d,%r9d
   69418:	xor    %r8d,%r8d
   6941b:	mov    (%rsi),%rax
   6941e:	mov    %rsi,%rdi
   69421:	mov    %rax,(%r11)
   69424:	mov    0x8(%rsi),%rsi
   69428:	mov    %rsi,0x8(%r11)
   6942c:	mov    0x10(%rdi),%rdi
   69430:	mov    %rdi,0x10(%r11)
   69434:	mov    %eax,%edi
   69436:	subl   $0x1,-0x530(%rbp)
   6943d:	je     69700 <_IO_vfwscanf+0x5720>
   69443:	cmp    $0x2f,%edi
   69446:	ja     696f1 <_IO_vfwscanf+0x5711>
   6944c:	add    $0x8,%edi
   6944f:	mov    $0x1,%r8d
   69455:	jmp    69436 <_IO_vfwscanf+0x5456>
   69457:	nopw   0x0(%rax,%rax,1)
   69460:	mov    %rax,%rsi
   69463:	jmpq   68ab3 <_IO_vfwscanf+0x4ad3>
   69468:	mov    0x3569f9(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   6946f:	mov    -0x514(%rbp),%edi
   69475:	mov    %edi,%fs:(%rax)
   69478:	jmpq   6931f <_IO_vfwscanf+0x533f>
   6947d:	pxor   %xmm0,%xmm0
   69481:	movaps %xmm0,-0x450(%rbp)
   69488:	jmpq   6541c <_IO_vfwscanf+0x143c>
   6948d:	and    $0x2000,%r13d
   69494:	mov    %r14,%r15
   69497:	mov    -0x510(%rbp),%r14
   6949e:	jne    6aa6b <_IO_vfwscanf+0x6a8b>
   694a4:	mov    -0x504(%rbp),%ebx
   694aa:	movl   $0x2,-0x508(%rbp)
   694b4:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   694b9:	mov    %r14,%r15
   694bc:	mov    -0x504(%rbp),%ebx
   694c2:	mov    -0x510(%rbp),%r14
   694c9:	movl   $0x2,-0x508(%rbp)
   694d3:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   694d8:	mov    %r14,%r15
   694db:	mov    -0x504(%rbp),%ebx
   694e1:	mov    -0x510(%rbp),%r14
   694e8:	movl   $0x2,-0x508(%rbp)
   694f2:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   694f7:	mov    %r14,%rdi
   694fa:	callq  73620 <__wuflow>
   694ff:	mov    %eax,%r15d
   69502:	jmpq   674cd <_IO_vfwscanf+0x34ed>
   69507:	mov    %r14,%r15
   6950a:	mov    -0x504(%rbp),%ebx
   69510:	mov    -0x510(%rbp),%r14
   69517:	movl   $0x2,-0x508(%rbp)
   69521:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   69526:	mov    -0x528(%rbp),%rdi
   6952d:	mov    %r15d,%esi
   69530:	callq  63f80 <char_buffer_add_slow>
   69535:	jmpq   6749d <_IO_vfwscanf+0x34bd>
   6953a:	mov    %r14,%r15
   6953d:	mov    -0x504(%rbp),%ebx
   69543:	mov    -0x510(%rbp),%r14
   6954a:	movl   $0x2,-0x508(%rbp)
   69554:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   69559:	mov    -0x528(%rbp),%rdi
   69560:	xor    %esi,%esi
   69562:	callq  63f80 <char_buffer_add_slow>
   69567:	mov    -0x450(%rbp),%rax
   6956e:	jmpq   667b8 <_IO_vfwscanf+0x27d8>
   69573:	mov    0x3568ee(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   6957a:	mov    $0xffffffff,%ebx
   6957f:	mov    %r14,%r15
   69582:	movl   $0x0,-0x508(%rbp)
   6958c:	mov    -0x510(%rbp),%r14
   69593:	mov    %ebx,-0x504(%rbp)
   69599:	movl   $0xc,%fs:(%rax)
   695a0:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   695a5:	mov    -0x528(%rbp),%rdi
   695ac:	mov    %r15d,%esi
   695af:	callq  63f80 <char_buffer_add_slow>
   695b4:	movb   $0x0,-0x538(%rbp)
   695bb:	jmpq   6586d <_IO_vfwscanf+0x188d>
   695c0:	mov    %rbx,-0x500(%rbp)
   695c7:	mov    -0x598(%rbp),%r13d
   695ce:	mov    -0x560(%rbp),%rbx
   695d5:	jmpq   66741 <_IO_vfwscanf+0x2761>
   695da:	mov    -0x580(%rbp),%rdi
   695e1:	mov    -0x588(%rbp),%rsi
   695e8:	mov    (%rdi),%rax
   695eb:	mov    %rax,(%rsi)
   695ee:	mov    0x8(%rdi),%rdx
   695f2:	mov    %rdx,0x8(%rsi)
   695f6:	mov    0x10(%rdi),%rcx
   695fa:	xor    %edi,%edi
   695fc:	mov    %rcx,0x10(%rsi)
   69600:	mov    %eax,%ecx
   69602:	xor    %esi,%esi
   69604:	subl   $0x1,-0x530(%rbp)
   6960b:	je     697b3 <_IO_vfwscanf+0x57d3>
   69611:	cmp    $0x2f,%ecx
   69614:	ja     697a5 <_IO_vfwscanf+0x57c5>
   6961a:	add    $0x8,%ecx
   6961d:	mov    $0x1,%edi
   69622:	jmp    69604 <_IO_vfwscanf+0x5624>
   69624:	nopl   0x0(%rax)
   69628:	sub    $0x120,%rsp
   6962f:	mov    -0x510(%rbp),%rdi
   69636:	mov    $0x1,%ecx
   6963b:	lea    0xf(%rsp),%rdx
   69640:	and    $0xfffffffffffffff0,%rdx
   69644:	movq   $0x0,(%rdx)
   6964b:	mov    %rdi,0x8(%rdx)
   6964f:	mov    %rdx,-0x510(%rbp)
   69656:	xor    %edx,%edx
   69658:	jmpq   65a1d <_IO_vfwscanf+0x1a3d>
   6965d:	and    $0x2000,%r13d
   69664:	mov    %r14,%r15
   69667:	mov    -0x510(%rbp),%r14
   6966e:	jne    698bd <_IO_vfwscanf+0x58dd>
   69674:	mov    -0x504(%rbp),%ebx
   6967a:	movl   $0x2,-0x508(%rbp)
   69684:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   69689:	mov    -0x538(%rbp),%rbx
   69690:	mov    -0x558(%rbp),%r13d
   69697:	mov    %r12,-0x570(%rbp)
   6969e:	jmpq   664b5 <_IO_vfwscanf+0x24d5>
   696a3:	mov    %r14,%r15
   696a6:	mov    -0x504(%rbp),%ebx
   696ac:	mov    -0x510(%rbp),%r14
   696b3:	movl   $0x2,-0x508(%rbp)
   696bd:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   696c2:	mov    %r14,%rdi
   696c5:	callq  73620 <__wuflow>
   696ca:	mov    %eax,%r15d
   696cd:	jmpq   67455 <_IO_vfwscanf+0x3475>
   696d2:	mov    %r14,%r15
   696d5:	mov    -0x504(%rbp),%ebx
   696db:	mov    -0x510(%rbp),%r14
   696e2:	movl   $0x2,-0x508(%rbp)
   696ec:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   696f1:	add    $0x8,%rsi
   696f5:	mov    $0x1,%r9d
   696fb:	jmpq   69436 <_IO_vfwscanf+0x5456>
   69700:	test   %r8b,%r8b
   69703:	je     6970d <_IO_vfwscanf+0x572d>
   69705:	mov    %edi,-0x4a0(%rbp)
   6970b:	mov    %edi,%eax
   6970d:	test   %r9b,%r9b
   69710:	je     69719 <_IO_vfwscanf+0x5739>
   69712:	mov    %rsi,-0x498(%rbp)
   69719:	cmp    $0x2f,%eax
   6971c:	ja     6983f <_IO_vfwscanf+0x585f>
   69722:	mov    %eax,%esi
   69724:	add    -0x490(%rbp),%rsi
   6972b:	add    $0x8,%eax
   6972e:	mov    %eax,-0x4a0(%rbp)
   69734:	mov    (%rsi),%rax
   69737:	jmpq   67eec <_IO_vfwscanf+0x3f0c>
   6973c:	mov    0x356725(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   69743:	mov    -0x450(%rbp),%rdx
   6974a:	mov    %fs:(%rax),%eax
   6974d:	mov    %eax,-0x514(%rbp)
   69753:	mov    -0x448(%rbp),%rax
   6975a:	jmpq   6679e <_IO_vfwscanf+0x27be>
   6975f:	add    $0x8,%rdx
   69763:	mov    $0x1,%esi
   69768:	jmpq   6936e <_IO_vfwscanf+0x538e>
   6976d:	test   %dil,%dil
   69770:	je     6977a <_IO_vfwscanf+0x579a>
   69772:	mov    %ecx,-0x4a0(%rbp)
   69778:	mov    %ecx,%eax
   6977a:	test   %sil,%sil
   6977d:	je     69786 <_IO_vfwscanf+0x57a6>
   6977f:	mov    %rdx,-0x498(%rbp)
   69786:	cmp    $0x2f,%eax
   69789:	ja     697eb <_IO_vfwscanf+0x580b>
   6978b:	mov    %eax,%edx
   6978d:	add    -0x490(%rbp),%rdx
   69794:	add    $0x8,%eax
   69797:	mov    %eax,-0x4a0(%rbp)
   6979d:	mov    (%rdx),%rax
   697a0:	jmpq   681c8 <_IO_vfwscanf+0x41e8>
   697a5:	add    $0x8,%rdx
   697a9:	mov    $0x1,%esi
   697ae:	jmpq   69604 <_IO_vfwscanf+0x5624>
   697b3:	test   %dil,%dil
   697b6:	je     697c0 <_IO_vfwscanf+0x57e0>
   697b8:	mov    %ecx,-0x4a0(%rbp)
   697be:	mov    %ecx,%eax
   697c0:	test   %sil,%sil
   697c3:	je     697cc <_IO_vfwscanf+0x57ec>
   697c5:	mov    %rdx,-0x498(%rbp)
   697cc:	cmp    $0x2f,%eax
   697cf:	ja     697ff <_IO_vfwscanf+0x581f>
   697d1:	mov    %eax,%edx
   697d3:	add    -0x490(%rbp),%rdx
   697da:	add    $0x8,%eax
   697dd:	mov    %eax,-0x4a0(%rbp)
   697e3:	mov    (%rdx),%rax
   697e6:	jmpq   68874 <_IO_vfwscanf+0x4894>
   697eb:	mov    -0x498(%rbp),%rdx
   697f2:	lea    0x8(%rdx),%rax
   697f6:	mov    %rax,-0x498(%rbp)
   697fd:	jmp    6979d <_IO_vfwscanf+0x57bd>
   697ff:	mov    -0x498(%rbp),%rdx
   69806:	lea    0x8(%rdx),%rax
   6980a:	mov    %rax,-0x498(%rbp)
   69811:	jmp    697e3 <_IO_vfwscanf+0x5803>
   69813:	add    $0x8,%rcx
   69817:	mov    $0x1,%edi
   6981c:	jmpq   66316 <_IO_vfwscanf+0x2336>
   69821:	add    $0x8,%rcx
   69825:	mov    $0x1,%edi
   6982a:	jmpq   68207 <_IO_vfwscanf+0x4227>
   6982f:	mov    %r14,%rdi
   69832:	callq  73620 <__wuflow>
   69837:	mov    %eax,%r15d
   6983a:	jmpq   67705 <_IO_vfwscanf+0x3725>
   6983f:	mov    -0x498(%rbp),%rsi
   69846:	lea    0x8(%rsi),%rax
   6984a:	mov    %rax,-0x498(%rbp)
   69851:	jmpq   69734 <_IO_vfwscanf+0x5754>
   69856:	mov    -0x4d0(%rbp),%rax
   6985d:	lea    0x8(%rax),%rdx
   69861:	mov    %rdx,-0x4d0(%rbp)
   69868:	jmpq   68871 <_IO_vfwscanf+0x4891>
   6986d:	or     $0xffffffff,%ebx
   69870:	movl   $0x0,-0x508(%rbp)
   6987a:	mov    %ebx,-0x504(%rbp)
   69880:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   69885:	test   %r8b,%r8b
   69888:	je     69892 <_IO_vfwscanf+0x58b2>
   6988a:	mov    %esi,-0x4a0(%rbp)
   69890:	mov    %esi,%edx
   69892:	test   %dil,%dil
   69895:	je     6989e <_IO_vfwscanf+0x58be>
   69897:	mov    %rcx,-0x498(%rbp)
   6989e:	cmp    $0x2f,%edx
   698a1:	ja     698d5 <_IO_vfwscanf+0x58f5>
   698a3:	mov    %edx,%ecx
   698a5:	add    -0x490(%rbp),%rcx
   698ac:	add    $0x8,%edx
   698af:	mov    %edx,-0x4a0(%rbp)
   698b5:	mov    (%rcx),%rdx
   698b8:	jmpq   66ad7 <_IO_vfwscanf+0x2af7>
   698bd:	or     $0xffffffff,%ebx
   698c0:	movl   $0x0,-0x508(%rbp)
   698ca:	mov    %ebx,-0x504(%rbp)
   698d0:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   698d5:	mov    -0x498(%rbp),%rcx
   698dc:	lea    0x8(%rcx),%rdx
   698e0:	mov    %rdx,-0x498(%rbp)
   698e7:	jmp    698b5 <_IO_vfwscanf+0x58d5>
   698e9:	mov    -0x528(%rbp),%rdi
   698f0:	mov    %r15d,%esi
   698f3:	callq  63f80 <char_buffer_add_slow>
   698f8:	jmpq   6586d <_IO_vfwscanf+0x188d>
   698fd:	fstp   %st(0)
   698ff:	mov    %r14,%r15
   69902:	mov    -0x504(%rbp),%ebx
   69908:	mov    -0x510(%rbp),%r14
   6990f:	movl   $0x2,-0x508(%rbp)
   69919:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6991e:	add    $0x8,%rsi
   69922:	mov    $0x1,%r9d
   69928:	jmpq   691d8 <_IO_vfwscanf+0x51f8>
   6992d:	test   %r8b,%r8b
   69930:	je     6993a <_IO_vfwscanf+0x595a>
   69932:	mov    %edi,-0x4a0(%rbp)
   69938:	mov    %edi,%eax
   6993a:	test   %r9b,%r9b
   6993d:	je     69946 <_IO_vfwscanf+0x5966>
   6993f:	mov    %rsi,-0x498(%rbp)
   69946:	cmp    $0x2f,%eax
   69949:	ja     69d37 <_IO_vfwscanf+0x5d57>
   6994f:	mov    %eax,%esi
   69951:	add    -0x490(%rbp),%rsi
   69958:	add    $0x8,%eax
   6995b:	mov    %eax,-0x4a0(%rbp)
   69961:	mov    (%rsi),%rax
   69964:	jmpq   66846 <_IO_vfwscanf+0x2866>
   69969:	add    $0x8,%rcx
   6996d:	mov    $0x1,%edi
   69972:	jmpq   682ce <_IO_vfwscanf+0x42ee>
   69977:	mov    -0x4d0(%rbp),%rax
   6997e:	lea    0x8(%rax),%rsi
   69982:	mov    %rsi,-0x4d0(%rbp)
   69989:	jmpq   66843 <_IO_vfwscanf+0x2863>
   6998e:	add    $0x8,%rcx
   69992:	mov    $0x1,%edi
   69997:	jmpq   6736a <_IO_vfwscanf+0x338a>
   6999c:	cmpl   $0x0,-0x5a0(%rbp)
   699a3:	jne    6675e <_IO_vfwscanf+0x277e>
   699a9:	mov    %rdx,%rax
   699ac:	sub    -0x440(%rbp),%rax
   699b3:	sar    $0x2,%rax
   699b7:	test   %rax,%rax
   699ba:	je     699c9 <_IO_vfwscanf+0x59e9>
   699bc:	testb  $0x1,-0x538(%rbp)
   699c3:	je     6675e <_IO_vfwscanf+0x277e>
   699c9:	lea    0x12007d(%rip),%rdi        # 189a4d <null+0xf>
   699d0:	callq  10b870 <wctrans>
   699d5:	test   %rax,%rax
   699d8:	mov    %rax,-0x560(%rbp)
   699df:	je     69c74 <_IO_vfwscanf+0x5c94>
   699e5:	cmp    $0xffffffff,%r15d
   699e9:	je     69d76 <_IO_vfwscanf+0x5d96>
   699ef:	mov    0xa0(%r14),%rax
   699f6:	test   %rax,%rax
   699f9:	je     69c44 <_IO_vfwscanf+0x5c64>
   699ff:	mov    (%rax),%rdx
   69a02:	cmp    0x8(%rax),%rdx
   69a06:	jae    69c44 <_IO_vfwscanf+0x5c64>
   69a0c:	lea    0x4(%rdx),%rcx
   69a10:	mov    (%rdx),%r15d
   69a13:	mov    %rcx,(%rax)
   69a16:	cmp    $0xffffffff,%r15d
   69a1a:	je     69c2f <_IO_vfwscanf+0x5c4f>
   69a20:	addq   $0x1,-0x500(%rbp)
   69a28:	mov    -0x560(%rbp),%rsi
   69a2f:	mov    $0x2e,%edi
   69a34:	callq  10b900 <__towctrans>
   69a39:	mov    -0x450(%rbp),%rdx
   69a40:	mov    %eax,-0x474(%rbp)
   69a46:	mov    %rdx,%rcx
   69a49:	sub    -0x440(%rbp),%rcx
   69a50:	sar    $0x2,%rcx
   69a54:	test   %rcx,%rcx
   69a57:	je     69aa0 <_IO_vfwscanf+0x5ac0>
   69a59:	cmp    %eax,-0x548(%rbp)
   69a5f:	jne    69a67 <_IO_vfwscanf+0x5a87>
   69a61:	sub    $0x1,%rcx
   69a65:	je     69aa0 <_IO_vfwscanf+0x5ac0>
   69a67:	test   %rdx,%rdx
   69a6a:	jne    6675e <_IO_vfwscanf+0x277e>
   69a70:	mov    0x3563f1(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   69a77:	or     $0xffffffff,%ebx
   69a7a:	mov    %r14,%r15
   69a7d:	movl   $0x0,-0x508(%rbp)
   69a87:	mov    -0x510(%rbp),%r14
   69a8e:	mov    %ebx,-0x504(%rbp)
   69a94:	movl   $0xc,%fs:(%rax)
   69a9b:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   69aa0:	cmpl   $0x0,-0x5a8(%rbp)
   69aa7:	mov    -0x588(%rbp),%rdx
   69aae:	mov    $0x30,%ecx
   69ab3:	setne  -0x598(%rbp)
   69aba:	mov    -0x560(%rbp),%rsi
   69ac1:	mov    %ecx,%edi
   69ac3:	mov    %rdx,-0x5b0(%rbp)
   69aca:	mov    %ecx,-0x5a8(%rbp)
   69ad0:	callq  10b900 <__towctrans>
   69ad5:	mov    -0x5a8(%rbp),%ecx
   69adb:	mov    -0x5b0(%rbp),%rdx
   69ae2:	add    $0x1,%ecx
   69ae5:	mov    %eax,(%rdx)
   69ae7:	add    $0x4,%rdx
   69aeb:	cmp    $0x3a,%ecx
   69aee:	jne    69aba <_IO_vfwscanf+0x5ada>
   69af0:	mov    -0x560(%rbp),%rsi
   69af7:	mov    $0x2c,%edi
   69afc:	callq  10b900 <__towctrans>
   69b01:	test   %eax,%eax
   69b03:	mov    %eax,-0x478(%rbp)
   69b09:	mov    %rbx,-0x560(%rbp)
   69b10:	setne  %al
   69b13:	and    -0x598(%rbp),%eax
   69b19:	movzbl -0x538(%rbp),%ebx
   69b20:	mov    %al,-0x598(%rbp)
   69b26:	mov    %r15d,%eax
   69b29:	mov    %r13d,%r15d
   69b2c:	mov    %eax,%r13d
   69b2f:	mov    -0x450(%rbp),%rdx
   69b36:	test   %rdx,%rdx
   69b39:	je     69ff8 <_IO_vfwscanf+0x6018>
   69b3f:	cmpb   $0x0,-0x558(%rbp)
   69b46:	je     69f92 <_IO_vfwscanf+0x5fb2>
   69b4c:	mov    -0x4f8(%rbp),%eax
   69b52:	cmp    -0x4(%rdx),%eax
   69b55:	je     69f65 <_IO_vfwscanf+0x5f85>
   69b5b:	cmp    -0x4a0(%rbp),%r13d
   69b62:	je     69f5e <_IO_vfwscanf+0x5f7e>
   69b68:	cmp    -0x49c(%rbp),%r13d
   69b6f:	je     69f54 <_IO_vfwscanf+0x5f74>
   69b75:	cmp    %r13d,-0x498(%rbp)
   69b7c:	je     69f4a <_IO_vfwscanf+0x5f6a>
   69b82:	cmp    -0x494(%rbp),%r13d
   69b89:	je     69f40 <_IO_vfwscanf+0x5f60>
   69b8f:	cmp    -0x490(%rbp),%r13d
   69b96:	je     69f36 <_IO_vfwscanf+0x5f56>
   69b9c:	cmp    -0x48c(%rbp),%r13d
   69ba3:	je     69f2c <_IO_vfwscanf+0x5f4c>
   69ba9:	cmp    -0x488(%rbp),%r13d
   69bb0:	je     69f22 <_IO_vfwscanf+0x5f42>
   69bb6:	cmp    -0x484(%rbp),%r13d
   69bbd:	je     69f18 <_IO_vfwscanf+0x5f38>
   69bc3:	cmp    -0x480(%rbp),%r13d
   69bca:	je     69f0e <_IO_vfwscanf+0x5f2e>
   69bd0:	cmp    -0x47c(%rbp),%r13d
   69bd7:	je     69e4d <_IO_vfwscanf+0x5e6d>
   69bdd:	cmp    -0x478(%rbp),%r13d
   69be4:	je     69e14 <_IO_vfwscanf+0x5e34>
   69bea:	cmp    -0x474(%rbp),%r13d
   69bf1:	je     69d8b <_IO_vfwscanf+0x5dab>
   69bf7:	mov    %r13d,%eax
   69bfa:	mov    -0x560(%rbp),%rbx
   69c01:	mov    %r15d,%r13d
   69c04:	cmp    $0xffffffff,%eax
   69c07:	mov    %eax,%r15d
   69c0a:	je     69a67 <_IO_vfwscanf+0x5a87>
   69c10:	mov    %r15d,%esi
   69c13:	mov    %r14,%rdi
   69c16:	subq   $0x1,-0x500(%rbp)
   69c1e:	callq  74430 <_IO_sputbackwc>
   69c23:	mov    -0x450(%rbp),%rdx
   69c2a:	jmpq   69a67 <_IO_vfwscanf+0x5a87>
   69c2f:	mov    0x356232(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   69c36:	mov    %fs:(%rax),%eax
   69c39:	mov    %eax,-0x514(%rbp)
   69c3f:	jmpq   69a28 <_IO_vfwscanf+0x5a48>
   69c44:	mov    %r14,%rdi
   69c47:	callq  73620 <__wuflow>
   69c4c:	mov    %eax,%r15d
   69c4f:	jmpq   69a16 <_IO_vfwscanf+0x5a36>
   69c54:	mov    %r13d,%eax
   69c57:	mov    %r15d,%r13d
   69c5a:	mov    -0x560(%rbp),%rbx
   69c61:	mov    %eax,%r15d
   69c64:	mov    0x3561fd(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   69c6b:	mov    %fs:(%rax),%eax
   69c6e:	mov    %eax,-0x514(%rbp)
   69c74:	mov    -0x450(%rbp),%rdx
   69c7b:	jmpq   69a67 <_IO_vfwscanf+0x5a87>
   69c80:	mov    0x3561e1(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   69c87:	or     $0xffffffff,%ebx
   69c8a:	mov    %r14,%r15
   69c8d:	movl   $0x0,-0x508(%rbp)
   69c97:	mov    -0x510(%rbp),%r14
   69c9e:	mov    %ebx,-0x504(%rbp)
   69ca4:	movl   $0xc,%fs:(%rax)
   69cab:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   69cb0:	add    $0x8,%rdx
   69cb4:	mov    $0x1,%edi
   69cb9:	jmpq   683e1 <_IO_vfwscanf+0x4401>
   69cbe:	test   %sil,%sil
   69cc1:	je     69ccb <_IO_vfwscanf+0x5ceb>
   69cc3:	mov    %ecx,-0x4a0(%rbp)
   69cc9:	mov    %ecx,%eax
   69ccb:	test   %dil,%dil
   69cce:	je     69cd7 <_IO_vfwscanf+0x5cf7>
   69cd0:	mov    %rdx,-0x498(%rbp)
   69cd7:	cmp    $0x2f,%eax
   69cda:	ja     69d4e <_IO_vfwscanf+0x5d6e>
   69cdc:	mov    %eax,%edx
   69cde:	add    -0x490(%rbp),%rdx
   69ce5:	add    $0x8,%eax
   69ce8:	mov    %eax,-0x4a0(%rbp)
   69cee:	mov    (%rdx),%rax
   69cf1:	mov    %rax,-0x520(%rbp)
   69cf8:	jmpq   651c3 <_IO_vfwscanf+0x11e3>
   69cfd:	test   %r8b,%r8b
   69d00:	je     69d0a <_IO_vfwscanf+0x5d2a>
   69d02:	mov    %esi,-0x4a0(%rbp)
   69d08:	mov    %esi,%edx
   69d0a:	test   %dil,%dil
   69d0d:	je     69d16 <_IO_vfwscanf+0x5d36>
   69d0f:	mov    %rcx,-0x498(%rbp)
   69d16:	cmp    $0x2f,%edx
   69d19:	ja     69d62 <_IO_vfwscanf+0x5d82>
   69d1b:	mov    %edx,%ecx
   69d1d:	add    -0x490(%rbp),%rcx
   69d24:	add    $0x8,%edx
   69d27:	mov    %edx,-0x4a0(%rbp)
   69d2d:	mov    (%rcx),%rdx
   69d30:	mov    %al,(%rdx)
   69d32:	jmpq   6563d <_IO_vfwscanf+0x165d>
   69d37:	mov    -0x498(%rbp),%rsi
   69d3e:	lea    0x8(%rsi),%rax
   69d42:	mov    %rax,-0x498(%rbp)
   69d49:	jmpq   69961 <_IO_vfwscanf+0x5981>
   69d4e:	mov    -0x498(%rbp),%rdx
   69d55:	lea    0x8(%rdx),%rax
   69d59:	mov    %rax,-0x498(%rbp)
   69d60:	jmp    69cee <_IO_vfwscanf+0x5d0e>
   69d62:	mov    -0x498(%rbp),%rcx
   69d69:	lea    0x8(%rcx),%rdx
   69d6d:	mov    %rdx,-0x498(%rbp)
   69d74:	jmp    69d2d <_IO_vfwscanf+0x5d4d>
   69d76:	mov    0x3560eb(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   69d7d:	mov    -0x514(%rbp),%edi
   69d83:	mov    %edi,%fs:(%rax)
   69d86:	jmpq   69a28 <_IO_vfwscanf+0x5a48>
   69d8b:	test   %bl,%bl
   69d8d:	jne    69bf7 <_IO_vfwscanf+0x5c17>
   69d93:	cmp    -0x448(%rbp),%rdx
   69d9a:	je     69ef2 <_IO_vfwscanf+0x5f12>
   69da0:	lea    0x4(%rdx),%rax
   69da4:	mov    $0x1,%ebx
   69da9:	mov    %rax,-0x450(%rbp)
   69db0:	mov    -0x548(%rbp),%eax
   69db6:	mov    %eax,(%rdx)
   69db8:	test   %r12d,%r12d
   69dbb:	je     69ed6 <_IO_vfwscanf+0x5ef6>
   69dc1:	cmp    $0xffffffff,%r13d
   69dc5:	je     69eaa <_IO_vfwscanf+0x5eca>
   69dcb:	mov    0xa0(%r14),%rax
   69dd2:	test   %rax,%rax
   69dd5:	je     69e9a <_IO_vfwscanf+0x5eba>
   69ddb:	mov    (%rax),%rdx
   69dde:	cmp    0x8(%rax),%rdx
   69de2:	jae    69e9a <_IO_vfwscanf+0x5eba>
   69de8:	lea    0x4(%rdx),%rcx
   69dec:	mov    (%rdx),%r13d
   69def:	mov    %rcx,(%rax)
   69df2:	cmp    $0xffffffff,%r13d
   69df6:	je     69c54 <_IO_vfwscanf+0x5c74>
   69dfc:	xor    %eax,%eax
   69dfe:	addq   $0x1,-0x500(%rbp)
   69e06:	test   %r12d,%r12d
   69e09:	setg   %al
   69e0c:	sub    %eax,%r12d
   69e0f:	jmpq   69b2f <_IO_vfwscanf+0x5b4f>
   69e14:	and    $0x1,%bl
   69e17:	jne    69bf7 <_IO_vfwscanf+0x5c17>
   69e1d:	cmpb   $0x0,-0x598(%rbp)
   69e24:	je     69bf7 <_IO_vfwscanf+0x5c17>
   69e2a:	cmp    -0x448(%rbp),%rdx
   69e31:	je     69e70 <_IO_vfwscanf+0x5e90>
   69e33:	lea    0x4(%rdx),%rax
   69e37:	xor    %ebx,%ebx
   69e39:	mov    %rax,-0x450(%rbp)
   69e40:	mov    -0x518(%rbp),%eax
   69e46:	mov    %eax,(%rdx)
   69e48:	jmpq   69db8 <_IO_vfwscanf+0x5dd8>
   69e4d:	mov    $0x9,%eax
   69e52:	cmp    -0x448(%rbp),%rdx
   69e59:	lea    0x30(%rax),%esi
   69e5c:	je     69e89 <_IO_vfwscanf+0x5ea9>
   69e5e:	lea    0x4(%rdx),%rax
   69e62:	mov    %rax,-0x450(%rbp)
   69e69:	mov    %esi,(%rdx)
   69e6b:	jmpq   69db8 <_IO_vfwscanf+0x5dd8>
   69e70:	mov    -0x518(%rbp),%esi
   69e76:	mov    -0x528(%rbp),%rdi
   69e7d:	xor    %ebx,%ebx
   69e7f:	callq  63f80 <char_buffer_add_slow>
   69e84:	jmpq   69db8 <_IO_vfwscanf+0x5dd8>
   69e89:	mov    -0x528(%rbp),%rdi
   69e90:	callq  63f80 <char_buffer_add_slow>
   69e95:	jmpq   69db8 <_IO_vfwscanf+0x5dd8>
   69e9a:	mov    %r14,%rdi
   69e9d:	callq  73620 <__wuflow>
   69ea2:	mov    %eax,%r13d
   69ea5:	jmpq   69df2 <_IO_vfwscanf+0x5e12>
   69eaa:	mov    %r13d,%eax
   69ead:	mov    -0x514(%rbp),%ecx
   69eb3:	mov    %r15d,%r13d
   69eb6:	mov    %eax,%r15d
   69eb9:	mov    0x355fa8(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   69ec0:	mov    -0x560(%rbp),%rbx
   69ec7:	mov    -0x450(%rbp),%rdx
   69ece:	mov    %ecx,%fs:(%rax)
   69ed1:	jmpq   69a67 <_IO_vfwscanf+0x5a87>
   69ed6:	mov    %r13d,%eax
   69ed9:	mov    -0x560(%rbp),%rbx
   69ee0:	mov    %r15d,%r13d
   69ee3:	mov    -0x450(%rbp),%rdx
   69eea:	mov    %eax,%r15d
   69eed:	jmpq   69a67 <_IO_vfwscanf+0x5a87>
   69ef2:	mov    -0x548(%rbp),%esi
   69ef8:	mov    -0x528(%rbp),%rdi
   69eff:	mov    $0x1,%ebx
   69f04:	callq  63f80 <char_buffer_add_slow>
   69f09:	jmpq   69db8 <_IO_vfwscanf+0x5dd8>
   69f0e:	mov    $0x8,%eax
   69f13:	jmpq   69e52 <_IO_vfwscanf+0x5e72>
   69f18:	mov    $0x7,%eax
   69f1d:	jmpq   69e52 <_IO_vfwscanf+0x5e72>
   69f22:	mov    $0x6,%eax
   69f27:	jmpq   69e52 <_IO_vfwscanf+0x5e72>
   69f2c:	mov    $0x5,%eax
   69f31:	jmpq   69e52 <_IO_vfwscanf+0x5e72>
   69f36:	mov    $0x4,%eax
   69f3b:	jmpq   69e52 <_IO_vfwscanf+0x5e72>
   69f40:	mov    $0x3,%eax
   69f45:	jmpq   69e52 <_IO_vfwscanf+0x5e72>
   69f4a:	mov    $0x2,%eax
   69f4f:	jmpq   69e52 <_IO_vfwscanf+0x5e72>
   69f54:	mov    $0x1,%eax
   69f59:	jmpq   69e52 <_IO_vfwscanf+0x5e72>
   69f5e:	xor    %eax,%eax
   69f60:	jmpq   69e52 <_IO_vfwscanf+0x5e72>
   69f65:	lea    -0x2b(%r13),%eax
   69f69:	and    $0xfffffffd,%eax
   69f6c:	jne    69b5b <_IO_vfwscanf+0x5b7b>
   69f72:	cmp    -0x448(%rbp),%rdx
   69f79:	je     6a028 <_IO_vfwscanf+0x6048>
   69f7f:	lea    0x4(%rdx),%rax
   69f83:	mov    %rax,-0x450(%rbp)
   69f8a:	mov    %r13d,(%rdx)
   69f8d:	jmpq   69db8 <_IO_vfwscanf+0x5dd8>
   69f92:	mov    %rdx,%rax
   69f95:	sub    -0x440(%rbp),%rax
   69f9c:	sar    $0x2,%rax
   69fa0:	test   %rax,%rax
   69fa3:	je     69b5b <_IO_vfwscanf+0x5b7b>
   69fa9:	mov    %r13d,%edi
   69fac:	mov    %rdx,-0x538(%rbp)
   69fb3:	callq  10b6c0 <towlower>
   69fb8:	cmp    %eax,-0x4f8(%rbp)
   69fbe:	mov    -0x538(%rbp),%rdx
   69fc5:	jne    69b5b <_IO_vfwscanf+0x5b7b>
   69fcb:	cmp    -0x448(%rbp),%rdx
   69fd2:	je     6a03c <_IO_vfwscanf+0x605c>
   69fd4:	lea    0x4(%rdx),%rax
   69fd8:	movb   $0x1,-0x558(%rbp)
   69fdf:	mov    $0x1,%ebx
   69fe4:	mov    %rax,-0x450(%rbp)
   69feb:	mov    -0x4f8(%rbp),%eax
   69ff1:	mov    %eax,(%rdx)
   69ff3:	jmpq   69db8 <_IO_vfwscanf+0x5dd8>
   69ff8:	mov    0x355e69(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   69fff:	or     $0xffffffff,%ebx
   6a002:	mov    %r14,%r15
   6a005:	movl   $0x0,-0x508(%rbp)
   6a00f:	mov    -0x510(%rbp),%r14
   6a016:	mov    %ebx,-0x504(%rbp)
   6a01c:	movl   $0xc,%fs:(%rax)
   6a023:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a028:	mov    -0x528(%rbp),%rdi
   6a02f:	mov    %r13d,%esi
   6a032:	callq  63f80 <char_buffer_add_slow>
   6a037:	jmpq   69db8 <_IO_vfwscanf+0x5dd8>
   6a03c:	mov    -0x4f8(%rbp),%esi
   6a042:	mov    -0x528(%rbp),%rdi
   6a049:	mov    $0x1,%ebx
   6a04e:	callq  63f80 <char_buffer_add_slow>
   6a053:	movb   $0x1,-0x558(%rbp)
   6a05a:	jmpq   69db8 <_IO_vfwscanf+0x5dd8>
   6a05f:	cmp    $0xffffffff,%r15d
   6a063:	mov    %rbx,%rax
   6a066:	mov    %rbx,-0x500(%rbp)
   6a06d:	mov    -0x598(%rbp),%r13d
   6a074:	mov    -0x560(%rbp),%rbx
   6a07b:	je     66751 <_IO_vfwscanf+0x2771>
   6a081:	sub    $0x1,%rax
   6a085:	mov    %r15d,%esi
   6a088:	mov    %r14,%rdi
   6a08b:	mov    %rax,-0x500(%rbp)
   6a092:	callq  74430 <_IO_sputbackwc>
   6a097:	jmpq   66741 <_IO_vfwscanf+0x2761>
   6a09c:	add    $0x8,%rcx
   6a0a0:	mov    $0x1,%edi
   6a0a5:	jmpq   68788 <_IO_vfwscanf+0x47a8>
   6a0aa:	add    $0x8,%rdx
   6a0ae:	mov    $0x1,%esi
   6a0b3:	jmpq   677e1 <_IO_vfwscanf+0x3801>
   6a0b8:	test   %dil,%dil
   6a0bb:	je     6a0c5 <_IO_vfwscanf+0x60e5>
   6a0bd:	mov    %ecx,-0x4a0(%rbp)
   6a0c3:	mov    %ecx,%eax
   6a0c5:	test   %sil,%sil
   6a0c8:	je     6a0d1 <_IO_vfwscanf+0x60f1>
   6a0ca:	mov    %rdx,-0x498(%rbp)
   6a0d1:	cmp    $0x2f,%eax
   6a0d4:	ja     6a152 <_IO_vfwscanf+0x6172>
   6a0d6:	mov    %eax,%edx
   6a0d8:	add    -0x490(%rbp),%rdx
   6a0df:	add    $0x8,%eax
   6a0e2:	mov    %eax,-0x4a0(%rbp)
   6a0e8:	mov    (%rdx),%rax
   6a0eb:	mov    %rax,-0x520(%rbp)
   6a0f2:	jmpq   64ae1 <_IO_vfwscanf+0xb01>
   6a0f7:	add    $0x8,%rcx
   6a0fb:	mov    $0x1,%edi
   6a100:	jmpq   6722e <_IO_vfwscanf+0x324e>
   6a105:	mov    %r14,%r15
   6a108:	mov    -0x504(%rbp),%ebx
   6a10e:	mov    -0x510(%rbp),%r14
   6a115:	movl   $0x2,-0x508(%rbp)
   6a11f:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a124:	mov    -0x4d0(%rbp),%rax
   6a12b:	lea    0x8(%rax),%rdx
   6a12f:	mov    %rdx,-0x4d0(%rbp)
   6a136:	jmpq   680c0 <_IO_vfwscanf+0x40e0>
   6a13b:	mov    -0x4d0(%rbp),%rax
   6a142:	lea    0x8(%rax),%rdx
   6a146:	mov    %rdx,-0x4d0(%rbp)
   6a14d:	jmpq   681c5 <_IO_vfwscanf+0x41e5>
   6a152:	mov    -0x498(%rbp),%rdx
   6a159:	lea    0x8(%rdx),%rax
   6a15d:	mov    %rax,-0x498(%rbp)
   6a164:	jmp    6a0e8 <_IO_vfwscanf+0x6108>
   6a166:	mov    %r14,%r15
   6a169:	mov    -0x504(%rbp),%ebx
   6a16f:	mov    -0x510(%rbp),%r14
   6a176:	movl   $0x2,-0x508(%rbp)
   6a180:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a185:	mov    -0x4d0(%rbp),%rax
   6a18c:	lea    0x8(%rax),%rdx
   6a190:	mov    %rdx,-0x4d0(%rbp)
   6a197:	jmpq   659c7 <_IO_vfwscanf+0x19e7>
   6a19c:	add    $0x8,%rdx
   6a1a0:	mov    $0x1,%edi
   6a1a5:	jmpq   68440 <_IO_vfwscanf+0x4460>
   6a1aa:	test   %sil,%sil
   6a1ad:	je     6a1b7 <_IO_vfwscanf+0x61d7>
   6a1af:	mov    %ecx,-0x4a0(%rbp)
   6a1b5:	mov    %ecx,%eax
   6a1b7:	test   %dil,%dil
   6a1ba:	je     6a1c3 <_IO_vfwscanf+0x61e3>
   6a1bc:	mov    %rdx,-0x498(%rbp)
   6a1c3:	cmp    $0x2f,%eax
   6a1c6:	ja     6a269 <_IO_vfwscanf+0x6289>
   6a1cc:	mov    %eax,%edx
   6a1ce:	add    -0x490(%rbp),%rdx
   6a1d5:	add    $0x8,%eax
   6a1d8:	mov    %eax,-0x4a0(%rbp)
   6a1de:	mov    (%rdx),%rax
   6a1e1:	mov    %rax,-0x570(%rbp)
   6a1e8:	jmpq   67588 <_IO_vfwscanf+0x35a8>
   6a1ed:	add    $0x8,%rdx
   6a1f1:	mov    $0x1,%edi
   6a1f6:	jmpq   68b65 <_IO_vfwscanf+0x4b85>
   6a1fb:	mov    -0x4d0(%rbp),%rax
   6a202:	lea    0x8(%rax),%rdx
   6a206:	mov    %rdx,-0x4d0(%rbp)
   6a20d:	jmpq   6848f <_IO_vfwscanf+0x44af>
   6a212:	or     $0xffffffff,%ebx
   6a215:	movl   $0x0,-0x508(%rbp)
   6a21f:	mov    %ebx,-0x504(%rbp)
   6a225:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a22a:	test   %sil,%sil
   6a22d:	je     6a237 <_IO_vfwscanf+0x6257>
   6a22f:	mov    %ecx,-0x4a0(%rbp)
   6a235:	mov    %ecx,%eax
   6a237:	test   %dil,%dil
   6a23a:	je     6a243 <_IO_vfwscanf+0x6263>
   6a23c:	mov    %rdx,-0x498(%rbp)
   6a243:	cmp    $0x2f,%eax
   6a246:	ja     6a280 <_IO_vfwscanf+0x62a0>
   6a248:	mov    %eax,%edx
   6a24a:	add    -0x490(%rbp),%rdx
   6a251:	add    $0x8,%eax
   6a254:	mov    %eax,-0x4a0(%rbp)
   6a25a:	mov    (%rdx),%rax
   6a25d:	mov    %rax,-0x570(%rbp)
   6a264:	jmpq   680ca <_IO_vfwscanf+0x40ea>
   6a269:	mov    -0x498(%rbp),%rdx
   6a270:	lea    0x8(%rdx),%rax
   6a274:	mov    %rax,-0x498(%rbp)
   6a27b:	jmpq   6a1de <_IO_vfwscanf+0x61fe>
   6a280:	mov    -0x498(%rbp),%rdx
   6a287:	lea    0x8(%rdx),%rax
   6a28b:	mov    %rax,-0x498(%rbp)
   6a292:	jmp    6a25a <_IO_vfwscanf+0x627a>
   6a294:	mov    -0x528(%rbp),%rdi
   6a29b:	mov    %r15d,%esi
   6a29e:	callq  63f80 <char_buffer_add_slow>
   6a2a3:	jmpq   675d7 <_IO_vfwscanf+0x35f7>
   6a2a8:	xor    %eax,%eax
   6a2aa:	test   %r12d,%r12d
   6a2ad:	setg   %al
   6a2b0:	sub    %eax,%r12d
   6a2b3:	mov    -0x450(%rbp),%rax
   6a2ba:	cmp    -0x448(%rbp),%rax
   6a2c1:	je     6a701 <_IO_vfwscanf+0x6721>
   6a2c7:	lea    0x4(%rax),%rdx
   6a2cb:	mov    %rdx,-0x450(%rbp)
   6a2d2:	mov    %r15d,(%rax)
   6a2d5:	test   %r12d,%r12d
   6a2d8:	je     6a6e2 <_IO_vfwscanf+0x6702>
   6a2de:	mov    0xa0(%r14),%rax
   6a2e5:	test   %rax,%rax
   6a2e8:	je     6a6d2 <_IO_vfwscanf+0x66f2>
   6a2ee:	mov    (%rax),%rdx
   6a2f1:	cmp    0x8(%rax),%rdx
   6a2f5:	jae    6a6d2 <_IO_vfwscanf+0x66f2>
   6a2fb:	lea    0x4(%rdx),%rcx
   6a2ff:	mov    (%rdx),%r15d
   6a302:	mov    %rcx,(%rax)
   6a305:	cmp    $0xffffffff,%r15d
   6a309:	je     6a6b3 <_IO_vfwscanf+0x66d3>
   6a30f:	mov    %r15d,%edi
   6a312:	callq  10b6c0 <towlower>
   6a317:	cmp    $0x6e,%eax
   6a31a:	jne    6a5cd <_IO_vfwscanf+0x65ed>
   6a320:	xor    %eax,%eax
   6a322:	test   %r12d,%r12d
   6a325:	setg   %al
   6a328:	sub    %eax,%r12d
   6a32b:	mov    -0x450(%rbp),%rax
   6a332:	cmp    -0x448(%rbp),%rax
   6a339:	je     6a5b9 <_IO_vfwscanf+0x65d9>
   6a33f:	lea    0x4(%rax),%rdx
   6a343:	mov    %rdx,-0x450(%rbp)
   6a34a:	mov    %r15d,(%rax)
   6a34d:	test   %r12d,%r12d
   6a350:	je     6a59a <_IO_vfwscanf+0x65ba>
   6a356:	mov    0xa0(%r14),%rax
   6a35d:	test   %rax,%rax
   6a360:	je     6a58a <_IO_vfwscanf+0x65aa>
   6a366:	mov    (%rax),%rdx
   6a369:	cmp    0x8(%rax),%rdx
   6a36d:	jae    6a58a <_IO_vfwscanf+0x65aa>
   6a373:	lea    0x4(%rdx),%rcx
   6a377:	mov    (%rdx),%r15d
   6a37a:	mov    %rcx,(%rax)
   6a37d:	cmp    $0xffffffff,%r15d
   6a381:	je     6a56b <_IO_vfwscanf+0x658b>
   6a387:	mov    %r15d,%edi
   6a38a:	callq  10b6c0 <towlower>
   6a38f:	cmp    $0x69,%eax
   6a392:	jne    6a54c <_IO_vfwscanf+0x656c>
   6a398:	xor    %eax,%eax
   6a39a:	test   %r12d,%r12d
   6a39d:	setg   %al
   6a3a0:	sub    %eax,%r12d
   6a3a3:	mov    -0x450(%rbp),%rax
   6a3aa:	cmp    -0x448(%rbp),%rax
   6a3b1:	je     6a538 <_IO_vfwscanf+0x6558>
   6a3b7:	lea    0x4(%rax),%rdx
   6a3bb:	mov    %rdx,-0x450(%rbp)
   6a3c2:	mov    %r15d,(%rax)
   6a3c5:	test   %r12d,%r12d
   6a3c8:	je     6a519 <_IO_vfwscanf+0x6539>
   6a3ce:	mov    0xa0(%r14),%rax
   6a3d5:	test   %rax,%rax
   6a3d8:	je     6a63e <_IO_vfwscanf+0x665e>
   6a3de:	mov    (%rax),%rdx
   6a3e1:	cmp    0x8(%rax),%rdx
   6a3e5:	jae    6a63e <_IO_vfwscanf+0x665e>
   6a3eb:	lea    0x4(%rdx),%rcx
   6a3ef:	mov    (%rdx),%r15d
   6a3f2:	mov    %rcx,(%rax)
   6a3f5:	cmp    $0xffffffff,%r15d
   6a3f9:	je     6a61f <_IO_vfwscanf+0x663f>
   6a3ff:	mov    %r15d,%edi
   6a402:	callq  10b6c0 <towlower>
   6a407:	cmp    $0x74,%eax
   6a40a:	jne    6a600 <_IO_vfwscanf+0x6620>
   6a410:	xor    %eax,%eax
   6a412:	test   %r12d,%r12d
   6a415:	setg   %al
   6a418:	sub    %eax,%r12d
   6a41b:	mov    -0x450(%rbp),%rax
   6a422:	cmp    -0x448(%rbp),%rax
   6a429:	je     6a5ec <_IO_vfwscanf+0x660c>
   6a42f:	lea    0x4(%rax),%rdx
   6a433:	mov    %rdx,-0x450(%rbp)
   6a43a:	mov    %r15d,(%rax)
   6a43d:	test   %r12d,%r12d
   6a440:	je     6a65e <_IO_vfwscanf+0x667e>
   6a446:	mov    0xa0(%r14),%rax
   6a44d:	test   %rax,%rax
   6a450:	je     6a64e <_IO_vfwscanf+0x666e>
   6a456:	mov    (%rax),%rdx
   6a459:	cmp    0x8(%rax),%rdx
   6a45d:	jae    6a64e <_IO_vfwscanf+0x666e>
   6a463:	lea    0x4(%rdx),%rcx
   6a467:	mov    (%rdx),%r15d
   6a46a:	mov    %rcx,(%rax)
   6a46d:	cmp    $0xffffffff,%r15d
   6a471:	je     6a67d <_IO_vfwscanf+0x669d>
   6a477:	mov    -0x500(%rbp),%rax
   6a47e:	mov    %r15d,%edi
   6a481:	add    $0x7,%rax
   6a485:	mov    %rax,-0x4f8(%rbp)
   6a48c:	callq  10b6c0 <towlower>
   6a491:	cmp    $0x79,%eax
   6a494:	je     674fa <_IO_vfwscanf+0x351a>
   6a49a:	mov    %r14,%r15
   6a49d:	mov    -0x504(%rbp),%ebx
   6a4a3:	mov    -0x510(%rbp),%r14
   6a4aa:	movl   $0x2,-0x508(%rbp)
   6a4b4:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a4b9:	test   %r8b,%r8b
   6a4bc:	je     6a4c6 <_IO_vfwscanf+0x64e6>
   6a4be:	mov    %esi,-0x4a0(%rbp)
   6a4c4:	mov    %esi,%edx
   6a4c6:	test   %dil,%dil
   6a4c9:	je     6a4d2 <_IO_vfwscanf+0x64f2>
   6a4cb:	mov    %rcx,-0x498(%rbp)
   6a4d2:	cmp    $0x2f,%edx
   6a4d5:	ja     6a69c <_IO_vfwscanf+0x66bc>
   6a4db:	mov    %edx,%ecx
   6a4dd:	add    -0x490(%rbp),%rcx
   6a4e4:	add    $0x8,%edx
   6a4e7:	mov    %edx,-0x4a0(%rbp)
   6a4ed:	mov    (%rcx),%rdx
   6a4f0:	mov    %eax,(%rdx)
   6a4f2:	jmpq   6563d <_IO_vfwscanf+0x165d>
   6a4f7:	or     $0xffffffff,%ebx
   6a4fa:	mov    -0x510(%rbp),%r14
   6a501:	mov    %r13,%r15
   6a504:	movl   $0x0,-0x508(%rbp)
   6a50e:	mov    %ebx,-0x504(%rbp)
   6a514:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a519:	mov    %r14,%r15
   6a51c:	mov    -0x504(%rbp),%ebx
   6a522:	mov    -0x510(%rbp),%r14
   6a529:	movl   $0x2,-0x508(%rbp)
   6a533:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a538:	mov    -0x528(%rbp),%rdi
   6a53f:	mov    %r15d,%esi
   6a542:	callq  63f80 <char_buffer_add_slow>
   6a547:	jmpq   6a3c5 <_IO_vfwscanf+0x63e5>
   6a54c:	mov    %r14,%r15
   6a54f:	mov    -0x504(%rbp),%ebx
   6a555:	mov    -0x510(%rbp),%r14
   6a55c:	movl   $0x2,-0x508(%rbp)
   6a566:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a56b:	mov    %r14,%r15
   6a56e:	mov    -0x504(%rbp),%ebx
   6a574:	mov    -0x510(%rbp),%r14
   6a57b:	movl   $0x2,-0x508(%rbp)
   6a585:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a58a:	mov    %r14,%rdi
   6a58d:	callq  73620 <__wuflow>
   6a592:	mov    %eax,%r15d
   6a595:	jmpq   6a37d <_IO_vfwscanf+0x639d>
   6a59a:	mov    %r14,%r15
   6a59d:	mov    -0x504(%rbp),%ebx
   6a5a3:	mov    -0x510(%rbp),%r14
   6a5aa:	movl   $0x2,-0x508(%rbp)
   6a5b4:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a5b9:	mov    -0x528(%rbp),%rdi
   6a5c0:	mov    %r15d,%esi
   6a5c3:	callq  63f80 <char_buffer_add_slow>
   6a5c8:	jmpq   6a34d <_IO_vfwscanf+0x636d>
   6a5cd:	mov    %r14,%r15
   6a5d0:	mov    -0x504(%rbp),%ebx
   6a5d6:	mov    -0x510(%rbp),%r14
   6a5dd:	movl   $0x2,-0x508(%rbp)
   6a5e7:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a5ec:	mov    -0x528(%rbp),%rdi
   6a5f3:	mov    %r15d,%esi
   6a5f6:	callq  63f80 <char_buffer_add_slow>
   6a5fb:	jmpq   6a43d <_IO_vfwscanf+0x645d>
   6a600:	mov    %r14,%r15
   6a603:	mov    -0x504(%rbp),%ebx
   6a609:	mov    -0x510(%rbp),%r14
   6a610:	movl   $0x2,-0x508(%rbp)
   6a61a:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a61f:	mov    %r14,%r15
   6a622:	mov    -0x504(%rbp),%ebx
   6a628:	mov    -0x510(%rbp),%r14
   6a62f:	movl   $0x2,-0x508(%rbp)
   6a639:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a63e:	mov    %r14,%rdi
   6a641:	callq  73620 <__wuflow>
   6a646:	mov    %eax,%r15d
   6a649:	jmpq   6a3f5 <_IO_vfwscanf+0x6415>
   6a64e:	mov    %r14,%rdi
   6a651:	callq  73620 <__wuflow>
   6a656:	mov    %eax,%r15d
   6a659:	jmpq   6a46d <_IO_vfwscanf+0x648d>
   6a65e:	mov    %r14,%r15
   6a661:	mov    -0x504(%rbp),%ebx
   6a667:	mov    -0x510(%rbp),%r14
   6a66e:	movl   $0x2,-0x508(%rbp)
   6a678:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a67d:	mov    %r14,%r15
   6a680:	mov    -0x504(%rbp),%ebx
   6a686:	mov    -0x510(%rbp),%r14
   6a68d:	movl   $0x2,-0x508(%rbp)
   6a697:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a69c:	mov    -0x498(%rbp),%rcx
   6a6a3:	lea    0x8(%rcx),%rdx
   6a6a7:	mov    %rdx,-0x498(%rbp)
   6a6ae:	jmpq   6a4ed <_IO_vfwscanf+0x650d>
   6a6b3:	mov    %r14,%r15
   6a6b6:	mov    -0x504(%rbp),%ebx
   6a6bc:	mov    -0x510(%rbp),%r14
   6a6c3:	movl   $0x2,-0x508(%rbp)
   6a6cd:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a6d2:	mov    %r14,%rdi
   6a6d5:	callq  73620 <__wuflow>
   6a6da:	mov    %eax,%r15d
   6a6dd:	jmpq   6a305 <_IO_vfwscanf+0x6325>
   6a6e2:	mov    %r14,%r15
   6a6e5:	mov    -0x504(%rbp),%ebx
   6a6eb:	mov    -0x510(%rbp),%r14
   6a6f2:	movl   $0x2,-0x508(%rbp)
   6a6fc:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a701:	mov    -0x528(%rbp),%rdi
   6a708:	mov    %r15d,%esi
   6a70b:	callq  63f80 <char_buffer_add_slow>
   6a710:	jmpq   6a2d5 <_IO_vfwscanf+0x62f5>
   6a715:	mov    %r14,%r15
   6a718:	mov    -0x504(%rbp),%ebx
   6a71e:	mov    -0x510(%rbp),%r14
   6a725:	movl   $0x2,-0x508(%rbp)
   6a72f:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a734:	mov    -0x4d0(%rbp),%rdx
   6a73b:	lea    0x8(%rdx),%rcx
   6a73f:	mov    %rcx,-0x4d0(%rbp)
   6a746:	jmpq   66ad4 <_IO_vfwscanf+0x2af4>
   6a74b:	mov    %r14,%r15
   6a74e:	mov    -0x504(%rbp),%ebx
   6a754:	mov    -0x510(%rbp),%r14
   6a75b:	movl   $0x2,-0x508(%rbp)
   6a765:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a76a:	mov    -0x4d0(%rbp),%rax
   6a771:	lea    0x8(%rax),%rdx
   6a775:	mov    %rdx,-0x4d0(%rbp)
   6a77c:	jmpq   651b9 <_IO_vfwscanf+0x11d9>
   6a781:	mov    -0x570(%rbp),%r12
   6a788:	mov    %rcx,-0x530(%rbp)
   6a78f:	sub    %rdi,%r12
   6a792:	lea    0x1(%rcx,%r12,1),%rdx
   6a797:	mov    %rdx,%rsi
   6a79a:	mov    %rdx,-0x4f8(%rbp)
   6a7a1:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   6a7a6:	test   %rax,%rax
   6a7a9:	mov    -0x4f8(%rbp),%rdx
   6a7b0:	mov    -0x530(%rbp),%rcx
   6a7b7:	je     6a811 <_IO_vfwscanf+0x6831>
   6a7b9:	mov    -0x520(%rbp),%rsi
   6a7c0:	mov    %rdx,-0x550(%rbp)
   6a7c7:	mov    %rax,(%rsi)
   6a7ca:	add    %r12,%rax
   6a7cd:	mov    %rax,-0x570(%rbp)
   6a7d4:	jmpq   68e49 <_IO_vfwscanf+0x4e69>
   6a7d9:	mov    0x355688(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   6a7e0:	mov    -0x514(%rbp),%esi
   6a7e6:	mov    %r14,%r15
   6a7e9:	mov    -0x510(%rbp),%r14
   6a7f0:	mov    %esi,%fs:(%rax)
   6a7f3:	mov    -0x504(%rbp),%eax
   6a7f9:	test   %eax,%eax
   6a7fb:	mov    %eax,%ebx
   6a7fd:	jne    64590 <_IO_vfwscanf+0x5b0>
   6a803:	or     $0xffffffff,%ebx
   6a806:	mov    %ebx,-0x504(%rbp)
   6a80c:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a811:	and    $0x2000,%r13d
   6a818:	mov    %r14,%r15
   6a81b:	mov    -0x510(%rbp),%r14
   6a822:	jne    6a890 <_IO_vfwscanf+0x68b0>
   6a824:	mov    -0x520(%rbp),%rax
   6a82b:	addl   $0x1,-0x504(%rbp)
   6a832:	movq   $0x0,-0x520(%rbp)
   6a83d:	movl   $0x2,-0x500(%rbp)
   6a847:	mov    (%rax),%rax
   6a84a:	movb   $0x0,(%rax,%r12,1)
   6a84f:	mov    -0x500(%rbp),%eax
   6a855:	mov    -0x504(%rbp),%ebx
   6a85b:	mov    %eax,-0x508(%rbp)
   6a861:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a866:	mov    %r14,%r15
   6a869:	mov    -0x510(%rbp),%r14
   6a870:	jmp    6a7f3 <_IO_vfwscanf+0x6813>
   6a872:	mov    %r14,%rdi
   6a875:	mov    %r8,-0x538(%rbp)
   6a87c:	callq  73620 <__wuflow>
   6a881:	mov    -0x538(%rbp),%r8
   6a888:	mov    %eax,%r15d
   6a88b:	jmpq   68cc0 <_IO_vfwscanf+0x4ce0>
   6a890:	movl   $0xffffffff,-0x504(%rbp)
   6a89a:	jmp    6a84f <_IO_vfwscanf+0x686f>
   6a89c:	mov    -0x588(%rbp),%rsi
   6a8a3:	mov    -0x570(%rbp),%rdi
   6a8aa:	mov    %rax,%rdx
   6a8ad:	callq  90920 <__GI___mempcpy>
   6a8b2:	lea    0x1(%rax),%rcx
   6a8b6:	movb   $0x0,(%rax)
   6a8b9:	mov    %rcx,-0x570(%rbp)
   6a8c0:	jmpq   68e99 <_IO_vfwscanf+0x4eb9>
   6a8c5:	mov    -0x570(%rbp),%rdi
   6a8cc:	mov    -0x588(%rbp),%rsi
   6a8d3:	xor    %edx,%edx
   6a8d5:	callq  90920 <__GI___mempcpy>
   6a8da:	cmpl   $0x0,-0x568(%rbp)
   6a8e1:	lea    0x1(%rax),%rdi
   6a8e5:	movb   $0x0,(%rax)
   6a8e8:	mov    %rdi,-0x570(%rbp)
   6a8ef:	je     68e99 <_IO_vfwscanf+0x4eb9>
   6a8f5:	jmpq   68e6d <_IO_vfwscanf+0x4e8d>
   6a8fa:	mov    %r14,%r15
   6a8fd:	mov    -0x504(%rbp),%ebx
   6a903:	mov    -0x510(%rbp),%r14
   6a90a:	movl   $0x2,-0x508(%rbp)
   6a914:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a919:	mov    %rsi,%rax
   6a91c:	sub    %rdi,%rcx
   6a91f:	add    %rsi,%rax
   6a922:	mov    %rcx,%r15
   6a925:	mov    %rax,%rsi
   6a928:	mov    %rax,-0x550(%rbp)
   6a92f:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   6a934:	test   %rax,%rax
   6a937:	je     6ab3f <_IO_vfwscanf+0x6b5f>
   6a93d:	mov    -0x520(%rbp),%rcx
   6a944:	mov    %rax,(%rcx)
   6a947:	lea    (%rax,%r15,1),%rcx
   6a94b:	jmpq   68f28 <_IO_vfwscanf+0x4f48>
   6a950:	mov    %r14,%r15
   6a953:	mov    -0x504(%rbp),%ebx
   6a959:	mov    -0x510(%rbp),%r14
   6a960:	movl   $0x2,-0x508(%rbp)
   6a96a:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a96f:	add    $0x8,%rdx
   6a973:	mov    $0x1,%edi
   6a978:	jmpq   68259 <_IO_vfwscanf+0x4279>
   6a97d:	test   %sil,%sil
   6a980:	je     6a98a <_IO_vfwscanf+0x69aa>
   6a982:	mov    %ecx,-0x4a0(%rbp)
   6a988:	mov    %ecx,%eax
   6a98a:	test   %dil,%dil
   6a98d:	je     6a996 <_IO_vfwscanf+0x69b6>
   6a98f:	mov    %rdx,-0x498(%rbp)
   6a996:	cmp    $0x2f,%eax
   6a999:	ja     6a9ef <_IO_vfwscanf+0x6a0f>
   6a99b:	mov    %eax,%edx
   6a99d:	add    -0x490(%rbp),%rdx
   6a9a4:	add    $0x8,%eax
   6a9a7:	mov    %eax,-0x4a0(%rbp)
   6a9ad:	mov    (%rdx),%rax
   6a9b0:	mov    %rax,-0x520(%rbp)
   6a9b7:	jmpq   66a0b <_IO_vfwscanf+0x2a2b>
   6a9bc:	mov    %r14,%r15
   6a9bf:	mov    -0x504(%rbp),%ebx
   6a9c5:	mov    -0x510(%rbp),%r14
   6a9cc:	movl   $0x2,-0x508(%rbp)
   6a9d6:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6a9db:	mov    -0x528(%rbp),%rdi
   6a9e2:	mov    %r15d,%esi
   6a9e5:	callq  63f80 <char_buffer_add_slow>
   6a9ea:	jmpq   6764f <_IO_vfwscanf+0x366f>
   6a9ef:	mov    -0x498(%rbp),%rdx
   6a9f6:	lea    0x8(%rdx),%rax
   6a9fa:	mov    %rax,-0x498(%rbp)
   6aa01:	jmp    6a9ad <_IO_vfwscanf+0x69cd>
   6aa03:	add    $0x8,%rcx
   6aa07:	mov    $0x1,%edi
   6aa0c:	jmpq   66b2a <_IO_vfwscanf+0x2b4a>
   6aa11:	mov    %r14,%rdi
   6aa14:	callq  73620 <__wuflow>
   6aa19:	mov    %eax,%r15d
   6aa1c:	jmpq   6767f <_IO_vfwscanf+0x369f>
   6aa21:	mov    -0x528(%rbp),%rdi
   6aa28:	mov    %r15d,%esi
   6aa2b:	callq  63f80 <char_buffer_add_slow>
   6aa30:	jmpq   676d9 <_IO_vfwscanf+0x36f9>
   6aa35:	mov    %r14,%r15
   6aa38:	mov    -0x504(%rbp),%ebx
   6aa3e:	mov    -0x510(%rbp),%r14
   6aa45:	movl   $0x2,-0x508(%rbp)
   6aa4f:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6aa54:	mov    -0x4d0(%rbp),%rdx
   6aa5b:	lea    0x8(%rdx),%rcx
   6aa5f:	mov    %rcx,-0x4d0(%rbp)
   6aa66:	jmpq   6728e <_IO_vfwscanf+0x32ae>
   6aa6b:	or     $0xffffffff,%ebx
   6aa6e:	movl   $0x0,-0x508(%rbp)
   6aa78:	mov    %ebx,-0x504(%rbp)
   6aa7e:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6aa83:	test   %r8b,%r8b
   6aa86:	je     6aa90 <_IO_vfwscanf+0x6ab0>
   6aa88:	mov    %esi,-0x4a0(%rbp)
   6aa8e:	mov    %esi,%edx
   6aa90:	test   %dil,%dil
   6aa93:	je     6aa9c <_IO_vfwscanf+0x6abc>
   6aa95:	mov    %rcx,-0x498(%rbp)
   6aa9c:	cmp    $0x2f,%edx
   6aa9f:	ja     6aadd <_IO_vfwscanf+0x6afd>
   6aaa1:	mov    %edx,%ecx
   6aaa3:	add    -0x490(%rbp),%rcx
   6aaaa:	add    $0x8,%edx
   6aaad:	mov    %edx,-0x4a0(%rbp)
   6aab3:	mov    (%rcx),%rdx
   6aab6:	jmpq   6563a <_IO_vfwscanf+0x165a>
   6aabb:	mov    -0x528(%rbp),%rdi
   6aac2:	mov    %r15d,%esi
   6aac5:	callq  63f80 <char_buffer_add_slow>
   6aaca:	mov    -0x450(%rbp),%rdx
   6aad1:	mov    -0x448(%rbp),%rax
   6aad8:	jmpq   6679e <_IO_vfwscanf+0x27be>
   6aadd:	mov    -0x498(%rbp),%rcx
   6aae4:	lea    0x8(%rcx),%rdx
   6aae8:	mov    %rdx,-0x498(%rbp)
   6aaef:	jmp    6aab3 <_IO_vfwscanf+0x6ad3>
   6aaf1:	mov    %r14,%r15
   6aaf4:	mov    -0x504(%rbp),%ebx
   6aafa:	mov    -0x510(%rbp),%r14
   6ab01:	movl   $0x2,-0x508(%rbp)
   6ab0b:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6ab10:	mov    -0x4d0(%rbp),%rax
   6ab17:	lea    0x8(%rax),%rdx
   6ab1b:	mov    %rdx,-0x4d0(%rbp)
   6ab22:	jmpq   66a01 <_IO_vfwscanf+0x2a21>
   6ab27:	or     $0xffffffff,%ebx
   6ab2a:	movl   $0x0,-0x508(%rbp)
   6ab34:	mov    %ebx,-0x504(%rbp)
   6ab3a:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6ab3f:	mov    0x35526a(%rip),%rax        # 3bfdb0 <_DYNAMIC+0x250>
   6ab46:	mov    %fs:(%rax),%rax
   6ab4a:	mov    (%rax),%rax
   6ab4d:	mov    0xa8(%rax),%esi
   6ab53:	mov    -0x520(%rbp),%rax
   6ab5a:	mov    (%rax),%rdi
   6ab5d:	add    %r15,%rsi
   6ab60:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   6ab65:	test   %rax,%rax
   6ab68:	je     6b725 <_IO_vfwscanf+0x7745>
   6ab6e:	mov    -0x520(%rbp),%rdi
   6ab75:	lea    (%rax,%r15,1),%rcx
   6ab79:	mov    %rax,(%rdi)
   6ab7c:	mov    0x35522d(%rip),%rax        # 3bfdb0 <_DYNAMIC+0x250>
   6ab83:	mov    %fs:(%rax),%rax
   6ab87:	mov    (%rax),%rax
   6ab8a:	mov    0xa8(%rax),%eax
   6ab90:	add    %r15,%rax
   6ab93:	mov    %rax,-0x550(%rbp)
   6ab9a:	jmpq   68f28 <_IO_vfwscanf+0x4f48>
   6ab9f:	mov    %r14,%rdi
   6aba2:	callq  73620 <__wuflow>
   6aba7:	mov    %eax,%r15d
   6abaa:	jmpq   671df <_IO_vfwscanf+0x31ff>
   6abaf:	mov    -0x4d0(%rbp),%rax
   6abb6:	lea    0x8(%rax),%rdx
   6abba:	mov    %rdx,-0x4d0(%rbp)
   6abc1:	jmpq   652ff <_IO_vfwscanf+0x131f>
   6abc6:	mov    %rsi,-0x578(%rbp)
   6abcd:	jmpq   689b2 <_IO_vfwscanf+0x49d2>
   6abd2:	lea    0x2(%rcx),%eax
   6abd5:	movslq %ecx,%rsi
   6abd8:	xor    %r8d,%r8d
   6abdb:	mov    %r12d,-0x568(%rbp)
   6abe2:	mov    %r14,-0x598(%rbp)
   6abe9:	mov    %r8,%r12
   6abec:	cltq   
   6abee:	mov    %r13d,%r14d
   6abf1:	mov    %rsi,-0x538(%rbp)
   6abf8:	shl    $0x2,%rax
   6abfc:	mov    %rbx,%r13
   6abff:	lea    -0x8(%rax),%rdi
   6ac03:	lea    -0x4(%rax),%r10
   6ac07:	add    $0x1e,%rax
   6ac0b:	shr    $0x4,%rax
   6ac0f:	shl    $0x4,%rax
   6ac13:	mov    %rdi,-0x500(%rbp)
   6ac1a:	mov    %rax,-0x558(%rbp)
   6ac21:	mov    0x355188(%rip),%rax        # 3bfdb0 <_DYNAMIC+0x250>
   6ac28:	sub    -0x558(%rbp),%rsp
   6ac2f:	mov    %ecx,-0x5b0(%rbp)
   6ac35:	mov    %r10,-0x5a8(%rbp)
   6ac3c:	mov    %fs:(%rax),%rax
   6ac40:	lea    0xf(%rsp),%rbx
   6ac45:	mov    (%rax),%rdx
   6ac48:	lea    0x1f(%r12),%eax
   6ac4d:	and    $0xfffffffffffffff0,%rbx
   6ac51:	mov    %rbx,%rdi
   6ac54:	cltq   
   6ac56:	mov    0x40(%rdx,%rax,8),%rsi
   6ac5b:	mov    -0x538(%rbp),%rdx
   6ac62:	callq  abf00 <wmemcpy>
   6ac67:	mov    -0x500(%rbp),%rax
   6ac6e:	mov    -0x560(%rbp),%rsi
   6ac75:	lea    0x30(%r12),%edi
   6ac7a:	lea    (%rbx,%rax,1),%rdx
   6ac7e:	mov    %rdx,-0x5a0(%rbp)
   6ac85:	callq  10b900 <__towctrans>
   6ac8a:	mov    -0x5a0(%rbp),%rdx
   6ac91:	mov    -0x5a8(%rbp),%r10
   6ac98:	mov    -0x5b0(%rbp),%ecx
   6ac9e:	mov    %eax,(%rdx)
   6aca0:	mov    -0x588(%rbp),%rax
   6aca7:	movl   $0x0,(%rbx,%r10,1)
   6acaf:	mov    %rbx,(%rax,%r12,8)
   6acb3:	add    $0x1,%r12
   6acb7:	cmp    $0xa,%r12
   6acbb:	jne    6ac21 <_IO_vfwscanf+0x6c41>
   6acc1:	mov    %r13,%rbx
   6acc4:	mov    -0x568(%rbp),%r12d
   6accb:	mov    %r14d,%r13d
   6acce:	mov    %ecx,-0x500(%rbp)
   6acd4:	mov    -0x598(%rbp),%r14
   6acdb:	jmpq   6796a <_IO_vfwscanf+0x398a>
   6ace0:	add    $0x8,%rcx
   6ace4:	mov    $0x1,%edi
   6ace9:	jmpq   6864b <_IO_vfwscanf+0x466b>
   6acee:	mov    %r14,%r15
   6acf1:	mov    -0x504(%rbp),%ebx
   6acf7:	mov    -0x510(%rbp),%r14
   6acfe:	movl   $0x2,-0x508(%rbp)
   6ad08:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6ad0d:	mov    -0x4d0(%rbp),%rax
   6ad14:	lea    0x8(%rax),%rdx
   6ad18:	mov    %rdx,-0x4d0(%rbp)
   6ad1f:	jmpq   64f66 <_IO_vfwscanf+0xf86>
   6ad24:	add    $0x8,%rdx
   6ad28:	mov    $0x1,%esi
   6ad2d:	jmpq   685aa <_IO_vfwscanf+0x45ca>
   6ad32:	test   %dil,%dil
   6ad35:	je     6ad3f <_IO_vfwscanf+0x6d5f>
   6ad37:	mov    %ecx,-0x4a0(%rbp)
   6ad3d:	mov    %ecx,%eax
   6ad3f:	test   %sil,%sil
   6ad42:	je     6ad4b <_IO_vfwscanf+0x6d6b>
   6ad44:	mov    %rdx,-0x498(%rbp)
   6ad4b:	cmp    $0x2f,%eax
   6ad4e:	ja     6ae71 <_IO_vfwscanf+0x6e91>
   6ad54:	mov    %eax,%edx
   6ad56:	add    -0x490(%rbp),%rdx
   6ad5d:	add    $0x8,%eax
   6ad60:	mov    %eax,-0x4a0(%rbp)
   6ad66:	mov    (%rdx),%rax
   6ad69:	jmpq   6714e <_IO_vfwscanf+0x316e>
   6ad6e:	mov    -0x4d0(%rbp),%rax
   6ad75:	lea    0x8(%rax),%rsi
   6ad79:	mov    %rsi,-0x4d0(%rbp)
   6ad80:	jmpq   6807a <_IO_vfwscanf+0x409a>
   6ad85:	add    $0x8,%rdx
   6ad89:	mov    $0x1,%esi
   6ad8e:	jmpq   68501 <_IO_vfwscanf+0x4521>
   6ad93:	test   %dil,%dil
   6ad96:	je     6ada0 <_IO_vfwscanf+0x6dc0>
   6ad98:	mov    %ecx,-0x4a0(%rbp)
   6ad9e:	mov    %ecx,%eax
   6ada0:	test   %sil,%sil
   6ada3:	je     6adac <_IO_vfwscanf+0x6dcc>
   6ada5:	mov    %rdx,-0x498(%rbp)
   6adac:	cmp    $0x2f,%eax
   6adaf:	ja     6adf9 <_IO_vfwscanf+0x6e19>
   6adb1:	mov    %eax,%edx
   6adb3:	add    -0x490(%rbp),%rdx
   6adba:	add    $0x8,%eax
   6adbd:	mov    %eax,-0x4a0(%rbp)
   6adc3:	mov    (%rdx),%rax
   6adc6:	jmpq   65302 <_IO_vfwscanf+0x1322>
   6adcb:	mov    -0x4d0(%rbp),%rax
   6add2:	lea    0x8(%rax),%rdx
   6add6:	mov    %rdx,-0x4d0(%rbp)
   6addd:	jmpq   6757e <_IO_vfwscanf+0x359e>
   6ade2:	mov    -0x4d0(%rbp),%rax
   6ade9:	lea    0x8(%rax),%rdx
   6aded:	mov    %rdx,-0x4d0(%rbp)
   6adf4:	jmpq   672d8 <_IO_vfwscanf+0x32f8>
   6adf9:	mov    -0x498(%rbp),%rdx
   6ae00:	lea    0x8(%rdx),%rax
   6ae04:	mov    %rax,-0x498(%rbp)
   6ae0b:	jmp    6adc3 <_IO_vfwscanf+0x6de3>
   6ae0d:	add    $0x8,%rdx
   6ae11:	mov    $0x1,%edi
   6ae16:	jmpq   685fa <_IO_vfwscanf+0x461a>
   6ae1b:	test   %sil,%sil
   6ae1e:	je     6ae28 <_IO_vfwscanf+0x6e48>
   6ae20:	mov    %ecx,-0x4a0(%rbp)
   6ae26:	mov    %ecx,%eax
   6ae28:	test   %dil,%dil
   6ae2b:	je     6ae34 <_IO_vfwscanf+0x6e54>
   6ae2d:	mov    %rdx,-0x498(%rbp)
   6ae34:	cmp    $0x2f,%eax
   6ae37:	ja     6ae88 <_IO_vfwscanf+0x6ea8>
   6ae39:	mov    %eax,%edx
   6ae3b:	add    -0x490(%rbp),%rdx
   6ae42:	add    $0x8,%eax
   6ae45:	mov    %eax,-0x4a0(%rbp)
   6ae4b:	mov    (%rdx),%rax
   6ae4e:	mov    %rax,-0x520(%rbp)
   6ae55:	jmpq   64f70 <_IO_vfwscanf+0xf90>
   6ae5a:	mov    -0x4d0(%rbp),%rdx
   6ae61:	lea    0x8(%rdx),%rcx
   6ae65:	mov    %rcx,-0x4d0(%rbp)
   6ae6c:	jmpq   6801b <_IO_vfwscanf+0x403b>
   6ae71:	mov    -0x498(%rbp),%rdx
   6ae78:	lea    0x8(%rdx),%rax
   6ae7c:	mov    %rax,-0x498(%rbp)
   6ae83:	jmpq   6ad66 <_IO_vfwscanf+0x6d86>
   6ae88:	mov    -0x498(%rbp),%rdx
   6ae8f:	lea    0x8(%rdx),%rax
   6ae93:	mov    %rax,-0x498(%rbp)
   6ae9a:	jmp    6ae4b <_IO_vfwscanf+0x6e6b>
   6ae9c:	mov    %r14,%rdi
   6ae9f:	mov    %rcx,-0x570(%rbp)
   6aea6:	callq  73620 <__wuflow>
   6aeab:	mov    -0x570(%rbp),%rcx
   6aeb2:	mov    %eax,%r13d
   6aeb5:	jmpq   68f9a <_IO_vfwscanf+0x4fba>
   6aeba:	mov    %r13d,%r15d
   6aebd:	mov    -0x560(%rbp),%rbx
   6aec4:	mov    %rcx,-0x570(%rbp)
   6aecb:	mov    -0x558(%rbp),%r13d
   6aed2:	jmpq   68dd1 <_IO_vfwscanf+0x4df1>
   6aed7:	lea    0x122702(%rip),%rcx        # 18d5e0 <__PRETTY_FUNCTION__.12112>
   6aede:	lea    0x11eb73(%rip),%rsi        # 189a58 <null+0x1a>
   6aee5:	lea    0x11eb87(%rip),%rdi        # 189a73 <null+0x35>
   6aeec:	mov    $0xb3e,%edx
   6aef1:	callq  2de10 <__assert_fail>
   6aef6:	mov    0x354f6b(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   6aefd:	mov    %r14,%r15
   6af00:	mov    -0x504(%rbp),%ebx
   6af06:	mov    -0x510(%rbp),%r14
   6af0d:	movl   $0x4,-0x508(%rbp)
   6af17:	movl   $0x54,%fs:(%rax)
   6af1e:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6af23:	pxor   %xmm0,%xmm0
   6af27:	test   %r12d,%r12d
   6af2a:	movaps %xmm0,-0x450(%rbp)
   6af31:	je     69c80 <_IO_vfwscanf+0x5ca0>
   6af37:	mov    $0x1,%r13d
   6af3d:	jmpq   65880 <_IO_vfwscanf+0x18a0>
   6af42:	lea    0x122697(%rip),%rcx        # 18d5e0 <__PRETTY_FUNCTION__.12112>
   6af49:	lea    0x11eb08(%rip),%rsi        # 189a58 <null+0x1a>
   6af50:	lea    0x11eb1c(%rip),%rdi        # 189a73 <null+0x35>
   6af57:	mov    $0x44c,%edx
   6af5c:	callq  2de10 <__assert_fail>
   6af61:	add    $0x8,%rdx
   6af65:	mov    $0x1,%edi
   6af6a:	jmpq   68bde <_IO_vfwscanf+0x4bfe>
   6af6f:	test   %sil,%sil
   6af72:	je     6af7c <_IO_vfwscanf+0x6f9c>
   6af74:	mov    %ecx,-0x4a0(%rbp)
   6af7a:	mov    %ecx,%eax
   6af7c:	test   %dil,%dil
   6af7f:	je     6af88 <_IO_vfwscanf+0x6fa8>
   6af81:	mov    %rdx,-0x498(%rbp)
   6af88:	cmp    $0x2f,%eax
   6af8b:	ja     6b03e <_IO_vfwscanf+0x705e>
   6af91:	mov    %eax,%edx
   6af93:	add    -0x490(%rbp),%rdx
   6af9a:	add    $0x8,%eax
   6af9d:	mov    %eax,-0x4a0(%rbp)
   6afa3:	mov    (%rdx),%rax
   6afa6:	mov    %rax,-0x570(%rbp)
   6afad:	jmpq   68499 <_IO_vfwscanf+0x44b9>
   6afb2:	mov    %r14,%r15
   6afb5:	mov    -0x510(%rbp),%r14
   6afbc:	mov    -0x504(%rbp),%eax
   6afc2:	test   %eax,%eax
   6afc4:	je     6b08e <_IO_vfwscanf+0x70ae>
   6afca:	mov    %eax,%ebx
   6afcc:	mov    -0x538(%rbp),%eax
   6afd2:	mov    %eax,-0x508(%rbp)
   6afd8:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6afdd:	mov    0x354e84(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   6afe4:	mov    %fs:(%rax),%eax
   6afe7:	mov    %eax,-0x514(%rbp)
   6afed:	jmpq   68c70 <_IO_vfwscanf+0x4c90>
   6aff2:	mov    0x354e6f(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   6aff9:	mov    -0x514(%rbp),%esi
   6afff:	mov    %r14,%r15
   6b002:	mov    -0x510(%rbp),%r14
   6b009:	mov    %esi,%fs:(%rax)
   6b00c:	jmp    6afbc <_IO_vfwscanf+0x6fdc>
   6b00e:	movl   $0x70,-0x4f8(%rbp)
   6b018:	xor    %r8d,%r8d
   6b01b:	jmpq   657f6 <_IO_vfwscanf+0x1816>
   6b020:	mov    %r14,%rdi
   6b023:	mov    %r8,-0x558(%rbp)
   6b02a:	callq  73620 <__wuflow>
   6b02f:	mov    -0x558(%rbp),%r8
   6b036:	mov    %eax,%r15d
   6b039:	jmpq   688ce <_IO_vfwscanf+0x48ee>
   6b03e:	mov    -0x498(%rbp),%rdx
   6b045:	lea    0x8(%rdx),%rax
   6b049:	mov    %rax,-0x498(%rbp)
   6b050:	jmpq   6afa3 <_IO_vfwscanf+0x6fc3>
   6b055:	mov    0x354e0c(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   6b05c:	mov    -0x514(%rbp),%ecx
   6b062:	mov    %ecx,%fs:(%rax)
   6b065:	jmpq   68c70 <_IO_vfwscanf+0x4c90>
   6b06a:	mov    -0x528(%rbp),%rdi
   6b071:	mov    %r15d,%esi
   6b074:	callq  63f80 <char_buffer_add_slow>
   6b079:	jmpq   68c22 <_IO_vfwscanf+0x4c42>
   6b07e:	mov    %r14,%rdi
   6b081:	callq  73620 <__wuflow>
   6b086:	mov    %eax,%r15d
   6b089:	jmpq   68c5e <_IO_vfwscanf+0x4c7e>
   6b08e:	mov    -0x538(%rbp),%eax
   6b094:	or     $0xffffffff,%ebx
   6b097:	mov    %ebx,-0x504(%rbp)
   6b09d:	mov    %eax,-0x508(%rbp)
   6b0a3:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6b0a8:	mov    -0x4d0(%rbp),%rax
   6b0af:	lea    0x8(%rax),%rsi
   6b0b3:	mov    %rsi,-0x4d0(%rbp)
   6b0ba:	jmpq   67ee9 <_IO_vfwscanf+0x3f09>
   6b0bf:	mov    -0x550(%rbp),%rax
   6b0c6:	mov    %rdx,-0x578(%rbp)
   6b0cd:	lea    0x0(,%rax,8),%rsi
   6b0d5:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   6b0da:	test   %rax,%rax
   6b0dd:	mov    -0x578(%rbp),%rdx
   6b0e4:	je     6b13c <_IO_vfwscanf+0x715c>
   6b0e6:	mov    -0x550(%rbp),%rcx
   6b0ed:	mov    -0x520(%rbp),%rsi
   6b0f4:	mov    %rax,(%rsi)
   6b0f7:	lea    (%rax,%rdx,1),%rsi
   6b0fb:	mov    %rcx,%rax
   6b0fe:	add    %rcx,%rax
   6b101:	mov    %rax,-0x550(%rbp)
   6b108:	jmpq   68ab3 <_IO_vfwscanf+0x4ad3>
   6b10d:	mov    -0x4d0(%rbp),%rdx
   6b114:	lea    0x8(%rdx),%rcx
   6b118:	mov    %rcx,-0x4d0(%rbp)
   6b11f:	jmpq   65637 <_IO_vfwscanf+0x1657>
   6b124:	or     $0xffffffff,%ebx
   6b127:	movl   $0x0,-0x508(%rbp)
   6b131:	mov    %ebx,-0x504(%rbp)
   6b137:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6b13c:	mov    -0x520(%rbp),%rax
   6b143:	lea    0x4(%rdx),%rsi
   6b147:	addq   $0x1,-0x550(%rbp)
   6b14f:	mov    (%rax),%rdi
   6b152:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   6b157:	test   %rax,%rax
   6b15a:	mov    -0x578(%rbp),%rdx
   6b161:	je     6b201 <_IO_vfwscanf+0x7221>
   6b167:	mov    -0x520(%rbp),%rdi
   6b16e:	lea    (%rax,%rdx,1),%rsi
   6b172:	mov    %rax,(%rdi)
   6b175:	jmpq   68ab3 <_IO_vfwscanf+0x4ad3>
   6b17a:	mov    %r14,%r15
   6b17d:	mov    -0x504(%rbp),%ebx
   6b183:	mov    -0x510(%rbp),%r14
   6b18a:	movl   $0x2,-0x508(%rbp)
   6b194:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6b199:	add    $0x8,%rdx
   6b19d:	mov    $0x1,%esi
   6b1a2:	jmpq   67887 <_IO_vfwscanf+0x38a7>
   6b1a7:	test   %dil,%dil
   6b1aa:	je     6b1b4 <_IO_vfwscanf+0x71d4>
   6b1ac:	mov    %ecx,-0x4a0(%rbp)
   6b1b2:	mov    %ecx,%eax
   6b1b4:	test   %sil,%sil
   6b1b7:	je     6b1c0 <_IO_vfwscanf+0x71e0>
   6b1b9:	mov    %rdx,-0x498(%rbp)
   6b1c0:	cmp    $0x2f,%eax
   6b1c3:	ja     6b256 <_IO_vfwscanf+0x7276>
   6b1c9:	mov    %eax,%edx
   6b1cb:	add    -0x490(%rbp),%rdx
   6b1d2:	add    $0x8,%eax
   6b1d5:	mov    %eax,-0x4a0(%rbp)
   6b1db:	mov    (%rdx),%rax
   6b1de:	mov    %rax,-0x578(%rbp)
   6b1e5:	jmpq   66e05 <_IO_vfwscanf+0x2e25>
   6b1ea:	mov    -0x4d0(%rbp),%rax
   6b1f1:	lea    0x8(%rax),%rdx
   6b1f5:	mov    %rdx,-0x4d0(%rbp)
   6b1fc:	jmpq   64d87 <_IO_vfwscanf+0xda7>
   6b201:	mov    -0x568(%rbp),%r13d
   6b208:	mov    %r14,%r15
   6b20b:	mov    -0x510(%rbp),%r14
   6b212:	and    $0x2000,%r13d
   6b219:	jne    6b26d <_IO_vfwscanf+0x728d>
   6b21b:	mov    -0x520(%rbp),%rax
   6b222:	addl   $0x1,-0x504(%rbp)
   6b229:	movq   $0x0,-0x520(%rbp)
   6b234:	movl   $0x2,-0x508(%rbp)
   6b23e:	mov    (%rax),%rax
   6b241:	movl   $0x0,-0x4(%rax,%rdx,1)
   6b249:	mov    -0x504(%rbp),%eax
   6b24f:	mov    %eax,%ebx
   6b251:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6b256:	mov    -0x498(%rbp),%rdx
   6b25d:	lea    0x8(%rdx),%rax
   6b261:	mov    %rax,-0x498(%rbp)
   6b268:	jmpq   6b1db <_IO_vfwscanf+0x71fb>
   6b26d:	or     $0xffffffff,%ebx
   6b270:	movl   $0x0,-0x508(%rbp)
   6b27a:	mov    %ebx,-0x504(%rbp)
   6b280:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6b285:	mov    -0x4f8(%rbp),%esi
   6b28b:	mov    -0x528(%rbp),%rdi
   6b292:	callq  63f80 <char_buffer_add_slow>
   6b297:	mov    %r13b,-0x558(%rbp)
   6b29e:	mov    %r13b,-0x538(%rbp)
   6b2a5:	jmpq   6586d <_IO_vfwscanf+0x188d>
   6b2aa:	mov    -0x4d0(%rbp),%rax
   6b2b1:	lea    0x8(%rax),%rdx
   6b2b5:	mov    %rdx,-0x4d0(%rbp)
   6b2bc:	jmpq   66d57 <_IO_vfwscanf+0x2d77>
   6b2c1:	mov    %r14,%r15
   6b2c4:	mov    -0x504(%rbp),%ebx
   6b2ca:	mov    -0x510(%rbp),%r14
   6b2d1:	movl   $0x2,-0x508(%rbp)
   6b2db:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6b2e0:	mov    -0x4d0(%rbp),%rax
   6b2e7:	lea    0x8(%rax),%rdx
   6b2eb:	mov    %rdx,-0x4d0(%rbp)
   6b2f2:	jmpq   64ad7 <_IO_vfwscanf+0xaf7>
   6b2f7:	add    $0x8,%rdx
   6b2fb:	mov    $0x1,%esi
   6b300:	jmpq   6778d <_IO_vfwscanf+0x37ad>
   6b305:	test   %dil,%dil
   6b308:	je     6b312 <_IO_vfwscanf+0x7332>
   6b30a:	mov    %ecx,-0x4a0(%rbp)
   6b310:	mov    %ecx,%eax
   6b312:	test   %sil,%sil
   6b315:	je     6b31e <_IO_vfwscanf+0x733e>
   6b317:	mov    %rdx,-0x498(%rbp)
   6b31e:	cmp    $0x2f,%eax
   6b321:	ja     6b391 <_IO_vfwscanf+0x73b1>
   6b323:	mov    %eax,%edx
   6b325:	add    -0x490(%rbp),%rdx
   6b32c:	add    $0x8,%eax
   6b32f:	mov    %eax,-0x4a0(%rbp)
   6b335:	mov    (%rdx),%rax
   6b338:	mov    %rax,-0x578(%rbp)
   6b33f:	jmpq   66d61 <_IO_vfwscanf+0x2d81>
   6b344:	add    $0x8,%rdx
   6b348:	mov    $0x1,%esi
   6b34d:	jmpq   678d9 <_IO_vfwscanf+0x38f9>
   6b352:	test   %dil,%dil
   6b355:	je     6b35f <_IO_vfwscanf+0x737f>
   6b357:	mov    %ecx,-0x4a0(%rbp)
   6b35d:	mov    %ecx,%eax
   6b35f:	test   %sil,%sil
   6b362:	je     6b36b <_IO_vfwscanf+0x738b>
   6b364:	mov    %rdx,-0x498(%rbp)
   6b36b:	cmp    $0x2f,%eax
   6b36e:	ja     6b3a5 <_IO_vfwscanf+0x73c5>
   6b370:	mov    %eax,%edx
   6b372:	add    -0x490(%rbp),%rdx
   6b379:	add    $0x8,%eax
   6b37c:	mov    %eax,-0x4a0(%rbp)
   6b382:	mov    (%rdx),%rax
   6b385:	mov    %rax,-0x520(%rbp)
   6b38c:	jmpq   64d91 <_IO_vfwscanf+0xdb1>
   6b391:	mov    -0x498(%rbp),%rdx
   6b398:	lea    0x8(%rdx),%rax
   6b39c:	mov    %rax,-0x498(%rbp)
   6b3a3:	jmp    6b335 <_IO_vfwscanf+0x7355>
   6b3a5:	mov    -0x498(%rbp),%rdx
   6b3ac:	lea    0x8(%rdx),%rax
   6b3b0:	mov    %rax,-0x498(%rbp)
   6b3b7:	jmp    6b382 <_IO_vfwscanf+0x73a2>
   6b3b9:	mov    0x3549f0(%rip),%rax        # 3bfdb0 <_DYNAMIC+0x250>
   6b3c0:	mov    %fs:(%rax),%rax
   6b3c4:	mov    (%rax),%rax
   6b3c7:	mov    0xa8(%rax),%esi
   6b3cd:	mov    -0x520(%rbp),%rax
   6b3d4:	mov    (%rax),%rdi
   6b3d7:	add    %r12,%rsi
   6b3da:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   6b3df:	test   %rax,%rax
   6b3e2:	je     6b42f <_IO_vfwscanf+0x744f>
   6b3e4:	mov    -0x520(%rbp),%rcx
   6b3eb:	mov    %r12,%rdi
   6b3ee:	lea    (%rax,%r12,1),%r12
   6b3f2:	mov    %rax,(%rcx)
   6b3f5:	mov    0x3549b4(%rip),%rax        # 3bfdb0 <_DYNAMIC+0x250>
   6b3fc:	mov    %fs:(%rax),%rax
   6b400:	mov    (%rax),%rax
   6b403:	mov    0xa8(%rax),%eax
   6b409:	add    %rdi,%rax
   6b40c:	mov    %rax,-0x550(%rbp)
   6b413:	jmpq   65070 <_IO_vfwscanf+0x1090>
   6b418:	mov    -0x4d0(%rbp),%rax
   6b41f:	lea    0x8(%rax),%rdx
   6b423:	mov    %rdx,-0x4d0(%rbp)
   6b42a:	jmpq   6714b <_IO_vfwscanf+0x316b>
   6b42f:	or     $0xffffffff,%ebx
   6b432:	mov    %r14,%r15
   6b435:	movl   $0x0,-0x508(%rbp)
   6b43f:	mov    -0x510(%rbp),%r14
   6b446:	mov    %ebx,-0x504(%rbp)
   6b44c:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6b451:	add    $0x8,%rdx
   6b455:	mov    $0x1,%esi
   6b45a:	jmpq   68159 <_IO_vfwscanf+0x4179>
   6b45f:	test   %dil,%dil
   6b462:	je     6b46c <_IO_vfwscanf+0x748c>
   6b464:	mov    %ecx,-0x4a0(%rbp)
   6b46a:	mov    %ecx,%eax
   6b46c:	test   %sil,%sil
   6b46f:	je     6b478 <_IO_vfwscanf+0x7498>
   6b471:	mov    %rdx,-0x498(%rbp)
   6b478:	cmp    $0x2f,%eax
   6b47b:	ja     6b5a3 <_IO_vfwscanf+0x75c3>
   6b481:	mov    %eax,%edx
   6b483:	add    -0x490(%rbp),%rdx
   6b48a:	add    $0x8,%eax
   6b48d:	mov    %eax,-0x4a0(%rbp)
   6b493:	mov    (%rdx),%rax
   6b496:	mov    %rax,-0x578(%rbp)
   6b49d:	jmpq   672e2 <_IO_vfwscanf+0x3302>
   6b4a2:	mov    -0x4d0(%rbp),%rax
   6b4a9:	lea    0x8(%rax),%rdx
   6b4ad:	mov    %rdx,-0x4d0(%rbp)
   6b4b4:	jmpq   66dfb <_IO_vfwscanf+0x2e1b>
   6b4b9:	mov    -0x588(%rbp),%rsi
   6b4c0:	mov    -0x570(%rbp),%rdi
   6b4c7:	xor    %edx,%edx
   6b4c9:	callq  90920 <__GI___mempcpy>
   6b4ce:	cmpl   $0x0,-0x530(%rbp)
   6b4d5:	lea    0x1(%rax),%rcx
   6b4d9:	movb   $0x0,(%rax)
   6b4dc:	mov    %rcx,-0x570(%rbp)
   6b4e3:	je     65c8f <_IO_vfwscanf+0x1caf>
   6b4e9:	jmpq   65c63 <_IO_vfwscanf+0x1c83>
   6b4ee:	mov    -0x4f8(%rbp),%r13d
   6b4f5:	mov    %r14,%r15
   6b4f8:	mov    -0x510(%rbp),%r14
   6b4ff:	and    $0x2000,%r13d
   6b506:	jne    6b5ba <_IO_vfwscanf+0x75da>
   6b50c:	mov    -0x520(%rbp),%rax
   6b513:	addl   $0x1,-0x504(%rbp)
   6b51a:	movq   $0x0,-0x520(%rbp)
   6b525:	movl   $0x2,-0x508(%rbp)
   6b52f:	mov    (%rax),%rax
   6b532:	movl   $0x0,-0x4(%rax,%rcx,1)
   6b53a:	mov    -0x504(%rbp),%eax
   6b540:	mov    %eax,%ebx
   6b542:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6b547:	mov    0x354862(%rip),%rax        # 3bfdb0 <_DYNAMIC+0x250>
   6b54e:	mov    %fs:(%rax),%rax
   6b552:	mov    (%rax),%rax
   6b555:	mov    0xa8(%rax),%esi
   6b55b:	mov    -0x520(%rbp),%rax
   6b562:	mov    (%rax),%rdi
   6b565:	add    %rbx,%rsi
   6b568:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   6b56d:	test   %rax,%rax
   6b570:	je     6b5d2 <_IO_vfwscanf+0x75f2>
   6b572:	mov    -0x520(%rbp),%rdi
   6b579:	lea    (%rax,%rbx,1),%r13
   6b57d:	mov    %rax,(%rdi)
   6b580:	mov    0x354829(%rip),%rax        # 3bfdb0 <_DYNAMIC+0x250>
   6b587:	mov    %fs:(%rax),%rax
   6b58b:	mov    (%rax),%rax
   6b58e:	mov    0xa8(%rax),%eax
   6b594:	add    %rbx,%rax
   6b597:	mov    %rax,-0x550(%rbp)
   6b59e:	jmpq   65b16 <_IO_vfwscanf+0x1b36>
   6b5a3:	mov    -0x498(%rbp),%rdx
   6b5aa:	lea    0x8(%rdx),%rax
   6b5ae:	mov    %rax,-0x498(%rbp)
   6b5b5:	jmpq   6b493 <_IO_vfwscanf+0x74b3>
   6b5ba:	or     $0xffffffff,%ebx
   6b5bd:	movl   $0x0,-0x508(%rbp)
   6b5c7:	mov    %ebx,-0x504(%rbp)
   6b5cd:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6b5d2:	mov    -0x560(%rbp),%r13d
   6b5d9:	mov    %r14,%r15
   6b5dc:	mov    -0x510(%rbp),%r14
   6b5e3:	and    $0x2000,%r13d
   6b5ea:	jne    6b6ea <_IO_vfwscanf+0x770a>
   6b5f0:	mov    -0x520(%rbp),%rax
   6b5f7:	addl   $0x1,-0x504(%rbp)
   6b5fe:	movq   $0x0,-0x520(%rbp)
   6b609:	movl   $0x2,-0x508(%rbp)
   6b613:	mov    (%rax),%rax
   6b616:	movb   $0x0,(%rax,%rbx,1)
   6b61a:	mov    -0x504(%rbp),%eax
   6b620:	mov    %eax,%ebx
   6b622:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6b627:	mov    -0x570(%rbp),%r12
   6b62e:	mov    %rcx,-0x530(%rbp)
   6b635:	sub    %rdi,%r12
   6b638:	lea    0x1(%rcx,%r12,1),%rdx
   6b63d:	mov    %rdx,%rsi
   6b640:	mov    %rdx,-0x500(%rbp)
   6b647:	callq  1f990 <*ABS*+0x911b0@plt+0x10>
   6b64c:	test   %rax,%rax
   6b64f:	mov    -0x500(%rbp),%rdx
   6b656:	mov    -0x530(%rbp),%rcx
   6b65d:	je     6b7c0 <_IO_vfwscanf+0x77e0>
   6b663:	mov    -0x520(%rbp),%rdi
   6b66a:	mov    %rdx,-0x550(%rbp)
   6b671:	mov    %rax,(%rdi)
   6b674:	add    %r12,%rax
   6b677:	mov    %rax,-0x570(%rbp)
   6b67e:	jmpq   65c3f <_IO_vfwscanf+0x1c5f>
   6b683:	add    $0x8,%rdx
   6b687:	mov    $0x1,%edi
   6b68c:	jmpq   68559 <_IO_vfwscanf+0x4579>
   6b691:	add    $0x8,%rsi
   6b695:	mov    $0x1,%r9d
   6b69b:	jmpq   690f5 <_IO_vfwscanf+0x5115>
   6b6a0:	test   %r8b,%r8b
   6b6a3:	je     6b6ad <_IO_vfwscanf+0x76cd>
   6b6a5:	mov    %edi,-0x4a0(%rbp)
   6b6ab:	mov    %edi,%eax
   6b6ad:	test   %r9b,%r9b
   6b6b0:	je     6b6b9 <_IO_vfwscanf+0x76d9>
   6b6b2:	mov    %rsi,-0x498(%rbp)
   6b6b9:	cmp    $0x2f,%eax
   6b6bc:	ja     6b702 <_IO_vfwscanf+0x7722>
   6b6be:	mov    %eax,%esi
   6b6c0:	add    -0x490(%rbp),%rsi
   6b6c7:	add    $0x8,%eax
   6b6ca:	mov    %eax,-0x4a0(%rbp)
   6b6d0:	mov    (%rsi),%rax
   6b6d3:	jmpq   6807d <_IO_vfwscanf+0x409d>
   6b6d8:	movl   $0x0,-0x530(%rbp)
   6b6e2:	mov    %rbx,%r8
   6b6e5:	jmpq   65255 <_IO_vfwscanf+0x1275>
   6b6ea:	or     $0xffffffff,%ebx
   6b6ed:	movl   $0x0,-0x508(%rbp)
   6b6f7:	mov    %ebx,-0x504(%rbp)
   6b6fd:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6b702:	mov    -0x498(%rbp),%rsi
   6b709:	lea    0x8(%rsi),%rax
   6b70d:	mov    %rax,-0x498(%rbp)
   6b714:	jmp    6b6d0 <_IO_vfwscanf+0x76f0>
   6b716:	movl   $0x0,-0x500(%rbp)
   6b720:	jmpq   65233 <_IO_vfwscanf+0x1253>
   6b725:	mov    -0x558(%rbp),%r13d
   6b72c:	mov    %r15,%rdx
   6b72f:	mov    %r14,%r15
   6b732:	mov    -0x510(%rbp),%r14
   6b739:	and    $0x2000,%r13d
   6b740:	jne    6b815 <_IO_vfwscanf+0x7835>
   6b746:	mov    -0x520(%rbp),%rax
   6b74d:	addl   $0x1,-0x504(%rbp)
   6b754:	movq   $0x0,-0x520(%rbp)
   6b75f:	movl   $0x2,-0x508(%rbp)
   6b769:	mov    (%rax),%rax
   6b76c:	movb   $0x0,(%rax,%rdx,1)
   6b770:	mov    -0x504(%rbp),%eax
   6b776:	mov    %eax,%ebx
   6b778:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6b77d:	test   %sil,%sil
   6b780:	je     6b78a <_IO_vfwscanf+0x77aa>
   6b782:	mov    %ecx,-0x4a0(%rbp)
   6b788:	mov    %ecx,%eax
   6b78a:	test   %dil,%dil
   6b78d:	je     6b796 <_IO_vfwscanf+0x77b6>
   6b78f:	mov    %rdx,-0x498(%rbp)
   6b796:	cmp    $0x2f,%eax
   6b799:	ja     6b82d <_IO_vfwscanf+0x784d>
   6b79f:	mov    %eax,%edx
   6b7a1:	add    -0x490(%rbp),%rdx
   6b7a8:	add    $0x8,%eax
   6b7ab:	mov    %eax,-0x4a0(%rbp)
   6b7b1:	mov    (%rdx),%rax
   6b7b4:	mov    %rax,-0x520(%rbp)
   6b7bb:	jmpq   659d1 <_IO_vfwscanf+0x19f1>
   6b7c0:	and    $0x2000,%r13d
   6b7c7:	mov    %r14,%r15
   6b7ca:	mov    -0x510(%rbp),%r14
   6b7d1:	jne    6b844 <_IO_vfwscanf+0x7864>
   6b7d3:	mov    -0x520(%rbp),%rax
   6b7da:	addl   $0x1,-0x504(%rbp)
   6b7e1:	movq   $0x0,-0x520(%rbp)
   6b7ec:	movl   $0x2,-0x558(%rbp)
   6b7f6:	mov    (%rax),%rax
   6b7f9:	movb   $0x0,(%rax,%r12,1)
   6b7fe:	mov    -0x558(%rbp),%eax
   6b804:	mov    -0x504(%rbp),%ebx
   6b80a:	mov    %eax,-0x508(%rbp)
   6b810:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6b815:	or     $0xffffffff,%ebx
   6b818:	movl   $0x0,-0x508(%rbp)
   6b822:	mov    %ebx,-0x504(%rbp)
   6b828:	jmpq   64590 <_IO_vfwscanf+0x5b0>
   6b82d:	mov    -0x498(%rbp),%rdx
   6b834:	lea    0x8(%rdx),%rax
   6b838:	mov    %rax,-0x498(%rbp)
   6b83f:	jmpq   6b7b1 <_IO_vfwscanf+0x77d1>
   6b844:	movl   $0xffffffff,-0x504(%rbp)
   6b84e:	jmp    6b7fe <_IO_vfwscanf+0x781e>
