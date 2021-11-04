00000000004004d6 <no_lock_func>:
  4004d6:	push   %rbp
  4004d7:	mov    %rsp,%rbp
  4004da:	mov    %rdi,-0x8(%rbp)
  4004de:	jmp    4004ef
  4004e0:	mov    -0x8(%rbp),%rax
  4004e4:	mov    (%rax),%eax
  4004e6:	lea    0x1(%rax),%edx
  4004e9:	mov    -0x8(%rbp),%rax
  4004ed:	mov    %edx,(%rax)
  4004ef:	mov    -0x8(%rbp),%rax
  4004f3:	mov    (%rax),%eax
  4004f5:	cmp    $0x63,%eax
  4004f8:	jle    4004e0
  4004fa:	nop
  4004fb:	pop    %rbp
  4004fc:	retq

