// TC_OUT _ZN7rocksdb9SpinMutex4lockEv,0x4007fa,0x40082f,0x0(%rbp)
00000000004007e4 <_ZN7rocksdb9SpinMutex4lockEv>:
  4007e4:	push   %r12
  4007e6:	push   %rbp
  4007e7:	push   %rbx
  4007e8:	sub    $0x10,%rsp
  4007ec:	mov    %rdi,%rbp
  4007ef:	mov    $0x0,%ebx
  4007f4:	mov    $0x1,%r12d
  4007fa:	movzbl 0x0(%rbp),%eax
  4007fe:	test   %al,%al
  400800:	setne  %al
  400803:	mov    %al,0xf(%rsp)
  400807:	test   %al,%al
  400809:	jne    40081e
  40080b:	lock cmpxchg %r12b,0x0(%rbp)
  400811:	sete   %dl
  400814:	je     40081a
  400816:	mov    %al,0xf(%rsp)
  40081a:	test   %dl,%dl
  40081c:	jne    400831
  40081e:	pause
  400820:	cmp    $0x64,%rbx
  400824:	jbe    40082b
  400826:	callq  400680
  40082b:	add    $0x1,%rbx
  40082f:	jmp    4007fa
  400831:	add    $0x10,%rsp
  400835:	pop    %rbx
  400836:	pop    %rbp
  400837:	pop    %r12
  400839:	retq
  40083a:	nopw   0x0(%rax,%rax,1)
