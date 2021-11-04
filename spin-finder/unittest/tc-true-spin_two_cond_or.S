// TC_OUT spin_two_cond_or,0x4005a2,0x4005b4,0x0(-0x8(%rbp)),0x0(0x601044)
0000000000400599 <spin_two_cond_or>:
  400599:	push   %rbp
  40059a:	mov    %rsp,%rbp
  40059d:	mov    %rdi,-0x8(%rbp)
  4005a1:	nop
  4005a2:	mov    -0x8(%rbp),%rax
  4005a6:	mov    (%rax),%eax
  4005a8:	test   %eax,%eax
  4005aa:	jne    4005b6 <spin_two_cond_or+0x1d>
  4005ac:	mov    0x200a92(%rip),%eax        # 601044 <thread_stop>
  4005b2:	test   %eax,%eax
  4005b4:	je     4005a2 <spin_two_cond_or+0x9>
  4005b6:	mov    0x200a88(%rip),%eax        # 601044 <thread_stop>
  4005bc:	test   %eax,%eax
  4005be:	jne    4005ca <spin_two_cond_or+0x31>
  4005c0:	mov    -0x8(%rbp),%rax
  4005c4:	movl   $0x1,(%rax)
  4005ca:	pop    %rbp
  4005cb:	retq
