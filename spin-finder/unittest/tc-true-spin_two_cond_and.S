// TC_OUT spin_two_cond_and,0x40056f,0x400581,0x0(-0x8(%rbp)),0x0(0x601044)
0000000000400566 <spin_two_cond_and>:
  400566:	push   %rbp
  400567:	mov    %rsp,%rbp
  40056a:	mov    %rdi,-0x8(%rbp)
  40056e:	nop
  40056f:	mov    -0x8(%rbp),%rax
  400573:	mov    (%rax),%eax
  400575:	test   %eax,%eax
  400577:	jne    400583 <spin_two_cond_and+0x1d>
  400579:	mov    0x200ac5(%rip),%eax        # 601044 <thread_stop>
  40057f:	test   %eax,%eax
  400581:	je     40056f <spin_two_cond_and+0x9>
  400583:	mov    0x200abb(%rip),%eax        # 601044 <thread_stop>
  400589:	test   %eax,%eax
  40058b:	jne    400597 <spin_two_cond_and+0x31>
  40058d:	mov    -0x8(%rbp),%rax
  400591:	movl   $0x1,(%rax)
  400597:	pop    %rbp
  400598:	retq

