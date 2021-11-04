// TC_OUT spin_ts_lock,0x4006ef,0x4006fc,0x0(-0x8(%rbp))
00000000004006e6 <spin_ts_lock>:
  4006e6:	push   %rbp
  4006e7:	mov    %rsp,%rbp
  4006ea:	mov    %rdi,-0x8(%rbp)
  4006ee:	nop
  4006ef:	mov    -0x8(%rbp),%rdx
  4006f3:	mov    $0x1,%eax
  4006f8:	xchg   %eax,(%rdx)
  4006fa:	test   %eax,%eax
  4006fc:	jne    4006ef <spin_ts_lock+0x9>
  4006fe:	nop
  4006ff:	pop    %rbp
  400700:	retq   
