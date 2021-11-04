// TC_OUT pfs_start_socket_wait_v1,0xed85e4,0xed85eb,0x0(%rbx)
0000000000ed8500 <pfs_start_socket_wait_v1>:
  ed8500:	push   %rbp
  ed8501:	mov    %rsp,%rbp
  ed8504:	push   %r13
  ed8506:	push   %r12
  ed8508:	push   %rbx
  ed8509:	mov    %rsi,%rbx
  ed850c:	sub    $0x28,%rsp
  ed8510:	cmpb   $0x0,0x4(%rsi)
  ed8514:	je     ed8698 <pfs_start_socket_wait_v1+0x198>
  ed851a:	cmpb   $0x0,0xac(%rsi)
  ed8521:	jne    ed8698 <pfs_start_socket_wait_v1+0x198>
  ed8527:	cmpb   $0x0,0xfbc6d2(%rip)        # 1e94c00 <flag_thread_instrumentation>
  ed852e:	mov    %rdi,%r12
  ed8531:	je     ed8668 <pfs_start_socket_wait_v1+0x168>
  ed8537:	mov    0x18(%rsi),%r13
  ed853b:	test   %r13,%r13
  ed853e:	je     ed8698 <pfs_start_socket_wait_v1+0x198>
  ed8544:	cmpb   $0x0,0x1c0(%r13)
  ed854c:	je     ed8698 <pfs_start_socket_wait_v1+0x198>
  ed8552:	mov    %r13,0x10(%rdi)
  ed8556:	cmpb   $0x0,0x5(%rsi)
  ed855a:	jne    ed86d8 <pfs_start_socket_wait_v1+0x1d8>
  ed8560:	mov    $0x6,%edi
  ed8565:	xor    %eax,%eax
  ed8567:	mov    $0x2,%esi
  ed856c:	cmpb   $0x0,0xfbc78d(%rip)        # 1e94d00 <flag_events_waits_current>
  ed8573:	je     ed8649 <pfs_start_socket_wait_v1+0x149>
  ed8579:	mov    0x1d0(%r13),%rsi
  ed8580:	lea    0x678(%r13),%r10
  ed8587:	cmp    %r10,%rsi
  ed858a:	jae    ed8719 <pfs_start_socket_wait_v1+0x219>
  ed8590:	mov    %rsi,0x48(%r12)
  ed8595:	mov    -0xa8(%rsi),%r10
  ed859c:	movl   $0x4,0x18(%rsi)
  ed85a3:	mov    %r10,0x20(%rsi)
  ed85a7:	mov    -0x98(%rsi),%r10d
  ed85ae:	mov    %r10d,0x28(%rsi)
  ed85b2:	mov    0x230(%r13),%r10
  ed85b9:	mov    %r10,(%rsi)
  ed85bc:	mov    0xb0(%rbx),%r10
  ed85c3:	mov    %rax,0x38(%rsi)
  ed85c7:	movq   $0x0,0x40(%rsi)
  ed85cf:	mov    %r10,0x30(%rsi)
  ed85d3:	mov    0x10(%rbx),%rax
  ed85d7:	mov    %rbx,0x70(%rsi)
  ed85db:	mov    %rax,0x88(%rsi)
  ed85e2:	mov    (%rbx),%eax
  ed85e4:	mov    %eax,%r10d
  ed85e7:	lock cmpxchg %eax,(%rbx)
  ed85eb:	jne    ed85e4 <pfs_start_socket_wait_v1+0xe4>
  ed85ed:	and    $0xfffffffc,%r10d
  ed85f1:	mov    %r10d,0x80(%rsi)
  ed85f8:	mov    0x1d8(%r13),%rax
  ed85ff:	lea    0x1(%rax),%r10
  ed8603:	mov    %r10,0x1d8(%r13)
  ed860a:	mov    %rax,0x8(%rsi)
  ed860e:	movslq %edx,%rax
  ed8611:	mov    0x15caa20(,%rax,4),%eax
  ed8618:	movq   $0x0,0x10(%rsi)
  ed8620:	mov    %r8,0x48(%rsi)
  ed8624:	mov    %r9d,0x50(%rsi)
  ed8628:	mov    %rcx,0x98(%rsi)
  ed862f:	movl   $0x6,0x58(%rsi)
  ed8636:	mov    %eax,0x90(%rsi)
  ed863c:	addq   $0xb0,0x1d0(%r13)
  ed8647:	mov    %edi,%esi
  ed8649:	mov    %esi,(%r12)
  ed864d:	mov    %rbx,0x8(%r12)
  ed8652:	mov    %r12,%rax
  ed8655:	mov    %edx,0x30(%r12)
  ed865a:	add    $0x28,%rsp
  ed865e:	pop    %rbx
  ed865f:	pop    %r12
  ed8661:	pop    %r13
  ed8663:	pop    %rbp
  ed8664:	retq   
  ed8665:	nopl   (%rax)
  ed8668:	cmpb   $0x0,0x5(%rsi)
  ed866c:	jne    ed86b0 <pfs_start_socket_wait_v1+0x1b0>
  ed866e:	cmp    $0xe,%edx
  ed8671:	ja     ed86a8 <pfs_start_socket_wait_v1+0x1a8>
  ed8673:	mov    $0x1,%eax
  ed8678:	mov    %edx,%ecx
  ed867a:	xor    %esi,%esi
  ed867c:	shl    %cl,%rax
  ed867f:	test   $0x7c0f,%eax
  ed8684:	je     ed8649 <pfs_start_socket_wait_v1+0x149>
  ed8686:	addq   $0x1,0x108(%rbx)
  ed868e:	xor    %eax,%eax
  ed8690:	jmp    ed865a <pfs_start_socket_wait_v1+0x15a>
  ed8692:	nopw   0x0(%rax,%rax,1)
  ed8698:	add    $0x28,%rsp
  ed869c:	xor    %eax,%eax
  ed869e:	pop    %rbx
  ed869f:	pop    %r12
  ed86a1:	pop    %r13
  ed86a3:	pop    %rbp
  ed86a4:	retq   
  ed86a5:	nopl   (%rax)
  ed86a8:	xor    %esi,%esi
  ed86aa:	jmp    ed8649 <pfs_start_socket_wait_v1+0x149>
  ed86ac:	nopl   0x0(%rax)
  ed86b0:	lea    0x28(%rdi),%rsi
  ed86b4:	mov    0xebdd66(%rip),%edi        # 1d96420 <wait_timer>
  ed86ba:	mov    %edx,-0x24(%rbp)
  ed86bd:	callq  f02b90 <_Z32get_timer_raw_value_and_function15enum_timer_namePPFyvE>
  ed86c2:	mov    $0x1,%esi
  ed86c7:	mov    %rax,0x20(%r12)
  ed86cc:	mov    -0x24(%rbp),%edx
  ed86cf:	jmpq   ed8649 <pfs_start_socket_wait_v1+0x149>
  ed86d4:	nopl   0x0(%rax)
  ed86d8:	lea    0x28(%rdi),%rsi
  ed86dc:	mov    0xebdd3e(%rip),%edi        # 1d96420 <wait_timer>
  ed86e2:	mov    %r9d,-0x28(%rbp)
  ed86e6:	mov    %r8,-0x38(%rbp)
  ed86ea:	mov    %rcx,-0x30(%rbp)
  ed86ee:	mov    %edx,-0x24(%rbp)
  ed86f1:	callq  f02b90 <_Z32get_timer_raw_value_and_function15enum_timer_namePPFyvE>
  ed86f6:	mov    $0x7,%edi
  ed86fb:	mov    %rax,0x20(%r12)
  ed8700:	mov    $0x3,%esi
  ed8705:	mov    -0x24(%rbp),%edx
  ed8708:	mov    -0x30(%rbp),%rcx
  ed870c:	mov    -0x38(%rbp),%r8
  ed8710:	mov    -0x28(%rbp),%r9d
  ed8714:	jmpq   ed856c <pfs_start_socket_wait_v1+0x6c>
  ed8719:	addq   $0x1,0xfbc91f(%rip)        # 1e95040 <locker_lost>
  ed8721:	xor    %eax,%eax
  ed8723:	jmpq   ed865a <pfs_start_socket_wait_v1+0x15a>
  ed8728:	nopl   0x0(%rax,%rax,1)
