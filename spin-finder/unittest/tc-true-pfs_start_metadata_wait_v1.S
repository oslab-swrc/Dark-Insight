// TC_OUT pfs_start_metadata_wait_v1,0xed8877,0xed8880,0x0(%r12)
0000000000ed8730 <pfs_start_metadata_wait_v1>:
  ed8730:	push   %rbp
  ed8731:	mov    %rsp,%rbp
  ed8734:	push   %r13
  ed8736:	push   %r12
  ed8738:	mov    %rsi,%r12
  ed873b:	push   %rbx
  ed873c:	sub    $0x18,%rsp
  ed8740:	cmpb   $0x0,0x4(%rsi)
  ed8744:	je     ed8910 <pfs_start_metadata_wait_v1+0x1e0>
  ed874a:	cmpb   $0x0,0xfbc4af(%rip)        # 1e94c00 <flag_thread_instrumentation>
  ed8751:	mov    %rdi,%rbx
  ed8754:	jne    ed8798 <pfs_start_metadata_wait_v1+0x68>
  ed8756:	cmpb   $0x0,0x5(%rsi)
  ed875a:	je     ed88f0 <pfs_start_metadata_wait_v1+0x1c0>
  ed8760:	lea    0x20(%rdi),%rsi
  ed8764:	mov    0xebdcb6(%rip),%edi        # 1d96420 <wait_timer>
  ed876a:	callq  f02b90 <_Z32get_timer_raw_value_and_function15enum_timer_namePPFyvE>
  ed876f:	movq   $0x0,0x10(%rbx)
  ed8777:	mov    %rax,0x18(%rbx)
  ed877b:	mov    $0x1,%esi
  ed8780:	mov    %esi,(%rbx)
  ed8782:	mov    %r12,0x8(%rbx)
  ed8786:	add    $0x18,%rsp
  ed878a:	mov    %rbx,%rax
  ed878d:	pop    %rbx
  ed878e:	pop    %r12
  ed8790:	pop    %r13
  ed8792:	pop    %rbp
  ed8793:	retq   
  ed8794:	nopl   0x0(%rax)
  ed8798:	mov    0xf7d0d2(%rip),%edi        # 1e55870 <THR_PFS>
  ed879e:	mov    %ecx,-0x2c(%rbp)
  ed87a1:	mov    %rdx,-0x28(%rbp)
  ed87a5:	callq  762c40 <pthread_getspecific@plt>
  ed87aa:	test   %rax,%rax
  ed87ad:	mov    %rax,%r13
  ed87b0:	je     ed8910 <pfs_start_metadata_wait_v1+0x1e0>
  ed87b6:	cmpb   $0x0,0x1c0(%rax)
  ed87bd:	je     ed8910 <pfs_start_metadata_wait_v1+0x1e0>
  ed87c3:	mov    %rax,0x10(%rbx)
  ed87c7:	cmpb   $0x0,0x5(%r12)
  ed87cd:	mov    -0x28(%rbp),%rdx
  ed87d1:	mov    -0x2c(%rbp),%ecx
  ed87d4:	jne    ed88c0 <pfs_start_metadata_wait_v1+0x190>
  ed87da:	mov    $0x6,%edi
  ed87df:	xor    %eax,%eax
  ed87e1:	mov    $0x2,%esi
  ed87e6:	cmpb   $0x0,0xfbc513(%rip)        # 1e94d00 <flag_events_waits_current>
  ed87ed:	je     ed8780 <pfs_start_metadata_wait_v1+0x50>
  ed87ef:	mov    0x1d0(%r13),%rsi
  ed87f6:	lea    0x678(%r13),%r8
  ed87fd:	cmp    %r8,%rsi
  ed8800:	jae    ed8905 <pfs_start_metadata_wait_v1+0x1d5>
  ed8806:	mov    %rsi,0x28(%rbx)
  ed880a:	mov    -0xa8(%rsi),%r8
  ed8811:	movl   $0x4,0x18(%rsi)
  ed8818:	mov    %r8,0x20(%rsi)
  ed881c:	mov    -0x98(%rsi),%r8d
  ed8823:	mov    %r8d,0x28(%rsi)
  ed8827:	mov    0x230(%r13),%r8
  ed882e:	movq   $0x1e953c0,0x30(%rsi)
  ed8836:	mov    %rax,0x38(%rsi)
  ed883a:	movq   $0x0,0x40(%rsi)
  ed8842:	mov    %r8,(%rsi)
  ed8845:	mov    0x10(%r12),%rax
  ed884a:	mov    %rax,0x88(%rsi)
  ed8851:	mov    0x1d8(%r13),%rax
  ed8858:	lea    0x1(%rax),%r8
  ed885c:	mov    %r8,0x1d8(%r13)
  ed8863:	mov    %rax,0x8(%rsi)
  ed8867:	movq   $0x0,0x10(%rsi)
  ed886f:	mov    %r12,0x78(%rsi)
  ed8873:	mov    (%r12),%eax
  ed8877:	mov    %eax,%r8d
  ed887a:	lock cmpxchg %eax,(%r12)
  ed8880:	jne    ed8877 <pfs_start_metadata_wait_v1+0x147>
  ed8882:	and    $0xfffffffc,%r8d
  ed8886:	movl   $0x3e,0x90(%rsi)
  ed8890:	mov    %rdx,0x48(%rsi)
  ed8894:	mov    %r8d,0x80(%rsi)
  ed889b:	mov    %ecx,0x50(%rsi)
  ed889e:	movl   $0x8,0x58(%rsi)
  ed88a5:	mov    %edi,%esi
  ed88a7:	addq   $0xb0,0x1d0(%r13)
  ed88b2:	jmpq   ed8780 <pfs_start_metadata_wait_v1+0x50>
  ed88b7:	nopw   0x0(%rax,%rax,1)
  ed88c0:	mov    0xebdb5a(%rip),%edi        # 1d96420 <wait_timer>
  ed88c6:	lea    0x20(%rbx),%rsi
  ed88ca:	callq  f02b90 <_Z32get_timer_raw_value_and_function15enum_timer_namePPFyvE>
  ed88cf:	mov    $0x7,%edi
  ed88d4:	mov    %rax,0x18(%rbx)
  ed88d8:	mov    $0x3,%esi
  ed88dd:	mov    -0x28(%rbp),%rdx
  ed88e1:	mov    -0x2c(%rbp),%ecx
  ed88e4:	jmpq   ed87e6 <pfs_start_metadata_wait_v1+0xb6>
  ed88e9:	nopl   0x0(%rax)
  ed88f0:	addq   $0x1,0xfbce48(%rip)        # 1e95740 <global_metadata_stat>
  ed88f8:	add    $0x18,%rsp
  ed88fc:	xor    %eax,%eax
  ed88fe:	pop    %rbx
  ed88ff:	pop    %r12
  ed8901:	pop    %r13
  ed8903:	pop    %rbp
  ed8904:	retq   
  ed8905:	addq   $0x1,0xfbc733(%rip)        # 1e95040 <locker_lost>
  ed890d:	nopl   (%rax)
  ed8910:	add    $0x18,%rsp
  ed8914:	xor    %eax,%eax
  ed8916:	pop    %rbx
  ed8917:	pop    %r12
  ed8919:	pop    %r13
  ed891b:	pop    %rbp
  ed891c:	retq   
  ed891d:	nopl   (%rax)
