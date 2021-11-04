// TC_OUT g_on_error_query,0x1f5f8,0x1f5fc,0x0(%rdx)
000000000001f470 <g_on_error_query>:
   1f470:	push   %r12
   1f472:	push   %rbp
   1f473:	push   %rbx
   1f474:	mov    %rdi,%rbx
   1f477:	sub    $0x20,%rsp
   1f47b:	mov    %fs:0x28,%rax
   1f484:	mov    %rax,0x18(%rsp)
   1f489:	xor    %eax,%eax
   1f48b:	test   %rdi,%rdi
   1f48e:	je     1f62c <g_on_error_query+0x1bc>
   1f494:	mov    0x2edaa5(%rip),%rbp        # 30cf40 <g_utf8_skip+0x368>
   1f49b:	mov    %rsp,%r12
   1f49e:	jmp    1f4b4 <g_on_error_query+0x44>
   1f4a0:	cmpb   $0xa,0x1(%rsp)
   1f4a5:	je     1f639 <g_on_error_query+0x1c9>
   1f4ab:	test   %rbx,%rbx
   1f4ae:	je     1f5d8 <g_on_error_query+0x168>
   1f4b4:	test   %rbx,%rbx
   1f4b7:	je     1f5a0 <g_on_error_query+0x130>
   1f4bd:	callq  19c40 <getpid@plt>
   1f4c2:	mov    %eax,%r8d
   1f4c5:	lea    0x72fbe(%rip),%rax        # 9248a <_fini+0xf5e>
   1f4cc:	lea    0x72fa1(%rip),%rdx        # 92474 <_fini+0xf48>
   1f4d3:	lea    0x72f8b(%rip),%r9        # 92465 <_fini+0xf39>
   1f4da:	mov    %rbx,%rcx
   1f4dd:	mov    $0x1,%esi
   1f4e2:	push   %rax
   1f4e3:	lea    0x72fae(%rip),%rax        # 92498 <_fini+0xf6c>
   1f4ea:	push   %rax
   1f4eb:	mov    0x0(%rbp),%rdi
   1f4ef:	xor    %eax,%eax
   1f4f1:	callq  1a580 <__fprintf_chk@plt>
   1f4f6:	pop    %rdx
   1f4f7:	pop    %rcx
   1f4f8:	mov    0x0(%rbp),%rdi
   1f4fc:	callq  1a1c0 <fflush@plt>
   1f501:	xor    %edi,%edi
   1f503:	callq  19ba0 <isatty@plt>
   1f508:	test   %eax,%eax
   1f50a:	je     1f51e <g_on_error_query+0xae>
   1f50c:	mov    $0x1,%edi
   1f511:	callq  19ba0 <isatty@plt>
   1f516:	test   %eax,%eax
   1f518:	jne    1f610 <g_on_error_query+0x1a0>
   1f51e:	mov    $0xa45,%eax
   1f523:	movb   $0x0,0x2(%r12)
   1f529:	mov    %ax,(%r12)
   1f52e:	movzbl (%rsp),%edx
   1f532:	and    $0xffffffdf,%edx
   1f535:	cmp    $0x45,%dl
   1f538:	je     1f4a0 <g_on_error_query+0x30>
   1f53e:	cmp    $0x50,%dl
   1f541:	jne    1f570 <g_on_error_query+0x100>
   1f543:	cmpb   $0xa,0x1(%rsp)
   1f548:	jne    1f4ab <g_on_error_query+0x3b>
   1f54e:	mov    0x18(%rsp),%rax
   1f553:	xor    %fs:0x28,%rax
   1f55c:	jne    1f640 <g_on_error_query+0x1d0>
   1f562:	add    $0x20,%rsp
   1f566:	pop    %rbx
   1f567:	pop    %rbp
   1f568:	pop    %r12
   1f56a:	retq   
   1f56b:	nopl   0x0(%rax,%rax,1)
   1f570:	test   %rbx,%rbx
   1f573:	je     1f5d8 <g_on_error_query+0x168>
   1f575:	cmp    $0x53,%dl
   1f578:	jne    1f5d8 <g_on_error_query+0x168>
   1f57a:	cmpb   $0xa,0x1(%rsp)
   1f57f:	jne    1f4b4 <g_on_error_query+0x44>
   1f585:	mov    %rbx,%rdi
   1f588:	callq  1f3a0 <g_on_error_stack_trace>
   1f58d:	test   %rbx,%rbx
   1f590:	jne    1f4bd <g_on_error_query+0x4d>
   1f596:	nopw   %cs:0x0(%rax,%rax,1)
   1f5a0:	callq  19c40 <getpid@plt>
   1f5a5:	mov    0x0(%rbp),%rdi
   1f5a9:	lea    0x72eda(%rip),%r9        # 9248a <_fini+0xf5e>
   1f5b0:	lea    0x72eae(%rip),%r8        # 92465 <_fini+0xf39>
   1f5b7:	lea    0x72eef(%rip),%rdx        # 924ad <_fini+0xf81>
   1f5be:	mov    %eax,%ecx
   1f5c0:	mov    $0x1,%esi
   1f5c5:	xor    %eax,%eax
   1f5c7:	callq  1a580 <__fprintf_chk@plt>
   1f5cc:	jmpq   1f4f8 <g_on_error_query+0x88>
   1f5d1:	nopl   0x0(%rax)
   1f5d8:	cmp    $0x48,%dl
   1f5db:	jne    1f4b4 <g_on_error_query+0x44>
   1f5e1:	cmpb   $0xa,0x1(%rsp)
   1f5e6:	jne    1f4b4 <g_on_error_query+0x44>
   1f5ec:	mov    0x2ed965(%rip),%rdx        # 30cf58 <g_utf8_skip+0x380>
   1f5f3:	nopl   0x0(%rax,%rax,1)
   1f5f8:	mov    (%rdx),%eax
   1f5fa:	test   %eax,%eax
   1f5fc:	jne    1f5f8 <g_on_error_query+0x188>
   1f5fe:	movl   $0x1,(%rdx)
   1f604:	jmpq   1f54e <g_on_error_query+0xde>
   1f609:	nopl   0x0(%rax)
   1f610:	mov    0x2ed939(%rip),%rax        # 30cf50 <g_utf8_skip+0x378>
   1f617:	mov    $0x8,%esi
   1f61c:	mov    %r12,%rdi
   1f61f:	mov    (%rax),%rdx
   1f622:	callq  19f90 <fgets@plt>
   1f627:	jmpq   1f52e <g_on_error_query+0xbe>
   1f62c:	callq  7cdd0 <g_get_prgname>
   1f631:	mov    %rax,%rbx
   1f634:	jmpq   1f494 <g_on_error_query+0x24>
   1f639:	xor    %edi,%edi
   1f63b:	callq  19b30 <_exit@plt>
   1f640:	callq  19d50 <__stack_chk_fail@plt>
   1f645:	nopw   %cs:0x0(%rax,%rax,1)
   1f64f:	nop
