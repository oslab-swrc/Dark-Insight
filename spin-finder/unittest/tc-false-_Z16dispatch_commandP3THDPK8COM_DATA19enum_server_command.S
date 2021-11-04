// TC_OUT
0000000000c951f0 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command>:
  c951f0:	push   %rbp
  c951f1:	mov    %rsp,%rbp
  c951f4:	push   %r15
  c951f6:	push   %r14
  c951f8:	mov    %edx,%r14d
  c951fb:	push   %r13
  c951fd:	push   %r12
  c951ff:	push   %rbx
  c95200:	mov    %rdi,%rbx
  c95203:	sub    $0xc68,%rsp
  c9520a:	mov    %rsi,-0xc20(%rbp)
  c95211:	lea    0x680d61(%rip),%rsi        # 1315f79 <_IO_stdin_used+0xd39>
  c95218:	mov    %fs:0x28,%rax
  c95221:	mov    %rax,-0x38(%rbp)
  c95225:	xor    %eax,%eax
  c95227:	lea    0x1188a12(%rip),%rax        # 1e1dc40 <_ZN18Global_THD_manager11thd_managerE>
  c9522e:	mov    %edx,-0xc04(%rbp)
  c95234:	mov    (%rax),%r13
  c95237:	lea    0x1bc0(%rdi),%rax
  c9523e:	mov    %rax,%rdi
  c95241:	mov    %rax,-0xc18(%rbp)
  c95248:	callq  cc0950 <_ZN9PROFILING15start_new_queryEPKc>
  c9524d:	mov    0x1040(%rbx),%rax
  c95254:	lea    0xa0(%rax),%rdx
  c9525b:	nop
  c9525c:	lea    0x118351d(%rip),%rcx        # 1e18780 <com_statement_info>
  c95263:	movslq %r14d,%rax
  c95266:	lea    (%rax,%rax,2),%rax
  c9526a:	mov    (%rcx,%rax,8),%esi
  c9526d:	mov    0x1c58(%rbx),%rax
  c95274:	test   %rax,%rax
  c95277:	je     c95281 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x91>
  c95279:	mov    %rax,%rdi
  c9527c:	callq  ed9e40 <pfs_refine_statement_v1>
  c95281:	mov    -0xc04(%rbp),%esi
  c95287:	mov    %rax,0x1c58(%rbx)
  c9528e:	mov    %rbx,%rdi
  c95291:	callq  c52230 <_ZN3THD11set_commandE19enum_server_command>
  c95296:	mov    0x1c8(%rbx),%rax
  c9529d:	movb   $0x1,0x1f46(%rbx)
  c952a4:	movl   $0x8c,0x8(%rax)
  c952ab:	callq  eb51c0 <my_micro_time>
  c952b0:	cmpq   $0x0,0x12d0(%rbx)
  c952b8:	mov    %rax,%rcx
  c952bb:	mov    %rax,0x12f0(%rbx)
  c952c2:	mov    %rax,0x12e8(%rbx)
  c952c9:	jne    c95308 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x118>
  c952cb:	cmpq   $0x0,0x12d8(%rbx)
  c952d3:	jne    c95308 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x118>
  c952d5:	movabs $0x431bde82d7b634db,%rdx
  c952df:	mul    %rdx
  c952e2:	shr    $0x12,%rdx
  c952e6:	imul   $0xf4240,%rdx,%rax
  c952ed:	mov    %rdx,0x12c0(%rbx)
  c952f4:	mov    %rdx,%rdi
  c952f7:	sub    %rax,%rcx
  c952fa:	mov    %rcx,0x12c8(%rbx)
  c95301:	jmp    c95327 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x137>
  c95303:	nopl   0x0(%rax,%rax,1)
  c95308:	mov    0x12d0(%rbx),%rax
  c9530f:	mov    0x12d8(%rbx),%rdx
  c95316:	mov    %rax,%rdi
  c95319:	mov    %rax,0x12c0(%rbx)
  c95320:	mov    %rdx,0x12c8(%rbx)
  c95327:	callq  ed6540 <pfs_set_thread_start_time_v1>
  c9532c:	mov    0x12c0(%rbx),%rax
  c95333:	mov    -0xc04(%rbp),%r12d
  c9533a:	sub    $0x1,%rax
  c9533e:	cmp    $0x7ffffffe,%rax
  c95344:	jbe    c95368 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x178>
  c95346:	mov    0x1040(%rbx),%rax
  c9534d:	mov    $0x8,%r12d
  c95353:	movl   $0x8,-0xc04(%rbp)
  c9535d:	orq    $0x80,0x200(%rax)
  c95368:	lea    0x1187fe9(%rip),%rax        # 1e1d358 <global_query_id>
  c9536f:	mov    $0x1,%r15d
  c95375:	lock xadd %r15,(%rax)
  c9537a:	mov    0xca0(%rbx),%rsi
  c95381:	add    $0x1,%r15
  c95385:	test   %rsi,%rsi
  c95388:	je     c95840 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x650>
  c9538e:	lea    -0xbc0(%rbp),%rax
  c95395:	lea    0x68b2a4(%rip),%rcx        # 1320640 <_ZTS11GRANT_TABLE+0x3ae>
  c9539c:	xor    %edx,%edx
  c9539e:	mov    $0x10a9,%r8d
  c953a4:	mov    %rax,%rdi
  c953a7:	callq  ed78e0 <pfs_start_mutex_wait_v1>
  c953ac:	mov    %rax,%r14
  c953af:	lea    0xc78(%rbx),%rax
  c953b6:	mov    %rax,%rdi
  c953b9:	mov    %rax,-0xc10(%rbp)
  c953c0:	callq  7620e0 <pthread_mutex_lock@plt>
  c953c5:	test   %r14,%r14
  c953c8:	je     c953d4 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1e4>
  c953ca:	mov    %eax,%esi
  c953cc:	mov    %r14,%rdi
  c953cf:	callq  ed8be0 <pfs_end_mutex_wait_v1>
  c953d4:	mov    0xca0(%rbx),%rdi
  c953db:	mov    %r15,0x1e78(%rbx)
  c953e2:	test   %rdi,%rdi
  c953e5:	je     c953ec <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1fc>
  c953e7:	callq  ed6140 <pfs_unlock_mutex_v1>
  c953ec:	mov    -0xc10(%rbp),%rdi
  c953f3:	callq  762030 <pthread_mutex_unlock@plt>
  c953f8:	cmpb   $0x0,0x244(%rbx)
  c953ff:	jne    c957b0 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x5c0>
  c95405:	lea    0x2048(%r13),%rax
  c9540c:	mov    %rax,-0xc28(%rbp)
  c95413:	lock addl $0x1,(%rax)
  c95417:	lea    0x1199a82(%rip),%r13        # 1e2eea0 <server_command_flags>
  c9541e:	movslq %r12d,%r15
  c95421:	testb  $0x2,0x0(%r13,%r15,4)
  c95427:	jne    c95431 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x241>
  c95429:	addq   $0x1,0x7c8(%rbx)
  c95431:	mov    0x1100(%rbx),%rdi
  c95438:	andl   $0xffffb207,0x1eb0(%rbx)
  c95442:	mov    (%rdi),%rax
  c95445:	callq  *0x10(%rax)
  c95448:	cmp    $0x4,%eax
  c9544b:	je     c957f0 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x600>
  c95451:	mov    0x1040(%rbx),%rax
  c95458:	cmpb   $0x0,0x210(%rax)
  c9545f:	je     c954b8 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x2c8>
  c95461:	mov    -0xc04(%rbp),%eax
  c95467:	sub    $0x18,%eax
  c9546a:	cmp    $0x1,%eax
  c9546d:	jbe    c954b8 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x2c8>
  c9546f:	cmpl   $0xe,-0xc04(%rbp)
  c95476:	je     c954b8 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x2c8>
  c95478:	mov    -0xc04(%rbp),%eax
  c9547e:	and    $0xfffffffd,%eax
  c95481:	cmp    $0x1,%eax
  c95484:	je     c954b8 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x2c8>
  c95486:	xor    %eax,%eax
  c95488:	xor    %esi,%esi
  c9548a:	mov    $0x71c,%edi
  c9548f:	callq  eb3d90 <my_error>
  c95494:	shl    $0x4,%r15
  c95498:	add    0x10d8aa1(%rip),%r15        # 1d6df40 <_DYNAMIC+0x358>
  c9549f:	lea    -0xbc0(%rbp),%rax
  c954a6:	xor    %r13d,%r13d
  c954a9:	mov    %rax,-0xc20(%rbp)
  c954b0:	mov    (%r15),%r12
  c954b3:	jmp    c9550a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x31a>
  c954b5:	nopl   (%rax)
  c954b8:	shl    $0x4,%r15
  c954bc:	add    0x10d8a7d(%rip),%r15        # 1d6df40 <_DYNAMIC+0x358>
  c954c3:	mov    -0xc04(%rbp),%ecx
  c954c9:	lea    0x8a43ae(%rip),%rdx        # 153987e <_ZTS8COND_CMP+0x1ac>
  c954d0:	mov    $0x1,%esi
  c954d5:	mov    %rbx,%rdi
  c954d8:	mov    (%r15),%rax
  c954db:	mov    %rax,%r8
  c954de:	mov    %rax,-0xc30(%rbp)
  c954e5:	callq  7a4df0 <_Z18mysql_audit_notifyP3THD30mysql_event_command_subclass_tPKc19enum_server_commandS3_>
  c954ea:	test   %eax,%eax
  c954ec:	je     c956d8 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x4e8>
  c954f2:	lea    -0xbc0(%rbp),%rax
  c954f9:	mov    -0xc30(%rbp),%r12
  c95500:	xor    %r13d,%r13d
  c95503:	mov    %rax,-0xc20(%rbp)
  c9550a:	callq  eb51c0 <my_micro_time>
  c9550f:	mov    0x358(%rbx),%rdx
  c95516:	add    0x12f0(%rbx),%rdx
  c9551d:	cmp    %rdx,%rax
  c95520:	jbe    c9552c <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x33c>
  c95522:	orl    $0x800,0x1eb0(%rbx)
  c9552c:	mov    0x1f1c(%rbx),%eax
  c95532:	test   %eax,%eax
  c95534:	jne    c95740 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x550>
  c9553a:	mov    %rbx,%rdi
  c9553d:	callq  c52dd0 <_ZN3THD21send_statement_statusEv>
  c95542:	mov    0x20f0(%rbx),%rax
  c95549:	lea    0x20f0(%rbx),%rdi
  c95550:	mov    %rbx,%rsi
  c95553:	callq  *0x10(%rax)
  c95556:	lea    0x1184c03(%rip),%rdi        # 1e1a160 <query_cache>
  c9555d:	mov    %rbx,%rsi
  c95560:	callq  c46c30 <_ZN11Query_cache13end_of_resultEP3THD>
  c95565:	mov    0x3478(%rbx),%rax
  c9556c:	cmpl   $0x3,0x94(%rax)
  c95573:	je     c95720 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x530>
  c95579:	mov    0x1f1c(%rbx),%eax
  c9557f:	cmp    $0x1,%eax
  c95582:	jbe    c956f8 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x508>
  c95588:	xor    %r14d,%r14d
  c9558b:	test   %r12,%r12
  c9558e:	je     c95730 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x540>
  c95594:	mov    %r12,%rdi
  c95597:	callq  762340 <strlen@plt>
  c9559c:	mov    %rax,%r8
  c9559f:	mov    %r12,%rcx
  c955a2:	mov    %r14d,%edx
  c955a5:	mov    $0x8,%esi
  c955aa:	mov    %rbx,%rdi
  c955ad:	callq  7a3fb0 <_Z18mysql_audit_notifyP3THD30mysql_event_general_subclass_tiPKcm>
  c955b2:	mov    -0xc04(%rbp),%ecx
  c955b8:	lea    0x8a42a7(%rip),%rdx        # 1539866 <_ZTS8COND_CMP+0x194>
  c955bf:	mov    %r12,%r8
  c955c2:	mov    $0x2,%esi
  c955c7:	mov    %rbx,%rdi
  c955ca:	callq  7a4df0 <_Z18mysql_audit_notifyP3THD30mysql_event_command_subclass_tPKc19enum_server_commandS3_>
  c955cf:	mov    %rbx,%rdi
  c955d2:	callq  be5780 <_Z18log_slow_statementP3THD>
  c955d7:	lea    0x10df382(%rip),%rsi        # 1d74960 <stage_cleaning_up>
  c955de:	lea    0x8a43cb(%rip),%r8        # 15399b0 <_ZTS8COND_CMP+0x2de>
  c955e5:	lea    0x8a4984(%rip),%rcx        # 1539f70 <_ZZ16dispatch_commandP3THDPK8COM_DATA19enum_server_commandE8__func__>
  c955ec:	xor    %edx,%edx
  c955ee:	mov    $0x748,%r9d
  c955f4:	mov    %rbx,%rdi
  c955f7:	callq  c4bda0 <_ZN3THD11enter_stageEPK17PSI_stage_info_v1PS0_PKcS5_j>
  c955fc:	mov    -0xc20(%rbp),%rsi
  c95603:	mov    %rbx,%rdi
  c95606:	movq   $0x0,-0xbc0(%rbp)
  c95611:	movq   $0x0,-0xbb8(%rbp)
  c9561c:	callq  c52250 <_ZN3THD9set_queryERK25st_mysql_const_lex_string>
  c95621:	xor    %esi,%esi
  c95623:	mov    %rbx,%rdi
  c95626:	callq  c52230 <_ZN3THD11set_commandE19enum_server_command>
  c9562b:	mov    0x1c58(%rbx),%r12
  c95632:	mov    0x3478(%rbx),%r14
  c95639:	callq  ed9cb0 <pfs_end_stage_v1>
  c9563e:	test   %r12,%r12
  c95641:	je     c9564e <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x45e>
  c95643:	mov    %r14,%rsi
  c95646:	mov    %r12,%rdi
  c95649:	callq  edb9d0 <pfs_end_statement_v1>
  c9564e:	mov    -0xc28(%rbp),%rax
  c95655:	movq   $0x0,0x1c58(%rbx)
  c95660:	movq   $0x0,0x1c08(%rbx)
  c9566b:	lock subl $0x1,(%rax)
  c9566f:	mov    0x18(%rbx),%rdi
  c95673:	mov    $0x1,%esi
  c95678:	callq  eb1f50 <free_root>
  c9567d:	lea    0x11826a6(%rip),%rax        # 1e17d2a <mysql_query__done_semaphore>
  c95684:	cmpw   $0x0,(%rax)
  c95688:	jne    c96ffc <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1e0c>
  c9568e:	lea    0x1182691(%rip),%rax        # 1e17d26 <mysql_command__done_semaphore>
  c95695:	cmpw   $0x0,(%rax)
  c95699:	jne    c96fe5 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1df5>
  c9569f:	mov    -0xc18(%rbp),%rdi
  c956a6:	callq  cc07a0 <_ZN9PROFILING20finish_current_queryEv>
  c956ab:	mov    -0x38(%rbp),%rcx
  c956af:	xor    %fs:0x28,%rcx
  c956b8:	mov    %r13d,%eax
  c956bb:	jne    c96fb8 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1dc8>
  c956c1:	add    $0xc68,%rsp
  c956c8:	pop    %rbx
  c956c9:	pop    %r12
  c956cb:	pop    %r13
  c956cd:	pop    %r14
  c956cf:	pop    %r15
  c956d1:	pop    %rbp
  c956d2:	retq   
  c956d3:	nopl   0x0(%rax,%rax,1)
  c956d8:	cmp    $0x1f,%r12d
  c956dc:	ja     c96aef <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x18ff>
  c956e2:	lea    0x8a47d3(%rip),%rax        # 1539ebc <_ZTS8COND_CMP+0x7ea>
  c956e9:	movslq (%rax,%r12,4),%rdx
  c956ed:	add    %rdx,%rax
  c956f0:	jmpq   *%rax
  c956f2:	nopw   0x0(%rax,%rax,1)
  c956f8:	xor    %r8d,%r8d
  c956fb:	xor    %ecx,%ecx
  c956fd:	xor    %edx,%edx
  c956ff:	mov    $0x4,%esi
  c95704:	mov    %rbx,%rdi
  c95707:	callq  7a3fb0 <_Z18mysql_audit_notifyP3THD30mysql_event_general_subclass_tiPKcm>
  c9570c:	mov    0x3478(%rbx),%rax
  c95713:	cmpl   $0x3,0x94(%rax)
  c9571a:	jne    c95588 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x398>
  c95720:	test   %r12,%r12
  c95723:	mov    0x2a0(%rax),%r14d
  c9572a:	jne    c95594 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x3a4>
  c95730:	xor    %r8d,%r8d
  c95733:	jmpq   c9559f <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x3af>
  c95738:	nopl   0x0(%rax,%rax,1)
  c95740:	mov    0x1f1c(%rbx),%r14d
  c95747:	cmp    $0x1,%r14d
  c9574b:	je     c9553a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x34a>
  c95751:	test   %r14d,%r14d
  c95754:	mov    %r14d,%r15d
  c95757:	je     c9553a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x34a>
  c9575d:	mov    0x3478(%rbx),%rax
  c95764:	mov    0x94(%rax),%eax
  c9576a:	test   %eax,%eax
  c9576c:	jne    c9553a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x34a>
  c95772:	cmp    $0x41d,%r14d
  c95779:	je     c96bb0 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x19c0>
  c9577f:	lea    0x118547a(%rip),%rax        # 1e1ac00 <THR_THD>
  c95786:	mov    (%rax),%edi
  c95788:	callq  762c40 <pthread_getspecific@plt>
  c9578d:	mov    %r15d,%esi
  c95790:	mov    %rax,%rdi
  c95793:	callq  7c1920 <_Z6ER_THDPK3THDi>
  c95798:	mov    $0x400,%edx
  c9579d:	mov    %rax,%rsi
  c957a0:	mov    %r14d,%edi
  c957a3:	callq  eb4020 <my_message>
  c957a8:	jmpq   c9553a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x34a>
  c957ad:	nopl   (%rax)
  c957b0:	mov    0x228(%rbx),%rdi
  c957b7:	movb   $0x0,0x244(%rbx)
  c957be:	movl   $0x0,0x240(%rbx)
  c957c8:	callq  eb6000 <my_free>
  c957cd:	movq   $0x0,0x228(%rbx)
  c957d8:	movq   $0x0,0x230(%rbx)
  c957e3:	jmpq   c95405 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x215>
  c957e8:	nopl   0x0(%rax,%rax,1)
  c957f0:	testb  $0x1,0x2(%r13,%r15,4)
  c957f6:	jne    c95451 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x261>
  c957fc:	xor    %eax,%eax
  c957fe:	xor    %esi,%esi
  c95800:	mov    $0xc3a,%edi
  c95805:	callq  eb3d90 <my_error>
  c9580a:	shl    $0x4,%r15
  c9580e:	add    0x10d872b(%rip),%r15        # 1d6df40 <_DYNAMIC+0x358>
  c95815:	lea    -0xbc0(%rbp),%rax
  c9581c:	movl   $0x41d,0x1f1c(%rbx)
  c95826:	mov    $0x1,%r13d
  c9582c:	mov    %rax,-0xc20(%rbp)
  c95833:	mov    (%r15),%r12
  c95836:	jmpq   c9550a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x31a>
  c9583b:	nopl   0x0(%rax,%rax,1)
  c95840:	lea    0xc78(%rbx),%rax
  c95847:	mov    %rax,%rdi
  c9584a:	mov    %rax,-0xc10(%rbp)
  c95851:	callq  7620e0 <pthread_mutex_lock@plt>
  c95856:	jmpq   c953d4 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1e4>
  c9585b:	addq   $0x1,0x7d0(%rbx)
  c95863:	mov    %rbx,%rdi
  c95866:	callq  c50520 <_ZN3THD18cleanup_connectionEv>
  c9586b:	mov    0x3478(%rbx),%rdi
  c95872:	movq   $0x0,0x1b90(%rbx)
  c9587d:	xor    %ecx,%ecx
  c9587f:	xor    %edx,%edx
  c95881:	xor    %esi,%esi
  c95883:	xor    %r13d,%r13d
  c95886:	callq  c5e680 <_ZN16Diagnostics_area13set_ok_statusEyyPKc>
  c9588b:	lea    -0xbc0(%rbp),%rax
  c95892:	mov    -0xc30(%rbp),%r12
  c95899:	mov    %rax,-0xc20(%rbp)
  c958a0:	jmpq   c9550a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x31a>
  c958a5:	mov    -0xc04(%rbp),%edx
  c958ab:	lea    0x119534e(%rip),%rdi        # 1e2ac00 <query_logger>
  c958b2:	xor    %ecx,%ecx
  c958b4:	mov    %rbx,%rsi
  c958b7:	xor    %eax,%eax
  c958b9:	callq  be4aa0 <_ZN12Query_logger17general_log_printEP3THD19enum_server_commandPKcz>
  c958be:	mov    0x1100(%rbx),%rdi
  c958c5:	mov    (%rdi),%rax
  c958c8:	callq  *0x10(%rax)
  c958cb:	cmp    $0x1,%eax
  c958ce:	ja     c958e3 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x6f3>
  c958d0:	mov    0x1100(%rbx),%rdi
  c958d7:	callq  bfc9b0 <_ZN16Protocol_classic7get_netEv>
  c958dc:	movb   $0x0,0x94(%rax)
  c958e3:	mov    0x3478(%rbx),%rax
  c958ea:	mov    -0xc30(%rbp),%r12
  c958f1:	mov    $0x1,%r13d
  c958f7:	movl   $0x4,0x94(%rax)
  c95901:	lea    -0xbc0(%rbp),%rax
  c95908:	mov    %rax,-0xc20(%rbp)
  c9590f:	jmpq   c9550a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x31a>
  c95914:	mov    -0xc20(%rbp),%rax
  c9591b:	addq   $0x1,0x8f0(%rbx)
  c95923:	lea    -0xbf0(%rbp),%rsi
  c9592a:	mov    0x5a0(%rbx),%r9
  c95931:	mov    %rbx,%rdi
  c95934:	mov    0x8(%rax),%r8
  c95938:	mov    (%rax),%rcx
  c9593b:	lea    0x118535e(%rip),%rax        # 1e1aca0 <system_charset_info>
  c95942:	mov    (%rax),%rdx
  c95945:	callq  c4db00 <_ZN3THD14convert_stringEP19st_mysql_lex_stringPK15charset_info_stPKcmS4_>
  c9594a:	mov    -0xbf0(%rbp),%rax
  c95951:	xor    %edx,%edx
  c95953:	mov    %rbx,%rdi
  c95956:	mov    %rax,-0xbc0(%rbp)
  c9595d:	mov    -0xbe8(%rbp),%rax
  c95964:	mov    %rax,-0xbb8(%rbp)
  c9596b:	lea    -0xbc0(%rbp),%rax
  c95972:	mov    %rax,%rsi
  c95975:	mov    %rax,-0xc20(%rbp)
  c9597c:	callq  c5a230 <_Z15mysql_change_dbP3THDRK25st_mysql_const_lex_stringb>
  c95981:	test   %al,%al
  c95983:	je     c96cd2 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1ae2>
  c95989:	mov    -0xc30(%rbp),%r12
  c95990:	xor    %r13d,%r13d
  c95993:	jmpq   c9550a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x31a>
  c95998:	lea    0x1c18(%rbx),%rax
  c9599f:	mov    0x1c10(%rbx),%rdx
  c959a6:	movl   $0x0,0x1c18(%rbx)
  c959b0:	movb   $0x0,0x1c20(%rbx)
  c959b7:	movq   $0x0,0x1c28(%rbx)
  c959c2:	mov    %rbx,%rdi
  c959c5:	mov    %rax,0x1c08(%rbx)
  c959cc:	mov    %rax,-0xc40(%rbp)
  c959d3:	lea    0x1196406(%rip),%rax        # 1e2bde0 <max_digest_length>
  c959da:	mov    %rdx,0x1c48(%rbx)
  c959e1:	movl   $0x0,0x1c40(%rbx)
  c959eb:	movq   $0x0,0x1c30(%rbx)
  c959f6:	movq   $0x0,0x1c38(%rbx)
  c95a01:	mov    (%rax),%rax
  c95a04:	and    $0xffffffff,%eax
  c95a07:	mov    %rax,0x1c50(%rbx)
  c95a0e:	mov    -0xc20(%rbp),%rax
  c95a15:	mov    0x8(%rax),%edx
  c95a18:	mov    (%rax),%rsi
  c95a1b:	callq  c8c2e0 <_Z11alloc_queryP3THDPKcm>
  c95a20:	test   %al,%al
  c95a22:	jne    c954f2 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x302>
  c95a28:	mov    0x218(%rbx),%rdx
  c95a2f:	lea    0x896eba(%rip),%rax        # 152c8f0 <_ZTS24Query_result_materialize+0x180>
  c95a36:	mov    0x1d8(%rbx),%r12
  c95a3d:	test   %rdx,%rdx
  c95a40:	cmovne %rdx,%rax
  c95a44:	mov    0x1040(%rbx),%rdx
  c95a4b:	lea    0xa0(%rdx),%rcx
  c95a52:	nop
  c95a53:	lea    0x1187d3e(%rip),%rax        # 1e1d798 <opt_general_log_raw>
  c95a5a:	mov    0x1e0(%rbx),%r13
  c95a61:	mov    %r12,%rsi
  c95a64:	cmpb   $0x0,(%rax)
  c95a67:	mov    %r13,%rdx
  c95a6a:	jne    c96e8b <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1c9b>
  c95a70:	mov    -0xc18(%rbp),%rdi
  c95a77:	callq  cc0f50 <_ZN9PROFILING16set_query_sourceEPKcm>
  c95a7c:	mov    0x1c58(%rbx),%rdi
  c95a83:	mov    0x1e0(%rbx),%rdx
  c95a8a:	mov    0x1d8(%rbx),%rsi
  c95a91:	test   %rdi,%rdi
  c95a94:	je     c95aa9 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x8b9>
  c95a96:	callq  eda870 <pfs_set_statement_text_v1>
  c95a9b:	mov    0x1d8(%rbx),%rsi
  c95aa2:	mov    0x1e0(%rbx),%rdx
  c95aa9:	lea    -0xbb8(%rbp),%rdi
  c95ab0:	xor    %eax,%eax
  c95ab2:	mov    $0x1d,%ecx
  c95ab7:	movb   $0x0,-0xbc0(%rbp)
  c95abe:	movb   $0x0,-0xaa0(%rbp)
  c95ac5:	rep stos %rax,%es:(%rdi)
  c95ac8:	lea    -0xbc0(%rbp),%rax
  c95acf:	mov    %rdx,%rcx
  c95ad2:	mov    %rsi,%rdx
  c95ad5:	mov    %rbx,%rsi
  c95ad8:	movq   $0x0,-0xad0(%rbp)
  c95ae3:	movq   $0x0,-0xac8(%rbp)
  c95aee:	lea    0x8(%rax),%rdi
  c95af2:	movq   $0x0,-0xac0(%rbp)
  c95afd:	movl   $0x1,-0xab8(%rbp)
  c95b07:	movl   $0x3,-0xab4(%rbp)
  c95b11:	movl   $0x0,-0xab0(%rbp)
  c95b1b:	mov    %rax,-0xc20(%rbp)
  c95b22:	callq  c6bb50 <_ZN16Lex_input_stream4initEP3THDPKcm>
  c95b27:	test   %al,%al
  c95b29:	jne    c96e7c <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1c8c>
  c95b2f:	mov    -0xc20(%rbp),%rsi
  c95b36:	mov    %rbx,%rdi
  c95b39:	callq  c94dc0 <_Z11mysql_parseP3THDP12Parser_state>
  c95b3e:	lea    (%r12,%r13,1),%rax
  c95b42:	mov    %rax,-0xc48(%rbp)
  c95b49:	lea    0x1c60(%rbx),%rax
  c95b50:	mov    %rax,-0xc50(%rbp)
  c95b57:	lea    -0xc00(%rbp),%rax
  c95b5e:	mov    %rax,-0xc58(%rbp)
  c95b65:	lea    -0xbf0(%rbp),%rax
  c95b6c:	mov    %rax,-0xc60(%rbp)
  c95b73:	nopl   0x0(%rax,%rax,1)
  c95b78:	mov    0x1f1c(%rbx),%eax
  c95b7e:	test   %eax,%eax
  c95b80:	jne    c96b68 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1978>
  c95b86:	mov    -0xb08(%rbp),%r14
  c95b8d:	test   %r14,%r14
  c95b90:	je     c96b68 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1978>
  c95b96:	mov    0x3478(%rbx),%rax
  c95b9d:	cmpl   $0x3,0x94(%rax)
  c95ba4:	je     c96b68 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1978>
  c95baa:	callq  eb51c0 <my_micro_time>
  c95baf:	mov    0x358(%rbx),%rdx
  c95bb6:	add    0x12f0(%rbx),%rdx
  c95bbd:	cmp    %rdx,%rax
  c95bc0:	jbe    c95bcc <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x9dc>
  c95bc2:	orl    $0x800,0x1eb0(%rbx)
  c95bcc:	mov    %rbx,%rdi
  c95bcf:	callq  c52dd0 <_ZN3THD21send_statement_statusEv>
  c95bd4:	lea    0x1184585(%rip),%rdi        # 1e1a160 <query_cache>
  c95bdb:	mov    %rbx,%rsi
  c95bde:	callq  c46c30 <_ZN11Query_cache13end_of_resultEP3THD>
  c95be3:	mov    0x3478(%rbx),%rax
  c95bea:	xor    %r12d,%r12d
  c95bed:	cmpl   $0x3,0x94(%rax)
  c95bf4:	je     c96ba0 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x19b0>
  c95bfa:	mov    -0xc30(%rbp),%rdi
  c95c01:	test   %rdi,%rdi
  c95c04:	je     c96be9 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x19f9>
  c95c0a:	callq  762340 <strlen@plt>
  c95c0f:	mov    %rax,%r8
  c95c12:	mov    -0xc30(%rbp),%rcx
  c95c19:	mov    %r12d,%edx
  c95c1c:	mov    $0x8,%esi
  c95c21:	mov    %rbx,%rdi
  c95c24:	callq  7a3fb0 <_Z18mysql_audit_notifyP3THD30mysql_event_general_subclass_tiPKcm>
  c95c29:	mov    -0xc48(%rbp),%r15
  c95c30:	mov    %rbx,%rdi
  c95c33:	sub    %r14,%r15
  c95c36:	callq  be5780 <_Z18log_slow_statementP3THD>
  c95c3b:	test   %r15,%r15
  c95c3e:	je     c95c70 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0xa80>
  c95c40:	mov    0x5a0(%rbx),%rax
  c95c47:	movzbl (%r14),%edx
  c95c4b:	mov    0x30(%rax),%rax
  c95c4f:	testb  $0x8,0x1(%rax,%rdx,1)
  c95c54:	je     c95c70 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0xa80>
  c95c56:	add    $0x1,%r14
  c95c5a:	sub    $0x1,%r15
  c95c5e:	je     c95c70 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0xa80>
  c95c60:	movzbl (%r14),%edx
  c95c64:	testb  $0x8,0x1(%rax,%rdx,1)
  c95c69:	jne    c95c56 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0xa66>
  c95c6b:	nopl   0x0(%rax,%rax,1)
  c95c70:	mov    0x3478(%rbx),%r13
  c95c77:	mov    0x1c58(%rbx),%r12
  c95c7e:	callq  ed9cb0 <pfs_end_stage_v1>
  c95c83:	test   %r12,%r12
  c95c86:	je     c95c93 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0xaa3>
  c95c88:	mov    %r13,%rsi
  c95c8b:	mov    %r12,%rdi
  c95c8e:	callq  edb9d0 <pfs_end_statement_v1>
  c95c93:	lea    0x1182090(%rip),%rax        # 1e17d2a <mysql_query__done_semaphore>
  c95c9a:	movq   $0x0,0x1c58(%rbx)
  c95ca5:	movq   $0x0,0x1c08(%rbx)
  c95cb0:	cmpw   $0x0,(%rax)
  c95cb4:	jne    c970c3 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1ed3>
  c95cba:	mov    -0xc18(%rbp),%r13
  c95cc1:	mov    %r13,%rdi
  c95cc4:	callq  cc07a0 <_ZN9PROFILING20finish_current_queryEv>
  c95cc9:	lea    0x8a3b07(%rip),%rsi        # 15397d7 <_ZTS8COND_CMP+0x105>
  c95cd0:	mov    %r13,%rdi
  c95cd3:	callq  cc0950 <_ZN9PROFILING15start_new_queryEPKc>
  c95cd8:	mov    %r15,%rdx
  c95cdb:	mov    %r14,%rsi
  c95cde:	mov    %r13,%rdi
  c95ce1:	callq  cc0f50 <_ZN9PROFILING16set_query_sourceEPKcm>
  c95ce6:	mov    0x218(%rbx),%r13
  c95ced:	mov    0x1040(%rbx),%rdx
  c95cf4:	lea    0x896bf5(%rip),%rax        # 152c8f0 <_ZTS24Query_result_materialize+0x180>
  c95cfb:	test   %r13,%r13
  c95cfe:	lea    0xa0(%rdx),%rcx
  c95d05:	cmovne %r13,%rax
  c95d09:	nop
  c95d0a:	mov    -0xc40(%rbp),%rax
  c95d11:	mov    0x5a0(%rbx),%rdx
  c95d18:	xor    %ecx,%ecx
  c95d1a:	mov    -0xc50(%rbp),%rdi
  c95d21:	mov    %rax,0x1c08(%rbx)
  c95d28:	mov    0x220(%rbx),%rax
  c95d2f:	mov    %rax,-0xc38(%rbp)
  c95d36:	lea    0x1182a43(%rip),%rax        # 1e18780 <com_statement_info>
  c95d3d:	mov    0x48(%rax),%esi
  c95d40:	callq  ed9ed0 <pfs_get_thread_statement_locker_v1>
  c95d45:	test   %rax,%rax
  c95d48:	mov    %rax,%r12
  c95d4b:	je     c95d6b <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0xb7b>
  c95d4d:	mov    -0xc38(%rbp),%edx
  c95d53:	lea    0x8a3c56(%rip),%rcx        # 15399b0 <_ZTS8COND_CMP+0x2de>
  c95d5a:	mov    $0x5d7,%r8d
  c95d60:	mov    %r13,%rsi
  c95d63:	mov    %rax,%rdi
  c95d66:	callq  ed75b0 <pfs_start_statement_v1>
  c95d6b:	lea    0x10de02e(%rip),%rsi        # 1d73da0 <stage_starting>
  c95d72:	lea    0x8a3c37(%rip),%r8        # 15399b0 <_ZTS8COND_CMP+0x2de>
  c95d79:	lea    0x8a41f0(%rip),%rcx        # 1539f70 <_ZZ16dispatch_commandP3THDPK8COM_DATA19enum_server_commandE8__func__>
  c95d80:	mov    %r12,0x1c58(%rbx)
  c95d87:	mov    $0x5d8,%r9d
  c95d8d:	xor    %edx,%edx
  c95d8f:	mov    %rbx,%rdi
  c95d92:	callq  c4bda0 <_ZN3THD11enter_stageEPK17PSI_stage_info_v1PS0_PKcS5_j>
  c95d97:	mov    0x1c58(%rbx),%rdi
  c95d9e:	test   %rdi,%rdi
  c95da1:	je     c95dae <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0xbbe>
  c95da3:	mov    %r15d,%edx
  c95da6:	mov    %r14,%rsi
  c95da9:	callq  eda870 <pfs_set_statement_text_v1>
  c95dae:	mov    -0xc58(%rbp),%rsi
  c95db5:	mov    %rbx,%rdi
  c95db8:	mov    %r14,-0xc00(%rbp)
  c95dbf:	mov    %r15,-0xbf8(%rbp)
  c95dc6:	callq  c52250 <_ZN3THD9set_queryERK25st_mysql_const_lex_string>
  c95dcb:	lea    0x1187586(%rip),%rax        # 1e1d358 <global_query_id>
  c95dd2:	mov    $0x1,%r12d
  c95dd8:	lock xadd %r12,(%rax)
  c95ddd:	mov    0xca0(%rbx),%rsi
  c95de4:	add    $0x1,%r12
  c95de8:	test   %rsi,%rsi
  c95deb:	je     c96bd8 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x19e8>
  c95df1:	mov    -0xc60(%rbp),%rdi
  c95df8:	lea    0x68a841(%rip),%rcx        # 1320640 <_ZTS11GRANT_TABLE+0x3ae>
  c95dff:	mov    $0x10a9,%r8d
  c95e05:	xor    %edx,%edx
  c95e07:	callq  ed78e0 <pfs_start_mutex_wait_v1>
  c95e0c:	mov    -0xc10(%rbp),%rdi
  c95e13:	mov    %rax,%r13
  c95e16:	callq  7620e0 <pthread_mutex_lock@plt>
  c95e1b:	test   %r13,%r13
  c95e1e:	je     c95e2a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0xc3a>
  c95e20:	mov    %eax,%esi
  c95e22:	mov    %r13,%rdi
  c95e25:	callq  ed8be0 <pfs_end_mutex_wait_v1>
  c95e2a:	mov    0xca0(%rbx),%rdi
  c95e31:	mov    %r12,0x1e78(%rbx)
  c95e38:	test   %rdi,%rdi
  c95e3b:	je     c95e42 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0xc52>
  c95e3d:	callq  ed6140 <pfs_unlock_mutex_v1>
  c95e42:	mov    -0xc10(%rbp),%rdi
  c95e49:	callq  762030 <pthread_mutex_unlock@plt>
  c95e4e:	addq   $0x1,0x7c8(%rbx)
  c95e56:	callq  eb51c0 <my_micro_time>
  c95e5b:	cmpq   $0x0,0x12d0(%rbx)
  c95e63:	mov    %rax,%rcx
  c95e66:	mov    %rax,0x12f0(%rbx)
  c95e6d:	mov    %rax,0x12e8(%rbx)
  c95e74:	jne    c96b40 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1950>
  c95e7a:	cmpq   $0x0,0x12d8(%rbx)
  c95e82:	jne    c96b40 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1950>
  c95e88:	movabs $0x431bde82d7b634db,%rdx
  c95e92:	mul    %rdx
  c95e95:	shr    $0x12,%rdx
  c95e99:	imul   $0xf4240,%rdx,%rax
  c95ea0:	mov    %rdx,0x12c0(%rbx)
  c95ea7:	mov    %rdx,%rdi
  c95eaa:	sub    %rax,%rcx
  c95ead:	mov    %rcx,0x12c8(%rbx)
  c95eb4:	callq  ed6540 <pfs_set_thread_start_time_v1>
  c95eb9:	mov    -0xc20(%rbp),%r13
  c95ec0:	mov    %r15,%rdx
  c95ec3:	mov    %r14,%rsi
  c95ec6:	lea    0x8(%r13),%rdi
  c95eca:	callq  c6ba70 <_ZN16Lex_input_stream5resetEPKcm>
  c95ecf:	mov    %r13,%rsi
  c95ed2:	mov    %rbx,%rdi
  c95ed5:	movq   $0x0,-0xad0(%rbp)
  c95ee0:	movq   $0x0,-0xac8(%rbp)
  c95eeb:	movq   $0x0,-0xac0(%rbp)
  c95ef6:	movl   $0x1,-0xab8(%rbp)
  c95f00:	movl   $0x3,-0xab4(%rbp)
  c95f0a:	movl   $0x0,-0xab0(%rbp)
  c95f14:	callq  c94dc0 <_Z11mysql_parseP3THDP12Parser_state>
  c95f19:	jmpq   c95b78 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x988>
  c95f1e:	lea    0x8a38e8(%rip),%rdx        # 153980d <_ZTS8COND_CMP+0x13b>
  c95f25:	lea    0x8a38f1(%rip),%rsi        # 153981d <_ZTS8COND_CMP+0x14b>
  c95f2c:	mov    %rbx,%rdi
  c95f2f:	callq  c5ef20 <_Z20push_deprecated_warnP3THDPKcS2_>
  c95f34:	mov    %rbx,%rdi
  c95f37:	callq  c72d60 <_Z9lex_startP3THD>
  c95f3c:	addq   $0x1,0x960(%rbx)
  c95f44:	mov    -0xc20(%rbp),%rax
  c95f4b:	mov    %rbx,%rdi
  c95f4e:	movzbl (%rax),%r12d
  c95f52:	callq  d37190 <_Z21trans_commit_implicitP3THD>
  c95f57:	test   %al,%al
  c95f59:	je     c96c2a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1a3a>
  c95f5f:	lea    -0xbc0(%rbp),%rax
  c95f66:	mov    %rax,-0xc20(%rbp)
  c95f6d:	jmpq   c95989 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x799>
  c95f72:	mov    -0xc04(%rbp),%edx
  c95f78:	lea    0x1194c81(%rip),%rdi        # 1e2ac00 <query_logger>
  c95f7f:	xor    %ecx,%ecx
  c95f81:	mov    %rbx,%rsi
  c95f84:	xor    %eax,%eax
  c95f86:	callq  be4aa0 <_ZN12Query_logger17general_log_printEP3THD19enum_server_commandPKcz>
  c95f8b:	lea    0x1184c2e(%rip),%r12        # 1e1abc0 <LOCK_status>
  c95f92:	addq   $0x1,0x858(%rbx)
  c95f9a:	mov    0x28(%r12),%rsi
  c95f9f:	test   %rsi,%rsi
  c95fa2:	je     c96eb9 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1cc9>
  c95fa8:	lea    -0xbc0(%rbp),%rax
  c95faf:	lea    0x8a39fa(%rip),%rcx        # 15399b0 <_ZTS8COND_CMP+0x2de>
  c95fb6:	xor    %edx,%edx
  c95fb8:	mov    $0x6c4,%r8d
  c95fbe:	mov    %rax,%rdi
  c95fc1:	mov    %rax,-0xc20(%rbp)
  c95fc8:	callq  ed78e0 <pfs_start_mutex_wait_v1>
  c95fcd:	mov    %r12,%rdi
  c95fd0:	mov    %rax,%r13
  c95fd3:	callq  7620e0 <pthread_mutex_lock@plt>
  c95fd8:	test   %r13,%r13
  c95fdb:	je     c95fe7 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0xdf7>
  c95fdd:	mov    %eax,%esi
  c95fdf:	mov    %r13,%rdi
  c95fe2:	callq  ed8be0 <pfs_end_mutex_wait_v1>
  c95fe7:	mov    -0xc20(%rbp),%rdi
  c95fee:	callq  cde3d0 <_Z22calc_sum_of_all_statusP17system_status_var>
  c95ff3:	mov    0x28(%r12),%rdi
  c95ff8:	test   %rdi,%rdi
  c95ffb:	je     c96002 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0xe12>
  c95ffd:	callq  ed6140 <pfs_unlock_mutex_v1>
  c96002:	mov    %r12,%rdi
  c96005:	callq  762030 <pthread_mutex_unlock@plt>
  c9600a:	lea    0x118723f(%rip),%rax        # 1e1d250 <server_start_time>
  c96011:	mov    0x12c0(%rbx),%rcx
  c96018:	sub    (%rax),%rcx
  c9601b:	mov    %rcx,%r15
  c9601e:	je     c96bf1 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1a01>
  c96024:	mov    0x1e78(%rbx),%rdx
  c9602b:	imul   $0x3e8,%rdx,%rax
  c96032:	xor    %edx,%edx
  c96034:	div    %rcx
  c96037:	movabs $0x20c49ba5e353f7cf,%rdx
  c96041:	mov    %rax,%r13
  c96044:	shr    $0x3,%rax
  c96048:	mul    %rdx
  c9604b:	shr    $0x4,%rdx
  c9604f:	imul   $0x3e8,%rdx,%rax
  c96056:	mov    %edx,%r12d
  c96059:	sub    %eax,%r13d
  c9605c:	lea    0x11b405d(%rip),%rdi        # 1e4a0c0 <table_cache_manager>
  c96063:	lea    -0x5c0(%rbp),%r14
  c9606a:	callq  d33d90 <_ZN19Table_cache_manager13cached_tablesEv>
  c9606f:	mov    0x1e78(%rbx),%r9
  c96076:	mov    %eax,0x18(%rsp)
  c9607a:	lea    0x8a3b37(%rip),%rdx        # 1539bb8 <_ZTS8COND_CMP+0x4e6>
  c96081:	lea    0x11872d8(%rip),%rax        # 1e1d360 <refresh_version>
  c96088:	mov    %r13d,0x28(%rsp)
  c9608d:	mov    %r15,%rcx
  c96090:	mov    %r12d,0x20(%rsp)
  c96095:	mov    $0xf9,%esi
  c9609a:	mov    %r14,%rdi
  c9609d:	lea    0x8a3728(%rip),%r12        # 15397cc <_ZTS8COND_CMP+0xfa>
  c960a4:	xor    %r13d,%r13d
  c960a7:	mov    (%rax),%rax
  c960aa:	mov    %rax,0x10(%rsp)
  c960af:	mov    -0xb20(%rbp),%rax
  c960b6:	mov    %rax,0x8(%rsp)
  c960bb:	mov    -0xad0(%rbp),%rax
  c960c2:	mov    %rax,(%rsp)
  c960c6:	lea    0x1187b83(%rip),%rax        # 1e1dc50 <_ZN18Global_THD_manager16global_thd_countE>
  c960cd:	mov    (%rax),%r8d
  c960d0:	xor    %eax,%eax
  c960d2:	callq  1313550 <my_snprintf>
  c960d7:	mov    0x1100(%rbx),%rdi
  c960de:	mov    %rax,%rdx
  c960e1:	mov    %r14,%rsi
  c960e4:	callq  bfc870 <_ZN16Protocol_classic5writeEPKhm>
  c960e9:	mov    0x1100(%rbx),%rdi
  c960f0:	callq  bfc850 <_ZN16Protocol_classic9flush_netEv>
  c960f5:	mov    0x3478(%rbx),%rax
  c960fc:	movl   $0x4,0x94(%rax)
  c96106:	jmpq   c9550a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x31a>
  c9610b:	lea    -0x5c0(%rbp),%r15
  c96112:	movq   $0x0,-0x4f8(%rbp)
  c9611d:	lea    0x268(%r15),%rdi
  c96124:	callq  d26e70 <_ZN10GRANT_INFOC1Ev>
  c96129:	lea    0x1196120(%rip),%rax        # 1e2c250 <end_of_list>
  c96130:	lea    0x8a36ab(%rip),%rdx        # 15397e2 <_ZTS8COND_CMP+0x110>
  c96137:	lea    0x8a36c0(%rip),%rsi        # 15397fe <_ZTS8COND_CMP+0x12c>
  c9613e:	mov    %rbx,%rdi
  c96141:	movl   $0x0,-0x248(%rbp)
  c9614b:	mov    %rax,-0x258(%rbp)
  c96152:	lea    0x368(%r15),%rax
  c96159:	mov    %rax,-0x250(%rbp)
  c96160:	callq  c5ef20 <_Z20push_deprecated_warnP3THDPKcS2_>
  c96165:	mov    0x218(%rbx),%rsi
  c9616c:	mov    0x110(%rbx),%rax
  c96173:	mov    0x108(%rbx),%rdx
  c9617a:	addq   $0x1,0x840(%rbx)
  c96182:	test   %rsi,%rsi
  c96185:	mov    %rax,-0xbe8(%rbp)
  c9618c:	mov    %rdx,-0xbf0(%rbp)
  c96193:	je     c96efc <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1d0c>
  c96199:	mov    0x220(%rbx),%rdx
  c961a0:	mov    0x18(%rbx),%rdi
  c961a4:	callq  eb20d0 <strmake_root>
  c961a9:	mov    %rax,%r12
  c961ac:	mov    -0xc20(%rbp),%rax
  c961b3:	lea    0x1184ae6(%rip),%r14        # 1e1aca0 <system_charset_info>
  c961ba:	mov    0x5a0(%rbx),%r9
  c961c1:	lea    -0xc00(%rbp),%rsi
  c961c8:	mov    %rbx,%rdi
  c961cb:	mov    0x220(%rbx),%r13
  c961d2:	mov    0x8(%rax),%r8d
  c961d6:	mov    (%rax),%rcx
  c961d9:	mov    (%r14),%rdx
  c961dc:	callq  c4db00 <_ZN3THD14convert_stringEP19st_mysql_lex_stringPK15charset_info_stPKcmS4_>
  c961e1:	mov    -0xbf8(%rbp),%rsi
  c961e8:	mov    -0xc00(%rbp),%rdi
  c961ef:	xor    %edx,%edx
  c961f1:	callq  d2e5a0 <_Z16check_table_namePKcmb>
  c961f6:	cmp    $0x1,%eax
  c961f9:	je     c96fbd <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1dcd>
  c961ff:	cmp    $0x2,%eax
  c96202:	je     c96f39 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1d49>
  c96208:	mov    %rbx,%rdi
  c9620b:	callq  c8c8a0 <_Z32mysql_reset_thd_for_next_commandP3THD>
  c96210:	mov    %rbx,%rdi
  c96213:	callq  c72d60 <_Z9lex_startP3THD>
  c96218:	lea    0x1187281(%rip),%rax        # 1e1d4a0 <lower_case_table_names>
  c9621f:	mov    (%rax),%ecx
  c96221:	test   %ecx,%ecx
  c96223:	jne    c96f8e <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1d9e>
  c96229:	mov    -0xbf8(%rbp),%rsi
  c96230:	xor    %eax,%eax
  c96232:	mov    $0xb0,%ecx
  c96237:	mov    %r15,%rdi
  c9623a:	rep stos %rax,%es:(%rdi)
  c9623d:	mov    -0xc00(%rbp),%rdx
  c96244:	lea    0x689635(%rip),%rax        # 131f880 <_ZTS32Find_thd_by_id_with_callback_setItE+0x3e0>
  c9624b:	lea    0x398(%r15),%rdi
  c96252:	mov    %rsi,-0x2f8(%rbp)
  c96259:	movl   $0x6d0,0x8(%rsp)
  c96261:	mov    $0x1,%r9d
  c96267:	mov    %rax,(%rsp)
  c9626b:	mov    $0x3,%r8d
  c96271:	mov    $0x3,%esi
  c96276:	mov    %rdx,%rcx
  c96279:	mov    %rdx,-0x5a0(%rbp)
  c96280:	mov    %rdx,-0x598(%rbp)
  c96287:	mov    %r12,%rdx
  c9628a:	movq   $0x1,-0x558(%rbp)
  c96295:	mov    %r12,-0x5a8(%rbp)
  c9629c:	mov    %r13,-0x300(%rbp)
  c962a3:	movl   $0x2,-0x310(%rbp)
  c962ad:	callq  be9ad0 <_ZN11MDL_request16init_with_sourceEN7MDL_key18enum_mdl_namespaceEPKcS3_13enum_mdl_type17enum_mdl_durationS3_j>
  c962b2:	mov    0x1c8(%rbx),%rax
  c962b9:	movq   $0x0,-0x318(%rbp)
  c962c4:	movq   $0x0,-0x570(%rbp)
  c962cf:	movq   $0x0,-0x568(%rbp)
  c962da:	mov    0xd8(%rax),%rdx
  c962e1:	mov    %rdx,-0x4b8(%rbp)
  c962e8:	mov    0xd8(%rax),%rax
  c962ef:	mov    0x110(%rax),%rdx
  c962f6:	addl   $0x1,0x100(%rax)
  c962fd:	mov    %r15,(%rdx)
  c96300:	mov    %r15,0x110(%rax)
  c96307:	mov    0x1c8(%rbx),%rax
  c9630e:	movq   $0x0,-0x5c0(%rbp)
  c96319:	mov    0x18(%rax),%rdx
  c9631d:	mov    %rdx,-0x5b0(%rbp)
  c96324:	mov    %r15,(%rdx)
  c96327:	lea    0x8(%r15),%rdx
  c9632b:	mov    %rdx,0x18(%rax)
  c9632f:	lea    0x10fceda(%rip),%rax        # 1d93210 <INFORMATION_SCHEMA_NAME>
  c96336:	mov    -0x5a8(%rbp),%rdx
  c9633d:	mov    0x8(%rax),%rcx
  c96341:	cmp    %rcx,-0x300(%rbp)
  c96348:	je     c97020 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1e30>
  c9634e:	mov    -0xc20(%rbp),%rax
  c96355:	mov    0x18(%rbx),%rdi
  c96359:	mov    0x18(%rax),%edx
  c9635c:	mov    0x10(%rax),%rsi
  c96360:	callq  eb2140 <memdup_root>
  c96365:	test   %rax,%rax
  c96368:	mov    %rax,%r12
  c9636b:	je     c95f5f <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0xd6f>
  c96371:	mov    -0xc20(%rbp),%rax
  c96378:	mov    %rbx,%rdi
  c9637b:	mov    %r12,-0xbc0(%rbp)
  c96382:	mov    0x18(%rax),%eax
  c96385:	sub    $0x1,%eax
  c96388:	mov    %rax,-0xbb8(%rbp)
  c9638f:	lea    -0xbc0(%rbp),%rax
  c96396:	mov    %rax,%rsi
  c96399:	mov    %rax,-0xc20(%rbp)
  c963a0:	callq  c52250 <_ZN3THD9set_queryERK25st_mysql_const_lex_string>
  c963a5:	mov    -0x5a0(%rbp),%r8
  c963ac:	mov    -0xc04(%rbp),%edx
  c963b2:	lea    0x926bc4(%rip),%rcx        # 15bcf7d <_ZTS25Delete_rows_log_event_old+0x1dfd>
  c963b9:	lea    0x1194840(%rip),%rdi        # 1e2ac00 <query_logger>
  c963c0:	mov    %r12,%r9
  c963c3:	mov    %rbx,%rsi
  c963c6:	xor    %eax,%eax
  c963c8:	callq  be4aa0 <_ZN12Query_logger17general_log_printEP3THD19enum_server_commandPKcz>
  c963cd:	mov    %r15,%rsi
  c963d0:	mov    %rbx,%rdi
  c963d3:	callq  c3d1a0 <_Z21open_temporary_tablesP3THDP10TABLE_LIST>
  c963d8:	test   %al,%al
  c963da:	jne    c95989 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x799>
  c963e0:	xor    %r9d,%r9d
  c963e3:	or     $0xffffffff,%r8d
  c963e7:	mov    $0x1,%ecx
  c963ec:	mov    %r15,%rdx
  c963ef:	mov    $0x1,%esi
  c963f4:	mov    %rbx,%rdi
  c963f7:	callq  d8e210 <_Z18check_table_accessP3THDmP10TABLE_LISTbjb>
  c963fc:	test   %al,%al
  c963fe:	jne    c95989 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x799>
  c96404:	mov    0x1c8(%rbx),%rax
  c9640b:	mov    -0xc20(%rbp),%rdi
  c96412:	mov    %r15,%rdx
  c96415:	mov    %rbx,%rsi
  c96418:	xor    %r9d,%r9d
  c9641b:	xor    %r8d,%r8d
  c9641e:	movl   $0xd,0x8(%rax)
  c96425:	mov    0x1c8(%rbx),%rax
  c9642c:	mov    0x8(%rax),%ecx
  c9642f:	movq   $0x0,0x10(%rsp)
  c96438:	movq   $0x0,0x8(%rsp)
  c96441:	movq   $0x0,(%rsp)
  c96449:	callq  de24a0 <_ZN15Opt_trace_startC1EP3THDP10TABLE_LIST16enum_sql_commandP4ListI12set_var_baseEPKcmP12sp_printablePK15charset_info_st>
  c9644e:	mov    %r12,%rdx
  c96451:	mov    %r15,%rsi
  c96454:	mov    %rbx,%rdi
  c96457:	callq  cda510 <_Z18mysqld_list_fieldsP3THDP10TABLE_LISTPKc>
  c9645c:	mov    0x1c8(%rbx),%rax
  c96463:	mov    $0x1,%esi
  c96468:	mov    0xd0(%rax),%rdi
  c9646f:	callq  d10b50 <_ZN18st_select_lex_unit7cleanupEb>
  c96474:	mov    %rbx,%rdi
  c96477:	callq  c381e0 <_Z19close_thread_tablesP3THD>
  c9647c:	lea    0x98(%rbx),%r12
  c96483:	lea    -0xbf0(%rbp),%rsi
  c9648a:	mov    %r12,%rdi
  c9648d:	callq  becca0 <_ZN11MDL_context21rollback_to_savepointERK13MDL_savepoint>
  c96492:	cmpb   $0x0,0x1f39(%rbx)
  c96499:	je     c964ab <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x12bb>
  c9649b:	mov    %rbx,%rdi
  c9649e:	callq  d372e0 <_Z23trans_rollback_implicitP3THD>
  c964a3:	mov    %r12,%rdi
  c964a6:	callq  beccd0 <_ZN11MDL_context27release_transactional_locksEv>
  c964ab:	mov    %rbx,%rdi
  c964ae:	callq  c4fd70 <_ZN3THD19cleanup_after_queryEv>
  c964b3:	mov    -0xc20(%rbp),%rdi
  c964ba:	callq  de26d0 <_ZN15Opt_trace_startD1Ev>
  c964bf:	jmpq   c95989 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x799>
  c964c4:	nopl   0x0(%rax)
  c964c8:	mov    -0xc20(%rbp),%rax
  c964cf:	mov    %rbx,%rdi
  c964d2:	xor    %r13d,%r13d
  c964d5:	mov    0x8(%rax),%edx
  c964d8:	mov    (%rax),%rsi
  c964db:	callq  cbd440 <_Z19mysqld_stmt_prepareP3THDPKcj>
  c964e0:	lea    -0xbc0(%rbp),%rax
  c964e7:	mov    -0xc30(%rbp),%r12
  c964ee:	mov    %rax,-0xc20(%rbp)
  c964f5:	jmpq   c9550a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x31a>
  c964fa:	mov    -0xc20(%rbp),%rax
  c96501:	mov    %rbx,%rdi
  c96504:	xor    %r13d,%r13d
  c96507:	mov    0x10(%rax),%rcx
  c9650b:	mov    0x8(%rax),%rdx
  c9650f:	mov    0x18(%rax),%r8
  c96513:	mov    (%rax),%rsi
  c96516:	callq  cbe9c0 <_Z19mysqld_stmt_executeP3THDmmPhm>
  c9651b:	lea    -0xbc0(%rbp),%rax
  c96522:	mov    -0xc30(%rbp),%r12
  c96529:	mov    %rax,-0xc20(%rbp)
  c96530:	jmpq   c9550a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x31a>
  c96535:	mov    -0xc20(%rbp),%rax
  c9653c:	mov    %rbx,%rdi
  c9653f:	xor    %r13d,%r13d
  c96542:	mov    0x10(%rax),%rcx
  c96546:	mov    0x8(%rax),%edx
  c96549:	mov    0x18(%rax),%r8
  c9654d:	mov    (%rax),%rsi
  c96550:	callq  cbb0f0 <_Z23mysql_stmt_get_longdataP3THDmjPhm>
  c96555:	lea    -0xbc0(%rbp),%rax
  c9655c:	mov    -0xc30(%rbp),%r12
  c96563:	mov    %rax,-0xc20(%rbp)
  c9656a:	jmpq   c9550a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x31a>
  c9656f:	mov    -0xc20(%rbp),%rax
  c96576:	mov    %rbx,%rdi
  c96579:	xor    %r13d,%r13d
  c9657c:	mov    (%rax),%esi
  c9657e:	callq  cbed10 <_Z17mysqld_stmt_closeP3THDm>
  c96583:	lea    -0xbc0(%rbp),%rax
  c9658a:	mov    -0xc30(%rbp),%r12
  c96591:	mov    %rax,-0xc20(%rbp)
  c96598:	jmpq   c9550a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x31a>
  c9659d:	mov    -0xc20(%rbp),%rax
  c965a4:	mov    %rbx,%rdi
  c965a7:	xor    %r13d,%r13d
  c965aa:	mov    (%rax),%esi
  c965ac:	callq  cbbb40 <_Z17mysqld_stmt_resetP3THDm>
  c965b1:	lea    -0xbc0(%rbp),%rax
  c965b8:	mov    -0xc30(%rbp),%r12
  c965bf:	mov    %rax,-0xc20(%rbp)
  c965c6:	jmpq   c9550a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x31a>
  c965cb:	mov    -0xc20(%rbp),%rax
  c965d2:	addq   $0x1,0x8d0(%rbx)
  c965da:	mov    (%rax),%eax
  c965dc:	test   %eax,%eax
  c965de:	je     c96bfc <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1a0c>
  c965e4:	cmp    $0x1,%eax
  c965e7:	jne    c96aef <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x18ff>
  c965ed:	mov    0x1100(%rbx),%rax
  c965f4:	andq   $0xfffffffffffeffff,0x8(%rax)
  c965fc:	mov    0x3478(%rbx),%rdi
  c96603:	movq   $0xffffffffffffffff,0x1b90(%rbx)
  c9660e:	mov    %rbx,%rsi
  c96611:	callq  c5e6f0 <_ZN16Diagnostics_area14set_eof_statusEP3THD>
  c96616:	cmpq   $0x0,0x640(%rbx)
  c9661e:	je     c954f2 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x302>
  c96624:	lea    0x34c0(%rbx),%rdi
  c9662b:	mov    $0x4,%esi
  c96630:	xor    %r13d,%r13d
  c96633:	callq  c0a9e0 <_ZNK15Session_tracker11get_trackerE20enum_session_tracker>
  c96638:	mov    $0x80,%edx
  c9663d:	mov    %rax,%rdi
  c96640:	mov    %rbx,%rsi
  c96643:	callq  c0a270 <_ZN25Transaction_state_tracker13add_trx_stateEP3THDj>
  c96648:	lea    -0xbc0(%rbp),%rax
  c9664f:	mov    -0xc30(%rbp),%r12
  c96656:	mov    %rax,-0xc20(%rbp)
  c9665d:	jmpq   c9550a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x31a>
  c96662:	mov    -0xc20(%rbp),%rax
  c96669:	mov    %rbx,%rdi
  c9666c:	xor    %r13d,%r13d
  c9666f:	mov    0x8(%rax),%rdx
  c96673:	mov    (%rax),%rsi
  c96676:	callq  cbb860 <_Z17mysqld_stmt_fetchP3THDmm>
  c9667b:	lea    -0xbc0(%rbp),%rax
  c96682:	mov    -0xc30(%rbp),%r12
  c96689:	mov    %rax,-0xc20(%rbp)
  c96690:	jmpq   c9550a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x31a>
  c96695:	mov    0x1100(%rbx),%rax
  c9669c:	mov    %rbx,%rdi
  c9669f:	mov    0x38(%rax),%edx
  c966a2:	mov    0x40(%rax),%rsi
  c966a6:	callq  e654f0 <_Z20com_binlog_dump_gtidP3THDPcm>
  c966ab:	mov    %eax,%r13d
  c966ae:	lea    -0xbc0(%rbp),%rax
  c966b5:	mov    -0xc30(%rbp),%r12
  c966bc:	mov    %rax,-0xc20(%rbp)
  c966c3:	jmpq   c9550a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x31a>
  c966c8:	addq   $0x1,0x7d0(%rbx)
  c966d0:	jmpq   c9586b <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x67b>
  c966d5:	addq   $0x1,0x7d0(%rbx)
  c966dd:	mov    %rbx,%rdi
  c966e0:	lea    -0x5c0(%rbp),%r15
  c966e7:	callq  c50520 <_ZN3THD18cleanup_connectionEv>
  c966ec:	mov    0x220(%rbx),%rax
  c966f3:	mov    0x1040(%rbx),%rsi
  c966fa:	mov    %r15,%rdi
  c966fd:	mov    0x1bb0(%rbx),%r12
  c96704:	mov    0x218(%rbx),%r13
  c9670b:	movq   $0x0,-0x5c0(%rbp)
  c96716:	movq   $0x0,-0x5b8(%rbp)
  c96721:	mov    %rax,-0xc20(%rbp)
  c96728:	lea    0x1111a11(%rip),%rax        # 1da8140 <my_charset_bin>
  c9672f:	movl   $0x0,-0x5a8(%rbp)
  c96739:	movb   $0x0,-0x5a4(%rbp)
  c96740:	movq   $0x0,-0x5a0(%rbp)
  c9674b:	movq   $0x0,-0x598(%rbp)
  c96756:	mov    %rax,-0x5b0(%rbp)
  c9675d:	mov    %rax,-0x590(%rbp)
  c96764:	movl   $0x0,-0x588(%rbp)
  c9676e:	movb   $0x0,-0x584(%rbp)
  c96775:	movq   $0x0,-0x580(%rbp)
  c96780:	movq   $0x0,-0x578(%rbp)
  c9678b:	mov    %rax,-0x570(%rbp)
  c96792:	movl   $0x0,-0x568(%rbp)
  c9679c:	movb   $0x0,-0x564(%rbp)
  c967a3:	movq   $0x0,-0x560(%rbp)
  c967ae:	movq   $0x0,-0x558(%rbp)
  c967b9:	mov    %rax,-0x550(%rbp)
  c967c0:	movl   $0x0,-0x548(%rbp)
  c967ca:	movb   $0x0,-0x544(%rbp)
  c967d1:	movq   $0x0,-0x540(%rbp)
  c967dc:	movq   $0x0,-0x538(%rbp)
  c967e7:	mov    %rax,-0x530(%rbp)
  c967ee:	movl   $0x0,-0x528(%rbp)
  c967f8:	movb   $0x0,-0x524(%rbp)
  c967ff:	callq  7bf9a0 <_ZN16Security_context17copy_security_ctxERKS_>
  c96804:	mov    $0x11,%esi
  c96809:	mov    %rbx,%rdi
  c9680c:	callq  7abe40 <_Z16acl_authenticateP3THD19enum_server_command>
  c96811:	lea    0x8a3378(%rip),%rdx        # 1539b90 <_ZTS8COND_CMP+0x4be>
  c96818:	mov    $0x4,%esi
  c9681d:	mov    %rbx,%rdi
  c96820:	mov    %eax,%r14d
  c96823:	callq  7a4660 <_Z18mysql_audit_notifyP3THD33mysql_event_connection_subclass_tPKc>
  c96828:	or     %r14d,%eax
  c9682b:	jne    c96dd7 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1be7>
  c96831:	test   %r12,%r12
  c96834:	je     c9683e <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x164e>
  c96836:	mov    %r12,%rdi
  c96839:	callq  c561d0 <_Z25decrease_user_connectionsP9user_conn>
  c9683e:	mov    0xca0(%rbx),%rsi
  c96845:	test   %rsi,%rsi
  c96848:	je     c96eeb <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1cfb>
  c9684e:	lea    -0xbc0(%rbp),%rax
  c96855:	lea    0x8a3154(%rip),%rcx        # 15399b0 <_ZTS8COND_CMP+0x2de>
  c9685c:	mov    $0x545,%r8d
  c96862:	xor    %edx,%edx
  c96864:	mov    %rax,%rdi
  c96867:	callq  ed78e0 <pfs_start_mutex_wait_v1>
  c9686c:	mov    -0xc10(%rbp),%rdi
  c96873:	mov    %rax,%r12
  c96876:	callq  7620e0 <pthread_mutex_lock@plt>
  c9687b:	test   %r12,%r12
  c9687e:	je     c9688a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x169a>
  c96880:	mov    %eax,%esi
  c96882:	mov    %r12,%rdi
  c96885:	callq  ed8be0 <pfs_end_mutex_wait_v1>
  c9688a:	mov    %r13,%rdi
  c9688d:	callq  eb6000 <my_free>
  c96892:	mov    0xca0(%rbx),%rdi
  c96899:	test   %rdi,%rdi
  c9689c:	je     c968a3 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x16b3>
  c9689e:	callq  ed6140 <pfs_unlock_mutex_v1>
  c968a3:	mov    -0xc10(%rbp),%rdi
  c968aa:	xor    %r13d,%r13d
  c968ad:	callq  762030 <pthread_mutex_unlock@plt>
  c968b2:	mov    %r15,%rdi
  c968b5:	callq  7bf6a0 <_ZN16Security_context7destroyEv>
  c968ba:	cmpb   $0x0,-0x524(%rbp)
  c968c1:	jne    c96d9f <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1baf>
  c968c7:	cmpb   $0x0,-0x544(%rbp)
  c968ce:	jne    c96d67 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1b77>
  c968d4:	cmpb   $0x0,-0x564(%rbp)
  c968db:	jne    c96d2f <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1b3f>
  c968e1:	cmpb   $0x0,-0x584(%rbp)
  c968e8:	jne    c96cf7 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1b07>
  c968ee:	cmpb   $0x0,-0x5a4(%rbp)
  c968f5:	je     c96914 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1724>
  c968f7:	mov    -0x5c0(%rbp),%rdi
  c968fe:	movb   $0x0,-0x5a4(%rbp)
  c96905:	movl   $0x0,-0x5a8(%rbp)
  c9690f:	callq  eb6000 <my_free>
  c96914:	lea    -0xbc0(%rbp),%rax
  c9691b:	lea    0x8a2e9e(%rip),%r12        # 15397c0 <_ZTS8COND_CMP+0xee>
  c96922:	mov    %rax,-0xc20(%rbp)
  c96929:	jmpq   c9550a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x31a>
  c9692e:	mov    0x1100(%rbx),%rax
  c96935:	mov    %rbx,%rdi
  c96938:	mov    0x38(%rax),%edx
  c9693b:	mov    0x40(%rax),%rsi
  c9693f:	callq  e653e0 <_Z15com_binlog_dumpP3THDPcm>
  c96944:	mov    %eax,%r13d
  c96947:	lea    -0xbc0(%rbp),%rax
  c9694e:	mov    -0xc30(%rbp),%r12
  c96955:	mov    %rax,-0xc20(%rbp)
  c9695c:	jmpq   c9550a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x31a>
  c96961:	mov    0x1100(%rbx),%rax
  c96968:	mov    %rbx,%rdi
  c9696b:	mov    0x38(%rax),%edx
  c9696e:	mov    0x40(%rax),%rsi
  c96972:	callq  e64110 <_Z14register_slaveP3THDPhm>
  c96977:	test   %eax,%eax
  c96979:	jne    c954f2 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x302>
  c9697f:	jmpq   c9586b <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x67b>
  c96984:	lea    0x8a32bd(%rip),%rdx        # 1539c48 <_ZTS8COND_CMP+0x576>
  c9698b:	lea    0x8a2ec3(%rip),%rsi        # 1539855 <_ZTS8COND_CMP+0x183>
  c96992:	mov    %rbx,%rdi
  c96995:	xor    %r13d,%r13d
  c96998:	callq  c5ef20 <_Z20push_deprecated_warnP3THDPKcS2_>
  c9699d:	mov    -0xc20(%rbp),%rax
  c969a4:	addq   $0x1,0x968(%rbx)
  c969ac:	xor    %edx,%edx
  c969ae:	mov    %rbx,%rdi
  c969b1:	mov    (%rax),%rsi
  c969b4:	callq  c8b810 <_ZL8sql_killP3THDjb>
  c969b9:	lea    -0xbc0(%rbp),%rax
  c969c0:	mov    -0xc30(%rbp),%r12
  c969c7:	mov    %rax,-0xc20(%rbp)
  c969ce:	jmpq   c9550a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x31a>
  c969d3:	addq   $0x1,0x7d0(%rbx)
  c969db:	mov    $0x8000,%esi
  c969e0:	mov    %rbx,%rdi
  c969e3:	callq  d95390 <_Z19check_global_accessP3THDm>
  c969e8:	test   %al,%al
  c969ea:	jne    c954f2 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x302>
  c969f0:	callq  d020e0 <_Z18mysql_print_statusv>
  c969f5:	mov    -0xc04(%rbp),%edx
  c969fb:	lea    0x11941fe(%rip),%rdi        # 1e2ac00 <query_logger>
  c96a02:	xor    %ecx,%ecx
  c96a04:	mov    %rbx,%rsi
  c96a07:	xor    %eax,%eax
  c96a09:	callq  be4aa0 <_ZN12Query_logger17general_log_printEP3THD19enum_server_commandPKcz>
  c96a0e:	jmpq   c965fc <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x140c>
  c96a13:	addq   $0x1,0x878(%rbx)
  c96a1b:	lea    0x8a2e07(%rip),%rdx        # 1539829 <_ZTS8COND_CMP+0x157>
  c96a22:	lea    0x8a2e1b(%rip),%rsi        # 1539844 <_ZTS8COND_CMP+0x172>
  c96a29:	mov    %rbx,%rdi
  c96a2c:	callq  c5ef20 <_Z20push_deprecated_warnP3THDPKcS2_>
  c96a31:	mov    0x1040(%rbx),%rax
  c96a38:	cmpb   $0x0,0xa0(%rax)
  c96a3f:	je     c96c10 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1a20>
  c96a45:	mov    -0xc04(%rbp),%edx
  c96a4b:	lea    0x11941ae(%rip),%rdi        # 1e2ac00 <query_logger>
  c96a52:	xor    %ecx,%ecx
  c96a54:	mov    %rbx,%rsi
  c96a57:	xor    %eax,%eax
  c96a59:	callq  be4aa0 <_ZN12Query_logger17general_log_printEP3THD19enum_server_commandPKcz>
  c96a5e:	mov    0x1040(%rbx),%rax
  c96a65:	xor    %esi,%esi
  c96a67:	testb  $0x1,0x201(%rax)
  c96a6e:	jne    c96a77 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1887>
  c96a70:	lea    0xa0(%rax),%rsi
  c96a77:	xor    %edx,%edx
  c96a79:	mov    %rbx,%rdi
  c96a7c:	xor    %r13d,%r13d
  c96a7f:	callq  ce99b0 <_Z21mysqld_list_processesP3THDPKcb>
  c96a84:	lea    -0xbc0(%rbp),%rax
  c96a8b:	mov    -0xc30(%rbp),%r12
  c96a92:	mov    %rax,-0xc20(%rbp)
  c96a99:	jmpq   c9550a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x31a>
  c96a9e:	mov    0x12c0(%rbx),%rax
  c96aa5:	addq   $0x1,0x7d0(%rbx)
  c96aad:	xor    %esi,%esi
  c96aaf:	sub    $0x1,%rax
  c96ab3:	cmp    $0x7ffffffe,%rax
  c96ab9:	ja     c96ac4 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x18d4>
  c96abb:	mov    -0xc20(%rbp),%rax
  c96ac2:	mov    (%rax),%esi
  c96ac4:	mov    -0xc04(%rbp),%edx
  c96aca:	mov    %rbx,%rdi
  c96acd:	callq  c8c1b0 <_Z8shutdownP3THD25mysql_enum_shutdown_level19enum_server_command>
  c96ad2:	mov    %eax,%r13d
  c96ad5:	lea    -0xbc0(%rbp),%rax
  c96adc:	mov    -0xc30(%rbp),%r12
  c96ae3:	mov    %rax,-0xc20(%rbp)
  c96aea:	jmpq   c9550a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x31a>
  c96aef:	lea    0x118410a(%rip),%rax        # 1e1ac00 <THR_THD>
  c96af6:	xor    %r13d,%r13d
  c96af9:	mov    (%rax),%edi
  c96afb:	callq  762c40 <pthread_getspecific@plt>
  c96b00:	mov    $0x417,%esi
  c96b05:	mov    %rax,%rdi
  c96b08:	callq  7c1920 <_Z6ER_THDPK3THDi>
  c96b0d:	xor    %edx,%edx
  c96b0f:	mov    %rax,%rsi
  c96b12:	mov    $0x417,%edi
  c96b17:	callq  eb4020 <my_message>
  c96b1c:	lea    -0xbc0(%rbp),%rax
  c96b23:	mov    -0xc30(%rbp),%r12
  c96b2a:	mov    %rax,-0xc20(%rbp)
  c96b31:	jmpq   c9550a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x31a>
  c96b36:	nopw   %cs:0x0(%rax,%rax,1)
  c96b40:	mov    0x12d0(%rbx),%rax
  c96b47:	mov    0x12d8(%rbx),%rdx
  c96b4e:	mov    %rax,%rdi
  c96b51:	mov    %rax,0x12c0(%rbx)
  c96b58:	mov    %rdx,0x12c8(%rbx)
  c96b5f:	jmpq   c95eb4 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0xcc4>
  c96b64:	nopl   0x0(%rax)
  c96b68:	mov    0x1c8(%rbx),%rax
  c96b6f:	cmpl   $0x8a,0x8(%rax)
  c96b76:	je     c96f68 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1d78>
  c96b7c:	lea    0x8a2c37(%rip),%r12        # 15397ba <_ZTS8COND_CMP+0xe8>
  c96b83:	xor    %r13d,%r13d
  c96b86:	mov    -0xc20(%rbp),%rax
  c96b8d:	lea    0xf0(%rax),%rdi
  c96b94:	callq  c6c050 <_ZN10Yacc_stateD1Ev>
  c96b99:	jmpq   c9550a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x31a>
  c96b9e:	xchg   %ax,%ax
  c96ba0:	mov    0x2a0(%rax),%r12d
  c96ba7:	jmpq   c95bfa <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0xa0a>
  c96bac:	nopl   0x0(%rax)
  c96bb0:	lea    0x1186b61(%rip),%rax        # 1e1d718 <abort_loop>
  c96bb7:	movzbl (%rax),%eax
  c96bba:	test   %al,%al
  c96bbc:	jne    c9577f <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x58f>
  c96bc2:	mov    $0x525,%r14d
  c96bc8:	mov    $0x525,%r15d
  c96bce:	jmpq   c9577f <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x58f>
  c96bd3:	nopl   0x0(%rax,%rax,1)
  c96bd8:	mov    -0xc10(%rbp),%rdi
  c96bdf:	callq  7620e0 <pthread_mutex_lock@plt>
  c96be4:	jmpq   c95e2a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0xc3a>
  c96be9:	xor    %r8d,%r8d
  c96bec:	jmpq   c95c12 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0xa22>
  c96bf1:	xor    %r12d,%r12d
  c96bf4:	xor    %r13d,%r13d
  c96bf7:	jmpq   c9605c <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0xe6c>
  c96bfc:	mov    0x1100(%rbx),%rax
  c96c03:	orq    $0x10000,0x8(%rax)
  c96c0b:	jmpq   c965fc <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x140c>
  c96c10:	mov    $0x100,%esi
  c96c15:	mov    %rbx,%rdi
  c96c18:	callq  d95390 <_Z19check_global_accessP3THDm>
  c96c1d:	test   %al,%al
  c96c1f:	jne    c954f2 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x302>
  c96c25:	jmpq   c96a45 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1855>
  c96c2a:	lea    0x98(%rbx),%r13
  c96c31:	mov    %r13,%rdi
  c96c34:	callq  beccd0 <_ZN11MDL_context27release_transactional_locksEv>
  c96c39:	mov    $0x40,%esi
  c96c3e:	mov    %rbx,%rdi
  c96c41:	callq  d95390 <_Z19check_global_accessP3THDm>
  c96c46:	lea    -0xbc0(%rbp),%rcx
  c96c4d:	test   %al,%al
  c96c4f:	mov    %rcx,-0xc20(%rbp)
  c96c56:	jne    c95989 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x799>
  c96c5c:	mov    -0xc04(%rbp),%edx
  c96c62:	lea    0x1193f97(%rip),%rdi        # 1e2ac00 <query_logger>
  c96c69:	xor    %ecx,%ecx
  c96c6b:	mov    %rbx,%rsi
  c96c6e:	callq  be4aa0 <_ZN12Query_logger17general_log_printEP3THD19enum_server_commandPKcz>
  c96c73:	mov    -0xc20(%rbp),%rcx
  c96c7a:	xor    %edx,%edx
  c96c7c:	movzbl %r12b,%esi
  c96c80:	mov    %rbx,%rdi
  c96c83:	callq  cc1af0 <_Z20reload_acl_and_cacheP3THDmP10TABLE_LISTPi>
  c96c88:	test   %al,%al
  c96c8a:	jne    c95989 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x799>
  c96c90:	mov    %rbx,%rdi
  c96c93:	callq  d37190 <_Z21trans_commit_implicitP3THD>
  c96c98:	test   %al,%al
  c96c9a:	jne    c95989 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x799>
  c96ca0:	mov    %rbx,%rdi
  c96ca3:	callq  c381e0 <_Z19close_thread_tablesP3THD>
  c96ca8:	mov    %r13,%rdi
  c96cab:	callq  beccd0 <_ZN11MDL_context27release_transactional_locksEv>
  c96cb0:	mov    0x3478(%rbx),%rdi
  c96cb7:	movq   $0x0,0x1b90(%rbx)
  c96cc2:	xor    %ecx,%ecx
  c96cc4:	xor    %edx,%edx
  c96cc6:	xor    %esi,%esi
  c96cc8:	callq  c5e680 <_ZN16Diagnostics_area13set_ok_statusEyyPKc>
  c96ccd:	jmpq   c95989 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x799>
  c96cd2:	mov    0x218(%rbx),%rcx
  c96cd9:	mov    0x220(%rbx),%r8
  c96ce0:	mov    %rbx,%rsi
  c96ce3:	mov    -0xc04(%rbp),%edx
  c96ce9:	lea    0x1193f10(%rip),%rdi        # 1e2ac00 <query_logger>
  c96cf0:	callq  be47e0 <_ZN12Query_logger17general_log_writeEP3THD19enum_server_commandPKcm>
  c96cf5:	jmp    c96cb0 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1ac0>
  c96cf7:	mov    -0x5a0(%rbp),%rdi
  c96cfe:	movb   $0x0,-0x584(%rbp)
  c96d05:	movl   $0x0,-0x588(%rbp)
  c96d0f:	callq  eb6000 <my_free>
  c96d14:	movq   $0x0,-0x5a0(%rbp)
  c96d1f:	movq   $0x0,-0x598(%rbp)
  c96d2a:	jmpq   c968ee <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x16fe>
  c96d2f:	mov    -0x580(%rbp),%rdi
  c96d36:	movb   $0x0,-0x564(%rbp)
  c96d3d:	movl   $0x0,-0x568(%rbp)
  c96d47:	callq  eb6000 <my_free>
  c96d4c:	movq   $0x0,-0x580(%rbp)
  c96d57:	movq   $0x0,-0x578(%rbp)
  c96d62:	jmpq   c968e1 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x16f1>
  c96d67:	mov    -0x560(%rbp),%rdi
  c96d6e:	movb   $0x0,-0x544(%rbp)
  c96d75:	movl   $0x0,-0x548(%rbp)
  c96d7f:	callq  eb6000 <my_free>
  c96d84:	movq   $0x0,-0x560(%rbp)
  c96d8f:	movq   $0x0,-0x558(%rbp)
  c96d9a:	jmpq   c968d4 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x16e4>
  c96d9f:	mov    -0x540(%rbp),%rdi
  c96da6:	movb   $0x0,-0x524(%rbp)
  c96dad:	movl   $0x0,-0x528(%rbp)
  c96db7:	callq  eb6000 <my_free>
  c96dbc:	movq   $0x0,-0x540(%rbp)
  c96dc7:	movq   $0x0,-0x538(%rbp)
  c96dd2:	jmpq   c968c7 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x16d7>
  c96dd7:	mov    0x1040(%rbx),%r14
  c96dde:	cmp    %r15,%r14
  c96de1:	je     c96df6 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1c06>
  c96de3:	mov    %r14,%rdi
  c96de6:	callq  7bf6a0 <_ZN16Security_context7destroyEv>
  c96deb:	mov    %r15,%rsi
  c96dee:	mov    %r14,%rdi
  c96df1:	callq  7bf9a0 <_ZN16Security_context17copy_security_ctxERKS_>
  c96df6:	mov    %r12,%rsi
  c96df9:	mov    %rbx,%rdi
  c96dfc:	callq  c525a0 <_ZN3THD16set_user_connectEP9user_conn>
  c96e01:	mov    -0xc20(%rbp),%rax
  c96e08:	mov    %r13,0x218(%rbx)
  c96e0f:	mov    %r13,%rdi
  c96e12:	mov    %rax,0x220(%rbx)
  c96e19:	mov    %eax,%esi
  c96e1b:	callq  ed6fc0 <pfs_set_thread_db_v1>
  c96e20:	cmpb   $0x0,0x1f37(%rbx)
  c96e27:	lea    0x1183dd2(%rip),%rax        # 1e1ac00 <THR_THD>
  c96e2e:	mov    (%rax),%edi
  c96e30:	je     c96ed4 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1ce4>
  c96e36:	callq  762c40 <pthread_getspecific@plt>
  c96e3b:	mov    $0x3eb,%esi
  c96e40:	mov    %rax,%rdi
  c96e43:	callq  7c1920 <_Z6ER_THDPK3THDi>
  c96e48:	mov    0x1040(%rbx),%rdx
  c96e4f:	mov    %rax,%r8
  c96e52:	xor    %esi,%esi
  c96e54:	mov    $0x751,%edi
  c96e59:	xor    %eax,%eax
  c96e5b:	mov    0x60(%rdx),%rcx
  c96e5f:	mov    (%rdx),%rdx
  c96e62:	callq  eb3d90 <my_error>
  c96e67:	movl   $0x41d,0x1f1c(%rbx)
  c96e71:	mov    $0x1,%r13d
  c96e77:	jmpq   c968b2 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x16c2>
  c96e7c:	mov    -0xc30(%rbp),%r12
  c96e83:	xor    %r13d,%r13d
  c96e86:	jmpq   c96b86 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1996>
  c96e8b:	mov    -0xc04(%rbp),%edx
  c96e91:	lea    0x1193d68(%rip),%rdi        # 1e2ac00 <query_logger>
  c96e98:	mov    %rbx,%rsi
  c96e9b:	mov    %r13,%r8
  c96e9e:	mov    %r12,%rcx
  c96ea1:	callq  be47e0 <_ZN12Query_logger17general_log_writeEP3THD19enum_server_commandPKcm>
  c96ea6:	mov    0x1e0(%rbx),%rdx
  c96ead:	mov    0x1d8(%rbx),%rsi
  c96eb4:	jmpq   c95a70 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x880>
  c96eb9:	mov    %r12,%rdi
  c96ebc:	callq  7620e0 <pthread_mutex_lock@plt>
  c96ec1:	lea    -0xbc0(%rbp),%rax
  c96ec8:	mov    %rax,-0xc20(%rbp)
  c96ecf:	jmpq   c95fe7 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0xdf7>
  c96ed4:	callq  762c40 <pthread_getspecific@plt>
  c96ed9:	mov    $0x3ea,%esi
  c96ede:	mov    %rax,%rdi
  c96ee1:	callq  7c1920 <_Z6ER_THDPK3THDi>
  c96ee6:	jmpq   c96e48 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1c58>
  c96eeb:	mov    -0xc10(%rbp),%rdi
  c96ef2:	callq  7620e0 <pthread_mutex_lock@plt>
  c96ef7:	jmpq   c9688a <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x169a>
  c96efc:	lea    0x1183cfd(%rip),%rax        # 1e1ac00 <THR_THD>
  c96f03:	mov    (%rax),%edi
  c96f05:	callq  762c40 <pthread_getspecific@plt>
  c96f0a:	mov    $0x416,%esi
  c96f0f:	mov    %rax,%rdi
  c96f12:	callq  7c1920 <_Z6ER_THDPK3THDi>
  c96f17:	xor    %edx,%edx
  c96f19:	mov    %rax,%rsi
  c96f1c:	mov    $0x416,%edi
  c96f21:	callq  eb4020 <my_message>
  c96f26:	lea    -0xbc0(%rbp),%rax
  c96f2d:	mov    %rax,-0xc20(%rbp)
  c96f34:	jmpq   c95989 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x799>
  c96f39:	mov    -0xc00(%rbp),%rdx
  c96f40:	xor    %eax,%eax
  c96f42:	xor    %esi,%esi
  c96f44:	mov    $0x423,%edi
  c96f49:	callq  eb3d90 <my_error>
  c96f4e:	lea    -0xbc0(%rbp),%rax
  c96f55:	mov    %rax,-0xc20(%rbp)
  c96f5c:	jmpq   c95989 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x799>
  c96f61:	nopl   0x0(%rax)
  c96f68:	mov    0x3478(%rbx),%rax
  c96f6f:	lea    0x8a2844(%rip),%r12        # 15397ba <_ZTS8COND_CMP+0xe8>
  c96f76:	mov    $0x1,%r13d
  c96f7c:	cmpl   $0x1,0x94(%rax)
  c96f83:	jne    c96b7c <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x198c>
  c96f89:	jmpq   c96b86 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1996>
  c96f8e:	lea    0x1183cfb(%rip),%rax        # 1e1ac90 <files_charset_info>
  c96f95:	mov    -0xc00(%rbp),%rsi
  c96f9c:	mov    (%rax),%rdi
  c96f9f:	mov    0xb0(%rdi),%rax
  c96fa6:	callq  *0x60(%rax)
  c96fa9:	mov    %rax,-0xbf8(%rbp)
  c96fb0:	mov    %rax,%rsi
  c96fb3:	jmpq   c96230 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1040>
  c96fb8:	callq  762130 <__stack_chk_fail@plt>
  c96fbd:	mov    -0xc00(%rbp),%rdx
  c96fc4:	xor    %eax,%eax
  c96fc6:	xor    %esi,%esi
  c96fc8:	mov    $0x44f,%edi
  c96fcd:	callq  eb3d90 <my_error>
  c96fd2:	lea    -0xbc0(%rbp),%rax
  c96fd9:	mov    %rax,-0xc20(%rbp)
  c96fe0:	jmpq   c95989 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x799>
  c96fe5:	mov    0x3478(%rbx),%rax
  c96fec:	cmpl   $0x3,0x94(%rax)
  c96ff3:	sete   %al
  c96ff6:	nop
  c96ff7:	jmpq   c9569f <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x4af>
  c96ffc:	cmpl   $0x3,-0xc04(%rbp)
  c97003:	jne    c9568e <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x49e>
  c97009:	mov    0x3478(%rbx),%rax
  c97010:	cmpl   $0x3,0x94(%rax)
  c97017:	sete   %al
  c9701a:	nop
  c9701b:	jmpq   c9568e <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x49e>
  c97020:	mov    (%r14),%rdi
  c97023:	mov    (%rax),%rsi
  c97026:	mov    0xb8(%rdi),%rcx
  c9702d:	callq  *0x38(%rcx)
  c97030:	test   %eax,%eax
  c97032:	jne    c9634e <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x115e>
  c97038:	mov    -0x598(%rbp),%rsi
  c9703f:	mov    %rbx,%rdi
  c97042:	callq  ce7e50 <_Z17find_schema_tableP3THDPKc>
  c97047:	test   %rax,%rax
  c9704a:	je     c9634e <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x115e>
  c97050:	mov    %rax,-0x4d8(%rbp)
  c97057:	jmpq   c9634e <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x115e>
  c9705c:	cmpb   $0x0,-0x524(%rbp)
  c97063:	mov    %rax,%rbx
  c97066:	je     c97074 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1e84>
  c97068:	lea    0x80(%r15),%rdi
  c9706f:	callq  76568e <_ZN6String8mem_freeEv.part.43>
  c97074:	cmpb   $0x0,-0x544(%rbp)
  c9707b:	je     c97086 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1e96>
  c9707d:	lea    0x60(%r15),%rdi
  c97081:	callq  76568e <_ZN6String8mem_freeEv.part.43>
  c97086:	cmpb   $0x0,-0x564(%rbp)
  c9708d:	je     c97098 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1ea8>
  c9708f:	lea    0x40(%r15),%rdi
  c97093:	callq  76568e <_ZN6String8mem_freeEv.part.43>
  c97098:	cmpb   $0x0,-0x584(%rbp)
  c9709f:	je     c970aa <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1eba>
  c970a1:	lea    0x20(%r15),%rdi
  c970a5:	callq  76568e <_ZN6String8mem_freeEv.part.43>
  c970aa:	cmpb   $0x0,-0x5a4(%rbp)
  c970b1:	je     c970bb <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1ecb>
  c970b3:	mov    %r15,%rdi
  c970b6:	callq  76568e <_ZN6String8mem_freeEv.part.43>
  c970bb:	mov    %rbx,%rdi
  c970be:	callq  762870 <_Unwind_Resume@plt>
  c970c3:	mov    0x3478(%rbx),%rax
  c970ca:	cmpl   $0x3,0x94(%rax)
  c970d1:	sete   %al
  c970d4:	nop
  c970d5:	jmpq   c95cba <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0xaca>
  c970da:	cmpb   $0x0,-0x524(%rbp)
  c970e1:	mov    %rax,%rbx
  c970e4:	je     c970f2 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1f02>
  c970e6:	lea    0x80(%r15),%rdi
  c970ed:	callq  76568e <_ZN6String8mem_freeEv.part.43>
  c970f2:	cmpb   $0x0,-0x544(%rbp)
  c970f9:	je     c97104 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1f14>
  c970fb:	lea    0x60(%r15),%rdi
  c970ff:	callq  76568e <_ZN6String8mem_freeEv.part.43>
  c97104:	cmpb   $0x0,-0x564(%rbp)
  c9710b:	je     c97116 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1f26>
  c9710d:	lea    0x40(%r15),%rdi
  c97111:	callq  76568e <_ZN6String8mem_freeEv.part.43>
  c97116:	cmpb   $0x0,-0x584(%rbp)
  c9711d:	je     c97128 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1f38>
  c9711f:	lea    0x20(%r15),%rdi
  c97123:	callq  76568e <_ZN6String8mem_freeEv.part.43>
  c97128:	cmpb   $0x0,-0x5a4(%rbp)
  c9712f:	je     c970bb <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1ecb>
  c97131:	mov    %r15,%rdi
  c97134:	callq  76568e <_ZN6String8mem_freeEv.part.43>
  c97139:	jmp    c970bb <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1ecb>
  c9713b:	mov    -0xc20(%rbp),%rdi
  c97142:	mov    %rax,%rbx
  c97145:	callq  de26d0 <_ZN15Opt_trace_startD1Ev>
  c9714a:	mov    %rbx,%rdi
  c9714d:	callq  762870 <_Unwind_Resume@plt>
  c97152:	mov    %r15,%rdi
  c97155:	mov    %rax,%rbx
  c97158:	callq  c18460 <_ZN16Security_contextD1Ev>
  c9715d:	jmpq   c970bb <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1ecb>
  c97162:	mov    %rax,%rbx
  c97165:	jmp    c970f2 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1f02>
  c97167:	mov    %rax,%rbx
  c9716a:	jmp    c97128 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1f38>
  c9716c:	mov    -0xc20(%rbp),%rdi
  c97173:	mov    %rax,%rbx
  c97176:	add    $0xf0,%rdi
  c9717d:	callq  c6c050 <_ZN10Yacc_stateD1Ev>
  c97182:	mov    %rbx,%rdi
  c97185:	callq  762870 <_Unwind_Resume@plt>
  c9718a:	mov    %rax,%rbx
  c9718d:	jmp    c97116 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1f26>
  c9718f:	mov    %rax,%rbx
  c97192:	jmpq   c97104 <_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command+0x1f14>
  c97197:	nopw   0x0(%rax,%rax,1)
